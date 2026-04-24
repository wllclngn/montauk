// montauk --trace: eBPF programs for real-time process group tracing
//
// Replaces /proc polling with event-driven kernel instrumentation:
//   tp/sched/sched_process_fork  → process tree tracking
//   tp/sched/sched_process_exec  → pattern match trigger
//   tp/sched/sched_process_exit  → process removal
//   tp/raw_syscalls/sys_enter    → per-thread syscall state
//   tp/raw_syscalls/sys_exit     → syscall completion
//   tp/sched/sched_switch        → thread state + CPU time
//   tp/syscalls/sys_exit_openat  → fd tracking (open)
//   tp/syscalls/sys_enter_close  → fd tracking (close)

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "montauk_trace.h"

char LICENSE[] SEC("license") = "GPL";

// ---- MAPS ----

// Tracked PID set — userspace populates roots, BPF auto-adds children
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, TRACE_MAX_PIDS);
  __type(key, u32);
  __type(value, struct proc_bpf_info);
} proc_map SEC(".maps");

// Per-thread state — updated by syscall + sched tracepoints
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, TRACE_MAX_THREADS);
  __type(key, u32);
  __type(value, struct thread_bpf_state);
} thread_map SEC(".maps");

// FD table — updated by openat/close tracepoints
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, TRACE_MAX_FDS);
  __type(key, struct fd_key);
  __type(value, struct fd_bpf_entry);
} fd_map SEC(".maps");

// Ring buffer for lifecycle events → userspace
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024); // 256KB (ntsync events are 128 bytes, high-frequency)
} events SEC(".maps");

// Per-CPU scratch for ntsync ioctl enter → exit state passing
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct ntsync_scratch);
} ntsync_scratch SEC(".maps");

// Per-CPU scratch for openat filename passing (enter → exit)
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct fd_bpf_entry);
} open_scratch SEC(".maps");

// Discovery map: ALL processes that make syscalls get comm recorded here.
// Userspace scans this periodically for pattern matching.
// This is how processes get found — they clone() (no exec), then
// set their comm via prctl(PR_SET_NAME). The discovery map catches them.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, TRACE_MAX_DISCOVERY);
  __type(key, u32);
  __type(value, struct discovery_entry);
} discovery_map SEC(".maps");

// BPF-side pattern for immediate exec matching — PANDEMONIUM-style.
// const volatile in .rodata: libbpf creates a frozen BPF_F_RDONLY_PROG array,
// which satisfies bpf_strncmp's requirement for a readonly map pointer.
// Userspace sets values via skel->rodata->trace_pat before load.
const volatile struct trace_pattern trace_pat = {};

// Per-CPU scratch buffer for substring matching.
// The BPF verifier can't track pointer arithmetic across two runtime loop
// variables on stack pointers (e.g. haystack[i + j] where i and j are both
// bounded by runtime values). It rejects the access even when logically safe.
// Map value pointers have verifier-known sizes — scratch[pos] with pos < 64
// is always provably safe.
struct match_scratch { char data[64]; };
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct match_scratch);
} match_buf SEC(".maps");

// ---- HELPERS ----

static __always_inline bool is_tracked(u32 pid) {
  return bpf_map_lookup_elem(&proc_map, &pid) != NULL;
}

// bpf_loop callback: check if pattern matches at position ctx->pos.
struct substr_ctx {
  struct match_scratch *buf;
  int need_len;
  int hay_len;
  int found;
};

static int match_at_pos(u32 pos, void *_ctx) {
  struct substr_ctx *ctx = _ctx;
  int nlen = ctx->need_len;
  if (nlen <= 0 || nlen > TRACE_PATTERN_MAX) return 1;
  if ((int)pos + nlen > ctx->hay_len)
    return 1;  // past end, stop
  // trace_pat is const volatile in .rodata — libbpf creates it as a frozen
  // BPF_F_RDONLY_PROG array, satisfying bpf_strncmp's readonly requirement.
  // pos & 31 guarantees max offset 31. With nlen <= 32 (TRACE_PATTERN_MAX),
  // 31 + 32 = 63 = last byte of the 64-byte scratch buffer.
  u32 safe_pos = pos & 31;
  if (bpf_strncmp(&ctx->buf->data[safe_pos], nlen, (const char *)trace_pat.pattern) == 0) {
    ctx->found = 1;
    return 1;  // stop, found
  }
  return 0;  // continue
}

// BPF-side case-insensitive substring match.
// GLOBAL function (not static) — verifier validates ONCE, each call = 1 insn.
// Uses bpf_loop() for the outer scan (verifier checks callback once) and
// bpf_strncmp() for inner comparison (zero branches, single helper call).
// Total verifier cost: ~50 insns regardless of call count or pattern length.
static __noinline int bpf_substr_match(const char *haystack, int hay_len,
                                        const char *needle, int need_len) {
  if (need_len <= 0 || hay_len <= 0 || need_len > hay_len)
    return 0;
  if (hay_len > 64) hay_len = 64;
  if (need_len > TRACE_PATTERN_MAX) need_len = TRACE_PATTERN_MAX;

  u32 zero = 0;
  struct match_scratch *scratch = bpf_map_lookup_elem(&match_buf, &zero);
  if (!scratch)
    return 0;

  // Copy haystack and lowercase in-place (bpf_strncmp is case-sensitive)
  bpf_probe_read_kernel(scratch->data, hay_len & 63, haystack);
  for (int i = 0; i < 64; i++) {
    if (i >= hay_len) break;
    char c = scratch->data[i];
    if (c >= 'A' && c <= 'Z') scratch->data[i] = c + 32;
  }

  struct substr_ctx ctx = {
    .buf = scratch,
    .need_len = need_len,
    .hay_len = hay_len,
    .found = 0,
  };
  bpf_loop(hay_len, match_at_pos, &ctx, 0);
  return ctx.found;
}

// Auto-track a process: write to proc_map immediately in BPF.
// Children will be auto-tracked by handle_fork on the next clone().
static __always_inline void auto_track_pid(u32 pid) {
  struct proc_bpf_info info = {};
  info.pid = pid;
  info.ppid = 0;
  info.tracked = 1;
  info.is_root = 1;
  bpf_get_current_comm(info.comm, sizeof(info.comm));
  bpf_map_update_elem(&proc_map, &pid, &info, BPF_NOEXIST);
}

static __always_inline void emit_event(u32 type, u32 pid, u32 ppid,
                                       u32 child_pid) {
  struct montauk_ring_event *evt;
  evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
  if (!evt)
    return;
  evt->type = type;
  evt->pid = pid;
  evt->ppid = ppid;
  evt->child_pid = child_pid;
  bpf_get_current_comm(evt->comm, sizeof(evt->comm));
  __builtin_memset(evt->filename, 0, sizeof(evt->filename));
  bpf_ringbuf_submit(evt, 0);
}

static __always_inline void emit_io_event(u32 pid, u32 tid, s32 syscall_nr,
                                          s32 fd, s64 result, u64 count, u32 whence) {
  struct montauk_io_event *evt;
  evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
  if (!evt)
    return;
  evt->type = TRACE_EVT_IO;
  evt->pid = pid;
  evt->tid = tid;
  evt->syscall_nr = syscall_nr;
  evt->fd = fd;
  evt->result = result;
  evt->count = count;
  evt->whence = whence;
  bpf_get_current_comm(evt->comm, sizeof(evt->comm));
  bpf_ringbuf_submit(evt, 0);
}

// ---- PROCESS LIFECYCLE ----

SEC("tp/sched/sched_process_fork")
int handle_fork(struct trace_event_raw_sched_process_fork *ctx) {
  u32 parent_pid = ctx->parent_pid;
  u32 child_pid = ctx->child_pid;

  // If parent is tracked, auto-track child
  struct proc_bpf_info *parent = bpf_map_lookup_elem(&proc_map, &parent_pid);
  if (!parent)
    return 0;

  struct proc_bpf_info child_info = {};
  child_info.pid = child_pid;
  child_info.ppid = parent_pid;
  child_info.tracked = 1;
  child_info.is_root = 0;
  child_info.exited = 0;
  child_info.exit_code = 0;
  child_info.fork_ts = bpf_ktime_get_ns();
  child_info.exec_ts = 0;
  child_info.exit_ts = 0;
  // Child inherits parent comm initially; exec will update it
  __builtin_memcpy(child_info.comm, parent->comm, 16);
  child_info.exec_file[0] = 0;

  bpf_map_update_elem(&proc_map, &child_pid, &child_info, BPF_ANY);
  return 0;
}

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx) {
  u32 pid = ctx->pid;

  // Read exec'd filename from tracepoint data area
  char filename[64] = {};
  unsigned short fname_off = ctx->__data_loc_filename & 0xFFFF;
  bpf_probe_read_kernel_str(filename, sizeof(filename),
                             (void *)ctx + fname_off);

  // Update proc_map for tracked processes (histogram-style, no ring buffer)
  struct proc_bpf_info *info = bpf_map_lookup_elem(&proc_map, &pid);
  if (info) {
    bpf_get_current_comm(info->comm, sizeof(info->comm));
    info->exec_ts = bpf_ktime_get_ns();
    __builtin_memcpy(info->exec_file, filename, 64);
  }

  // BPF-SIDE PATTERN MATCH — no userspace roundtrip.
  if (!is_tracked(pid)) {
    if (trace_pat.len > 0) {
      if (bpf_substr_match(filename, 56, (const char *)trace_pat.pattern, trace_pat.len)) {
        auto_track_pid(pid);
      } else {
        char comm[16] = {};
        bpf_get_current_comm(comm, sizeof(comm));
        if (bpf_substr_match(comm, 16, (const char *)trace_pat.pattern, trace_pat.len)) {
          auto_track_pid(pid);
        }
      }
    }
  }

  return 0;
}

SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_exit *ctx) {
  u32 pid = ctx->pid;

  if (!is_tracked(pid))
    return 0;

  // Mark process as exited in proc_map with exit code and timestamp.
  // Do NOT delete from proc_map — userspace needs to read the exit data.
  // Userspace is responsible for cleaning up after scraping.
  struct proc_bpf_info *info = bpf_map_lookup_elem(&proc_map, &pid);
  if (info) {
    info->exited = 1;
    info->exit_ts = bpf_ktime_get_ns();
    // Exit code from task_struct: (exit_code >> 8) = status, (exit_code & 0x7f) = signal
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task) {
      int code = 0;
      bpf_probe_read_kernel(&code, sizeof(code), &task->exit_code);
      info->exit_code = code;
    }
  }

  // Thread cleanup: delete this tid from thread_map
  bpf_map_delete_elem(&thread_map, &pid);
  return 0;
}

// ---- NTSYNC HELPERS (used by raw_syscalls handlers below) ----

static __always_inline bool is_ntsync_ioctl(u32 cmd) {
  return ((cmd >> 8) & 0xFF) == 0x4E &&
         (cmd & 0xFF) >= 0x80 && (cmd & 0xFF) <= 0x8D;
}

static __always_inline u8 ntsync_cmd_to_op(u32 cmd) {
  u8 nr = cmd & 0xFF;
  switch (nr) {
    case 0x80: return NTS_CREATE_SEM;
    case 0x81: return NTS_SEM_RELEASE;
    case 0x82: return NTS_WAIT_ANY;
    case 0x83: return NTS_WAIT_ALL;
    case 0x84: return NTS_CREATE_MUTEX;
    case 0x85: return NTS_MUTEX_UNLOCK;
    case 0x86: return NTS_MUTEX_KILL;
    case 0x87: return NTS_CREATE_EVENT;
    case 0x88: return NTS_EVENT_SET;
    case 0x89: return NTS_EVENT_RESET;
    case 0x8a: return NTS_EVENT_PULSE;
    case 0x8b: return NTS_SEM_READ;
    case 0x8c: return NTS_MUTEX_READ;
    case 0x8d: return NTS_EVENT_READ;
    default:   return 0xFF;
  }
}

// ---- SYSCALL TRACING ----

SEC("tp/raw_syscalls/sys_enter")
int handle_sys_enter(struct trace_event_raw_sys_enter *ctx) {
  // Cache ctx fields immediately — BPF verifier disallows ctx pointer
  // dereference after register arithmetic later in the function.
  long syscall_id = ctx->id;
  u64 arg0 = ctx->args[0];
  u64 arg1 = ctx->args[1];
  u64 arg2 = ctx->args[2];

  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  u32 tid = (u32)pid_tgid;

  // ALWAYS record comm in discovery_map for ALL processes.
  // This is how processes get found — clone() (no exec), then
  // set their comm via prctl(PR_SET_NAME). The discovery map catches them.
  if (!is_tracked(pid)) {
    struct discovery_entry *existing = bpf_map_lookup_elem(&discovery_map, &pid);
    if (!existing) {
      struct discovery_entry de = {};
      de.pid = pid;
      bpf_get_current_comm(de.comm, sizeof(de.comm));
      bpf_map_update_elem(&discovery_map, &pid, &de, BPF_NOEXIST);

      // BPF-SIDE PATTERN MATCH on first syscall — auto-track immediately.
      // No userspace roundtrip. Same as handle_exec pattern match.
      if (trace_pat.len > 0) {
        if (bpf_substr_match(de.comm, 16, (const char *)trace_pat.pattern, trace_pat.len)) {
          auto_track_pid(pid);
        }
      }
    }
  }

  // prctl(PR_SET_NAME) — update comm everywhere + re-check pattern
  if (syscall_id == 157 && arg0 == 15) {
    const char *name = (const char *)arg1;

    // Update discovery_map with new name
    struct discovery_entry de = {};
    de.pid = pid;
    bpf_probe_read_user_str(de.comm, sizeof(de.comm), name);
    bpf_map_update_elem(&discovery_map, &pid, &de, BPF_ANY);

    // Update proc_map if tracked
    struct proc_bpf_info *info = bpf_map_lookup_elem(&proc_map, &pid);
    if (info) {
      bpf_probe_read_user_str(info->comm, sizeof(info->comm), name);
    } else {
      // Not tracked yet — BPF-side pattern match on the new name.
      // Any process that renames itself to match the pattern gets
      // auto-tracked immediately. Application-agnostic.
      if (trace_pat.len > 0) {
        if (bpf_substr_match(de.comm, 16, (const char *)trace_pat.pattern, trace_pat.len)) {
          auto_track_pid(pid);
        }
      }
    }

    // Update thread_map if entry exists
    struct thread_bpf_state *ts = bpf_map_lookup_elem(&thread_map, &tid);
    if (ts) {
      bpf_probe_read_user_str(ts->comm, sizeof(ts->comm), name);
    }
  }

  if (!is_tracked(pid))
    return 0;

  struct thread_bpf_state *ts = bpf_map_lookup_elem(&thread_map, &tid);
  if (ts) {
    ts->syscall_nr = syscall_id;
    ts->syscall_arg0 = arg0;
    ts->syscall_arg1 = arg1;
  } else {
    struct thread_bpf_state new_ts = {};
    new_ts.pid = pid;
    new_ts.tid = tid;
    new_ts.syscall_nr = syscall_id;
    new_ts.syscall_arg0 = arg0;
    new_ts.syscall_arg1 = arg1;
    new_ts.state = 0; // R
    new_ts.io_fd = -1;
    bpf_get_current_comm(new_ts.comm, sizeof(new_ts.comm));
    bpf_map_update_elem(&thread_map, &tid, &new_ts, BPF_ANY);
  }

  // ntsync ioctl capture: stash args in per-CPU scratch for exit handler
  if (syscall_id == 16) { // ioctl
    u32 cmd = (u32)arg1;
    if (is_ntsync_ioctl(cmd)) {
      u32 zero = 0;
      struct ntsync_scratch *s = bpf_map_lookup_elem(&ntsync_scratch, &zero);
      if (s) {
        __builtin_memset(s, 0, sizeof(*s));
        s->pid = pid;
        s->fd = (s32)arg0;
        s->op = ntsync_cmd_to_op(cmd);
        s->arg_ptr = arg2;

        u64 arg = arg2;
        switch (s->op) {
          case NTS_CREATE_SEM:
          case NTS_CREATE_MUTEX:
          case NTS_CREATE_EVENT: {
            u32 vals[2] = {};
            bpf_probe_read_user(vals, sizeof(vals), (void *)arg);
            s->arg0 = vals[0];
            s->arg1 = vals[1];
            break;
          }
          case NTS_WAIT_ANY:
          case NTS_WAIT_ALL: {
            u64 wa_buf[5] = {};
            bpf_probe_read_user(wa_buf, 40, (void *)arg);
            s->timeout_ns = wa_buf[0];
            u64 objs_ptr = wa_buf[1];
            u32 *wa32 = (u32 *)&wa_buf[2];
            s->wait_count = wa32[0];
            s->wait_owner = wa32[3];
            s->wait_alert = wa32[4];
            u32 n = s->wait_count;
            if (n > NTSYNC_MAX_WAIT_FDS) n = NTSYNC_MAX_WAIT_FDS;
            if (n > 0 && objs_ptr)
              bpf_probe_read_user(s->wait_fds, n * sizeof(u32), (void *)objs_ptr);
            // Emit ENTRY event for waits so blocked calls are visible
            {
              struct montauk_ntsync_event *we;
              we = bpf_ringbuf_reserve(&events, sizeof(*we), 0);
              if (we) {
                we->type = TRACE_EVT_NTSYNC;
                we->pid = pid;
                we->tid = tid;
                we->op = s->op;
                we->fd = s->fd;
                we->result = -999; // sentinel: ENTRY (not yet completed)
                we->timestamp_ns = bpf_ktime_get_ns();
                we->arg0 = 0;
                we->arg1 = 0;
                we->timeout_ns = s->timeout_ns;
                we->wait_count = s->wait_count;
                we->wait_index = 0;
                we->wait_owner = s->wait_owner;
                we->wait_alert = s->wait_alert;
                __builtin_memcpy(we->wait_fds, s->wait_fds, sizeof(we->wait_fds));
                bpf_get_current_comm(we->comm, sizeof(we->comm));
                bpf_ringbuf_submit(we, 0);
              }
            }
            break;
          }
          default:
            break;
        }
      }
    }
  }
  return 0;
}

SEC("tp/raw_syscalls/sys_exit")
int handle_sys_exit(struct trace_event_raw_sys_exit *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  u32 tid = (u32)pid_tgid;

  if (!is_tracked(pid))
    return 0;

  struct thread_bpf_state *ts = bpf_map_lookup_elem(&thread_map, &tid);
  if (ts) {
    ts->syscall_nr = -1; // back to running
  }

  // ntsync ioctl exit: emit ring event if scratch was populated by enter
  {
    u32 zero = 0;
    struct ntsync_scratch *s = bpf_map_lookup_elem(&ntsync_scratch, &zero);
    if (s && s->pid == pid && (s->op != 0 || s->fd != 0)) {
      struct montauk_ntsync_event *evt;
      evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
      if (evt) {
        evt->type = TRACE_EVT_NTSYNC;
        evt->pid = pid;
        evt->tid = tid;
        evt->op = s->op;
        evt->fd = s->fd;
        evt->result = ctx->ret;
        evt->timestamp_ns = bpf_ktime_get_ns();
        evt->arg0 = s->arg0;
        evt->arg1 = s->arg1;
        evt->timeout_ns = s->timeout_ns;
        evt->wait_count = s->wait_count;
        evt->wait_index = 0;
        evt->wait_owner = s->wait_owner;
        evt->wait_alert = s->wait_alert;
        __builtin_memcpy(evt->wait_fds, s->wait_fds, sizeof(evt->wait_fds));
        bpf_get_current_comm(evt->comm, sizeof(evt->comm));

        // WAIT ops: read back index (OUT param at offset 20)
        if ((s->op == NTS_WAIT_ANY || s->op == NTS_WAIT_ALL) && s->arg_ptr) {
          u32 out_index = 0;
          bpf_probe_read_user(&out_index, sizeof(out_index), (void *)(s->arg_ptr + 20));
          evt->wait_index = out_index;
        }
        // EVENT_SET/RESET/PULSE: read back prev_state
        if (s->op >= NTS_EVENT_SET && s->op <= NTS_EVENT_PULSE && s->arg_ptr) {
          u32 prev = 0;
          bpf_probe_read_user(&prev, sizeof(prev), (void *)s->arg_ptr);
          evt->arg0 = prev;
        }
        // Read ops: read back result struct
        if ((s->op == NTS_SEM_READ || s->op == NTS_MUTEX_READ || s->op == NTS_EVENT_READ)
            && s->arg_ptr) {
          u32 vals[2] = {};
          bpf_probe_read_user(vals, sizeof(vals), (void *)s->arg_ptr);
          evt->arg0 = vals[0];
          evt->arg1 = vals[1];
        }

        bpf_ringbuf_submit(evt, 0);
      }
      s->pid = 0; // clear scratch
    }
  }
  return 0;
}

// ---- SCHEDULER STATE ----

SEC("tp/sched/sched_switch")
int handle_sched_switch(struct trace_event_raw_sched_switch *ctx) {
  u64 now = bpf_ktime_get_ns();

  // Handle prev task going off-CPU
  u32 prev_tid = ctx->prev_pid; // confusingly named: this is actually the tid
  struct thread_bpf_state *prev = bpf_map_lookup_elem(&thread_map, &prev_tid);
  if (prev) {
    // Accumulate runtime
    if (prev->enter_ns > 0) {
      u64 delta = now - prev->enter_ns;
      prev->runtime_ns += delta;
    }
    prev->enter_ns = 0;

    // Map prev_state to our state encoding
    long prev_state = ctx->prev_state;
    if (prev_state == 0)
      prev->state = 0; // R (preempted, still runnable)
    else if (prev_state & 0x01) // TASK_INTERRUPTIBLE
      prev->state = 1; // S
    else if (prev_state & 0x02) // TASK_UNINTERRUPTIBLE
      prev->state = 2; // D
    else if (prev_state & 0x04) // __TASK_STOPPED
      prev->state = 3; // T
    else if (prev_state & 0x20) // EXIT_ZOMBIE
      prev->state = 4; // Z
    else
      prev->state = 1; // default S
  }

  // Handle next task coming on-CPU
  u32 next_tid = ctx->next_pid;
  struct thread_bpf_state *next = bpf_map_lookup_elem(&thread_map, &next_tid);
  if (next) {
    next->enter_ns = now;
    next->state = 0; // R (running)
    // comm is already set by handle_sys_enter via bpf_get_current_comm()
  }

  return 0;
}

// ---- COMM CHANGE TRACKING ----

// prctl(PR_SET_NAME) handling merged into handle_sys_enter above.

// ---- FD TRACKING ----

SEC("tp/syscalls/sys_enter_openat")
int handle_openat_enter(struct trace_event_raw_sys_enter *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  if (!is_tracked(pid))
    return 0;

  u32 zero = 0;
  struct fd_bpf_entry *scratch = bpf_map_lookup_elem(&open_scratch, &zero);
  if (!scratch)
    return 0;

  scratch->pid = pid;
  scratch->fd_num = -1;
  scratch->type = 0; // file

  // Read filename from userspace pointer (arg1 = filename for openat)
  const char *filename = (const char *)ctx->args[1];
  bpf_probe_read_user_str(scratch->target, sizeof(scratch->target), filename);

  // Classify: /dev/ prefix = device
  if (scratch->target[0] == '/' && scratch->target[1] == 'd' &&
      scratch->target[2] == 'e' && scratch->target[3] == 'v' &&
      scratch->target[4] == '/')
    scratch->type = 3; // device

  return 0;
}

SEC("tp/syscalls/sys_exit_openat")
int handle_openat_exit(struct trace_event_raw_sys_exit *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  if (!is_tracked(pid))
    return 0;

  long fd = ctx->ret;
  if (fd < 0)
    return 0;

  u32 zero = 0;
  struct fd_bpf_entry *scratch = bpf_map_lookup_elem(&open_scratch, &zero);
  if (!scratch || scratch->pid != pid)
    return 0;

  struct fd_key key = {.pid = pid, .fd = (s32)fd};
  struct fd_bpf_entry entry = {};
  entry.pid = pid;
  entry.fd_num = (s32)fd;
  entry.type = scratch->type;
  __builtin_memcpy(entry.target, scratch->target, sizeof(entry.target));

  bpf_map_update_elem(&fd_map, &key, &entry, BPF_ANY);
  emit_io_event(pid, (u32)pid_tgid, 257, (s32)fd, fd, 0, 0);
  return 0;
}

SEC("tp/syscalls/sys_enter_close")
int handle_close(struct trace_event_raw_sys_enter *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  if (!is_tracked(pid))
    return 0;

  s32 fd = (s32)ctx->args[0];
  struct fd_key key = {.pid = pid, .fd = fd};
  bpf_map_delete_elem(&fd_map, &key);
  return 0;
}

SEC("tp/syscalls/sys_exit_socket")
int handle_socket_exit(struct trace_event_raw_sys_exit *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  if (!is_tracked(pid))
    return 0;

  long fd = ctx->ret;
  if (fd < 0)
    return 0;

  struct fd_key key = {.pid = pid, .fd = (s32)fd};
  struct fd_bpf_entry entry = {};
  entry.pid = pid;
  entry.fd_num = (s32)fd;
  entry.type = 2; // socket
  __builtin_memcpy(entry.target, "socket:", 7);

  bpf_map_update_elem(&fd_map, &key, &entry, BPF_ANY);
  return 0;
}

SEC("tp/syscalls/sys_exit_eventfd2")
int handle_eventfd2_exit(struct trace_event_raw_sys_exit *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  if (!is_tracked(pid))
    return 0;

  long fd = ctx->ret;
  if (fd < 0)
    return 0;

  struct fd_key key = {.pid = pid, .fd = (s32)fd};
  struct fd_bpf_entry entry = {};
  entry.pid = pid;
  entry.fd_num = (s32)fd;
  entry.type = 4; // eventfd
  __builtin_memcpy(entry.target, "eventfd", 7);

  bpf_map_update_elem(&fd_map, &key, &entry, BPF_ANY);
  return 0;
}

// ---- FILE I/O TRACKING ----

// -- lseek (syscall 8) --

SEC("tp/syscalls/sys_enter_lseek")
int handle_lseek_enter(struct trace_event_raw_sys_enter *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  u32 tid = (u32)pid_tgid;

  if (!is_tracked(pid))
    return 0;

  struct thread_bpf_state *ts = bpf_map_lookup_elem(&thread_map, &tid);
  if (!ts)
    return 0;

  ts->io_fd = (s32)ctx->args[0];
  ts->io_count = ctx->args[1];   // offset argument
  ts->io_whence = (u32)ctx->args[2];
  return 0;
}

SEC("tp/syscalls/sys_exit_lseek")
int handle_lseek_exit(struct trace_event_raw_sys_exit *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  u32 tid = (u32)pid_tgid;

  if (!is_tracked(pid))
    return 0;

  struct thread_bpf_state *ts = bpf_map_lookup_elem(&thread_map, &tid);
  if (!ts)
    return 0;

  ts->io_result = ctx->ret;
  ts->io_timestamp_ns = bpf_ktime_get_ns();
  emit_io_event(pid, tid, 8, ts->io_fd, ctx->ret, ts->io_count, ts->io_whence);
  return 0;
}

// -- read (syscall 0) --

SEC("tp/syscalls/sys_enter_read")
int handle_read_enter(struct trace_event_raw_sys_enter *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  u32 tid = (u32)pid_tgid;

  if (!is_tracked(pid))
    return 0;

  struct thread_bpf_state *ts = bpf_map_lookup_elem(&thread_map, &tid);
  if (!ts)
    return 0;

  ts->io_fd = (s32)ctx->args[0];
  ts->io_count = ctx->args[2];
  return 0;
}

SEC("tp/syscalls/sys_exit_read")
int handle_read_exit(struct trace_event_raw_sys_exit *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  u32 tid = (u32)pid_tgid;

  if (!is_tracked(pid))
    return 0;

  struct thread_bpf_state *ts = bpf_map_lookup_elem(&thread_map, &tid);
  if (!ts)
    return 0;

  ts->io_result = ctx->ret;
  ts->io_timestamp_ns = bpf_ktime_get_ns();
  emit_io_event(pid, tid, 0, ts->io_fd, ctx->ret, ts->io_count, 0);
  return 0;
}

// -- write (syscall 1) --

SEC("tp/syscalls/sys_enter_write")
int handle_write_enter(struct trace_event_raw_sys_enter *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  u32 tid = (u32)pid_tgid;

  if (!is_tracked(pid))
    return 0;

  struct thread_bpf_state *ts = bpf_map_lookup_elem(&thread_map, &tid);
  if (!ts)
    return 0;

  ts->io_fd = (s32)ctx->args[0];
  ts->io_count = ctx->args[2];
  return 0;
}

SEC("tp/syscalls/sys_exit_write")
int handle_write_exit(struct trace_event_raw_sys_exit *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  u32 tid = (u32)pid_tgid;

  if (!is_tracked(pid))
    return 0;

  struct thread_bpf_state *ts = bpf_map_lookup_elem(&thread_map, &tid);
  if (!ts)
    return 0;

  ts->io_result = ctx->ret;
  ts->io_timestamp_ns = bpf_ktime_get_ns();
  emit_io_event(pid, tid, 1, ts->io_fd, ctx->ret, ts->io_count, 0);
  return 0;
}

// -- pread64 (syscall 17) --

SEC("tp/syscalls/sys_enter_pread64")
int handle_pread64_enter(struct trace_event_raw_sys_enter *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  u32 tid = (u32)pid_tgid;

  if (!is_tracked(pid))
    return 0;

  struct thread_bpf_state *ts = bpf_map_lookup_elem(&thread_map, &tid);
  if (!ts)
    return 0;

  ts->io_fd = (s32)ctx->args[0];
  ts->io_count = ctx->args[2];
  ts->io_whence = (u32)ctx->args[3]; // offset for pread64
  return 0;
}

SEC("tp/syscalls/sys_exit_pread64")
int handle_pread64_exit(struct trace_event_raw_sys_exit *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  u32 tid = (u32)pid_tgid;

  if (!is_tracked(pid))
    return 0;

  struct thread_bpf_state *ts = bpf_map_lookup_elem(&thread_map, &tid);
  if (!ts)
    return 0;

  ts->io_result = ctx->ret;
  ts->io_timestamp_ns = bpf_ktime_get_ns();
  emit_io_event(pid, tid, 17, ts->io_fd, ctx->ret, ts->io_count, ts->io_whence);
  return 0;
}

// -- fstat / newfstat (syscall 5) --

SEC("tp/syscalls/sys_enter_newfstat")
int handle_fstat_enter(struct trace_event_raw_sys_enter *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  u32 tid = (u32)pid_tgid;

  if (!is_tracked(pid))
    return 0;

  struct thread_bpf_state *ts = bpf_map_lookup_elem(&thread_map, &tid);
  if (!ts)
    return 0;

  ts->io_fd = (s32)ctx->args[0];
  ts->io_count = ctx->args[1]; // statbuf pointer for exit handler
  return 0;
}

SEC("tp/syscalls/sys_exit_newfstat")
int handle_fstat_exit(struct trace_event_raw_sys_exit *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  u32 tid = (u32)pid_tgid;

  if (!is_tracked(pid))
    return 0;

  struct thread_bpf_state *ts = bpf_map_lookup_elem(&thread_map, &tid);
  if (!ts)
    return 0;

  ts->io_result = ctx->ret;
  ts->io_timestamp_ns = bpf_ktime_get_ns();

  // On success, read st_size from the stat buffer (offset 48 on x86_64)
  if (ctx->ret == 0 && ts->io_count != 0) {
    s64 st_size = 0;
    bpf_probe_read_user(&st_size, sizeof(st_size),
                         (void *)(ts->io_count + 48));
    ts->io_result = st_size;
  }
  emit_io_event(pid, tid, 5, ts->io_fd, ts->io_result, ts->io_count, 0);
  return 0;
}

// ntsync ioctl handlers are integrated into handle_sys_enter/handle_sys_exit
// above via the raw_syscalls tracepoints (sys_enter_ioctl doesn't exist on
// all kernels). The ntsync filter checks syscall_nr == 16 and magic 'N'.
