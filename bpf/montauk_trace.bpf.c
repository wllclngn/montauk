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
  __uint(max_entries, 64 * 1024); // 64KB
} events SEC(".maps");

// Per-CPU scratch for openat filename passing (enter → exit)
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct fd_bpf_entry);
} open_scratch SEC(".maps");

// Discovery map: ALL processes that make syscalls get comm recorded here.
// Userspace scans this periodically for pattern matching.
// This is how Wine processes get found — they clone() (no exec), then
// set their comm via prctl(PR_SET_NAME). The discovery map catches them.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, TRACE_MAX_DISCOVERY);
  __type(key, u32);
  __type(value, struct discovery_entry);
} discovery_map SEC(".maps");

// ---- HELPERS ----

static __always_inline bool is_tracked(u32 pid) {
  return bpf_map_lookup_elem(&proc_map, &pid) != NULL;
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
  // Child inherits parent comm initially; exec will update it
  __builtin_memcpy(child_info.comm, parent->comm, 16);

  bpf_map_update_elem(&proc_map, &child_pid, &child_info, BPF_ANY);

  emit_event(TRACE_EVT_FORK, parent_pid, parent_pid, child_pid);
  return 0;
}

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx) {
  u32 pid = ctx->pid;

  // Update comm for tracked processes
  struct proc_bpf_info *info = bpf_map_lookup_elem(&proc_map, &pid);
  if (info) {
    bpf_get_current_comm(info->comm, sizeof(info->comm));
  }

  // Emit exec event with filename extracted from tracepoint (no /proc)
  struct montauk_ring_event *evt;
  evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
  if (!evt)
    return 0;
  evt->type = TRACE_EVT_EXEC;
  evt->pid = pid;
  evt->ppid = 0;
  evt->child_pid = 0;
  bpf_get_current_comm(evt->comm, sizeof(evt->comm));

  // Read exec'd filename from tracepoint data area
  unsigned short fname_off = ctx->__data_loc_filename & 0xFFFF;
  bpf_probe_read_kernel_str(evt->filename, sizeof(evt->filename),
                             (void *)ctx + fname_off);

  bpf_ringbuf_submit(evt, 0);
  return 0;
}

SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_exit *ctx) {
  u32 pid = ctx->pid;

  if (!is_tracked(pid))
    return 0;

  emit_event(TRACE_EVT_EXIT, pid, 0, 0);

  // Remove from proc map
  bpf_map_delete_elem(&proc_map, &pid);

  // Thread cleanup: delete this tid from thread_map
  // (threads share pid with process for main thread)
  bpf_map_delete_elem(&thread_map, &pid);
  return 0;
}

// ---- SYSCALL TRACING ----

SEC("tp/raw_syscalls/sys_enter")
int handle_sys_enter(struct trace_event_raw_sys_enter *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  u32 tid = (u32)pid_tgid;

  // ALWAYS record comm in discovery_map for ALL processes.
  // This is how userspace finds Wine processes (clone, no exec).
  // Cost: one hash map write per syscall for undiscovered processes.
  if (!is_tracked(pid)) {
    struct discovery_entry *existing = bpf_map_lookup_elem(&discovery_map, &pid);
    if (!existing) {
      struct discovery_entry de = {};
      de.pid = pid;
      bpf_get_current_comm(de.comm, sizeof(de.comm));
      bpf_map_update_elem(&discovery_map, &pid, &de, BPF_NOEXIST);
    }
  }

  // prctl(PR_SET_NAME) — update comm everywhere
  if (ctx->id == 157 && ctx->args[0] == 15) {
    const char *name = (const char *)ctx->args[1];

    // Update discovery_map with new name
    struct discovery_entry de = {};
    de.pid = pid;
    bpf_probe_read_user_str(de.comm, sizeof(de.comm), name);
    bpf_map_update_elem(&discovery_map, &pid, &de, BPF_ANY);

    // Update proc_map if tracked
    struct proc_bpf_info *info = bpf_map_lookup_elem(&proc_map, &pid);
    if (info) {
      bpf_probe_read_user_str(info->comm, sizeof(info->comm), name);
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
    ts->syscall_nr = ctx->id;
    ts->syscall_arg0 = ctx->args[0];
    ts->syscall_arg1 = ctx->args[1];
  } else {
    struct thread_bpf_state new_ts = {};
    new_ts.pid = pid;
    new_ts.tid = tid;
    new_ts.syscall_nr = ctx->id;
    new_ts.syscall_arg0 = ctx->args[0];
    new_ts.syscall_arg1 = ctx->args[1];
    new_ts.state = 0; // R
    new_ts.io_fd = -1;
    bpf_get_current_comm(new_ts.comm, sizeof(new_ts.comm));
    bpf_map_update_elem(&thread_map, &tid, &new_ts, BPF_ANY);
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

// ---- COMM CHANGE TRACKING (Wine prctl PR_SET_NAME) ----

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
  return 0;
}
