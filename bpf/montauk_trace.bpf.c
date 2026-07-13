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

// MAPS

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
  __uint(max_entries, 1024 * 1024); // 1MB (ntsync events 128B; headroom so a brief
                                    // flush stall can't overflow before the next drain)
} events SEC(".maps");

// Per-CPU scratch for ntsync ioctl enter → exit state passing
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct ntsync_scratch);
} ntsync_scratch SEC(".maps");

// sched_ext kick-storm counters (per-CPU; the collector sums + deltas each interval)
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct scx_storm_counters);
} scx_storm SEC(".maps");

// Per-CPU scratch for openat filename passing (enter → exit)
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct fd_bpf_entry);
} open_scratch SEC(".maps");

// Per-CPU scratch for mmap arg passing (sys_enter_mmap -> sys_exit_mmap).
// Captures fd/length/prot/flags/offset on enter; emit fires on exit using
// the syscall return value as the mapped address.
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct mmap_scratch);
} mmap_scratch_map SEC(".maps");

// Per-thread scratch for libc heap uprobes (entry → uretprobe).
// malloc/calloc need to pair size (entry) with addr (return); realloc
// needs to pair old_addr+size (entry) with new_addr (return). Keyed by
// tid so concurrent calls from different threads don't collide.
struct heap_scratch {
  __u64 size;
  __u64 old_addr;
  __u32 op;
};
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4096);
  __type(key, u32);
  __type(value, struct heap_scratch);
} heap_inflight SEC(".maps");

// Free-probe echo guard. The uprobe layer can deliver the free probe TWICE
// for one logical call: two handler executions 1-3us apart, observed on a
// thread's early frees, with the process never aborting (a real second
// glibc free of a just-freed chunk aborts on every path, so the duplicate
// is physically not an app re-free). Per-tid last freed pointer: a repeat
// of the same pointer inside the window with no allocation in between is
// the echo and is not emitted. Every allocation return clears the entry,
// so a real rapid free/alloc/free cycle at one address never matches.
#define FREE_ECHO_WINDOW_NS 10000
struct free_echo { u64 ptr; u64 ts; };
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 8192);
  __type(key, u32);
  __type(value, struct free_echo);
} free_echo_guard SEC(".maps");

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

// BPF-side pattern for immediate exec matching.
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

// Per-CPU scheduler-decision counters. The decision tracepoints fire on the
// dispatch hot path, so aggregating per-CPU (one counter bump, no shared
// ringbuf reserve) keeps tracing near-zero-overhead there. Userspace sums
// across CPUs at snapshot time.
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct sched_op_counters);
} sched_op_counts SEC(".maps");

// cpu → cache domain/L3-domain id. Userspace populates from sysfs L3 shared_cpu_list
// before attach: CPUs sharing an L3 (one cache domain) get the same id. On a monolithic
// single-L3 part every CPU maps to 0, so every move classifies intra (correct).
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, TRACE_MAX_CPUS);
  __type(key, u32);
  __type(value, u32);
} cpu_cache_domain SEC(".maps");

// Per-CPU current frequency in MHz, indexed by logical CPU. Updated on every
// tp/power/cpu_frequency transition (the cpufreq core emits one per P-state
// change under any governor). Read at WAKE2RUN to stamp the core's frequency at
// the wake instant -- the signal that separates a slow wake caused by dispatch
// latency from one caused by the core still sitting at minimum frequency after a
// deep idle (the cold-wake ramp). 0 until the first transition is observed.
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, TRACE_MAX_CPUS);
  __type(key, u32);
  __type(value, u32);
} cur_freq_mhz SEC(".maps");

// Per-CPU migration classification counters (intra/cross/unknown cache domain), bumped on
// the sched_switch migration path and summed in userspace. Churn-proof, unlike
// the per-thread thread_bpf_state.migrations that a short-lived thread takes with
// it when it exits.
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct mig_domain_counters);
} mig_domain_counts SEC(".maps");

// Per-event streaming of sched-decision events to the ringbuf is a firehose on
// a hot path; OFF by default. Userspace sets this true only when the binary
// --trace-out log is active. The per-CPU counters above are always maintained.
const volatile unsigned char sched_stream = 0;  /* base type: portable into the C++ skeleton (u8 is BPF-only) */
const volatile unsigned char sched_detail = 0;    /* --sched-detail: gate the per-CPU idle-boundary firehose (off by default) */

// Heap caller-stack size filter (bytes). Loaded from MONTAUK_HEAP_STACK_SIZE
// before skeleton load; 0 disables. Non-zero: every malloc/calloc whose
// requested size equals this also emits a TRACE_EVT_HEAPSTACK carrying the
// user stack, alongside the normal TRACE_EVT_HEAP record.
const volatile __u64 heap_stack_size = 0;

// Per-CPU kthread strand threshold (ns). A per-CPU kthread whose
// became-runnable -> ran latency reaches this emits a TRACE_EVT_KSTRAND. 5ms
// default: well above a healthy dispatch (tens of us) yet far below the I/O
// timescales (btrfs writeback, fsync) that wedge when these threads strand.
// Userspace may lower it via MONTAUK_KSTRAND_THRESH_NS before load.
const volatile __u64 kstrand_thresh_ns = 5000000;

// WRITABLE global (.bss), set by the collector AFTER the decision tracepoints are
// bound -- not const volatile rodata, which is frozen at load before that attach
// result is known. 1 when no sched_decision/pick tracepoint attached, so
// handle_sched_switch emits a SCHED_OP_SWITCH_IN pick from the universal
// sched_switch and the slice/service reports still resolve; 0 when the scheduler's
// own pick stream is present, so the two streams never double up.
unsigned char switch_in_fallback = 0;

// became-runnable timestamp + comm for per-CPU kthreads pending a run, keyed by
// tid. Separate from thread_map (which is scoped to the traced comm group);
// these kthreads are tracked system-wide so a strand that freezes the box is
// caught even when the traced app is not the victim. Earliest wake is kept
// (BPF_NOEXIST on re-wakeup) so the latency reflects the full strand, not the
// last poke. The comm is stamped here from the task_struct (verifier-clean CO-RE
// read) so the sched-in side never has to dereference the tracepoint ctx.
struct kpcpu_wait {
  __u64 wake_ns;
  char  comm[16];
};
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4096);
  __type(key, __u32);
  __type(value, struct kpcpu_wait);
} kpcpu_wake SEC(".maps");

// Dedup set for TRACE_EVT_THREAD_NAME: one tid->comm binding per thread. A tid
// already present skips the emit, so a CPU-bound holder is named once, not per
// switch-in. Bounded; if full, BPF_NOEXIST fails and the tid stays unnamed.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 8192);
  __type(key, __u32);
  __type(value, __u8);
} named_tids SEC(".maps");

#ifndef PF_KTHREAD
#define PF_KTHREAD 0x00200000
#endif

static __always_inline void sched_op_bump(u32 op)
{
  u32 z = 0;
  struct sched_op_counters *c = bpf_map_lookup_elem(&sched_op_counts, &z);
  if (c && op < MONTAUK_SCHED_OP_MAX)
    c->op[op]++;
}

// HELPERS

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
  evt->duration_ns = 0;  // not tracked for this call site; see emit_io_event_dur
  bpf_get_current_comm(evt->comm, sizeof(evt->comm));
  evt->timestamp_ns = bpf_ktime_get_ns();
  bpf_ringbuf_submit(evt, 0);
}

// Same as emit_io_event, plus a real enter->exit duration -- used by the
// pwrite64 exit handler, the synchronous O_DIRECT completion-latency probe.
static __always_inline void emit_io_event_dur(u32 pid, u32 tid, s32 syscall_nr,
                                              s32 fd, s64 result, u64 count,
                                              u32 whence, u64 duration_ns) {
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
  evt->duration_ns = duration_ns;
  bpf_get_current_comm(evt->comm, sizeof(evt->comm));
  evt->timestamp_ns = bpf_ktime_get_ns();
  bpf_ringbuf_submit(evt, 0);
}

static __always_inline void emit_mmap_event(u32 pid, u32 tid, s32 fd, u64 addr,
                                            u64 length, u64 offset, u32 prot, u32 flags) {
  struct montauk_mmap_event *evt;
  evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
  if (!evt)
    return;
  evt->type = TRACE_EVT_MMAP;
  evt->pid = pid;
  evt->tid = tid;
  evt->fd = fd;
  evt->addr = addr;
  evt->length = length;
  evt->offset = offset;
  evt->prot = prot;
  evt->flags = flags;
  evt->timestamp_ns = bpf_ktime_get_ns();
  bpf_get_current_comm(evt->comm, sizeof(evt->comm));
  bpf_ringbuf_submit(evt, 0);
}

// Emit a keyed-event record (critical-section wait/release by lock identity).
static __always_inline void emit_keyedevt(u32 op, u64 key) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  struct montauk_keyedevt_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e)
    return;
  e->type = TRACE_EVT_KEYEDEVT;
  e->pid = pid_tgid >> 32;
  e->tid = (u32)pid_tgid;
  e->op = op;
  e->key = key;
  e->timestamp_ns = bpf_ktime_get_ns();
  bpf_get_current_comm(e->comm, sizeof(e->comm));
  bpf_ringbuf_submit(e, 0);
}

// Emit a SIGNAL event with the current task's user-mode stack snapshot.
// kind distinguishes synchronous deliver (sig is the actual signal) from
// post-mortem exit capture (sig = low 7 bits of exit_code, may be 0).
//
// bpf_get_stack with BPF_F_USER_STACK walks the userspace stack via either
// frame pointers (cheap, accurate if -fno-omit-frame-pointer) or DWARF
// unwind (libbpf installs a CORE-relocated helper for stripped binaries).
// Some code is built without frame pointers; the captured frames may be
// partial but always include the innermost IP, which is the load-bearing
// datum for "what was executing when this died."
static __always_inline void emit_signal_event(void *ctx, u32 kind, u32 pid,
                                              u32 tid, s32 sig, s32 sender_pid,
                                              s32 exit_code) {
  struct montauk_signal_event *evt;
  evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
  if (!evt)
    return;
  evt->type        = TRACE_EVT_SIGNAL;
  evt->pid         = pid;
  evt->tid         = tid;
  evt->kind        = kind;
  evt->signal_nr   = sig;
  evt->sender_pid  = sender_pid;
  evt->exit_code   = exit_code;
  evt->timestamp_ns = bpf_ktime_get_ns();
  bpf_get_current_comm(evt->comm, sizeof(evt->comm));

  // Per-thread state lookup: what syscall was this thread in when the
  // signal fired? thread_map is keyed by tid and is updated on every
  // sys_enter/sys_exit. If the entry exists (we've seen this thread
  // before), copy syscall_nr and the first two args plus io_fd.
  evt->syscall_nr  = -1;
  evt->io_fd       = -1;
  evt->syscall_arg0 = 0;
  evt->syscall_arg1 = 0;
  struct thread_bpf_state *ts = bpf_map_lookup_elem(&thread_map, &tid);
  if (ts) {
    evt->syscall_nr   = ts->syscall_nr;
    evt->io_fd        = ts->io_fd;
    evt->syscall_arg0 = ts->syscall_arg0;
    evt->syscall_arg1 = ts->syscall_arg1;
  }

  // bpf_get_stack returns size in bytes; convert to frame count.
  // BPF_F_USER_STACK walks user-mode stack; without it we'd get kernel stack.
  // ctx is the tracepoint context (or pt_regs for uprobes); required by
  // the verifier so the helper can reach pt_regs->ip/sp for the unwinder.
  long stack_bytes = bpf_get_stack(ctx, evt->stack_user,
                                   sizeof(evt->stack_user),
                                   BPF_F_USER_STACK);
  if (stack_bytes > 0)
    evt->stack_depth = (u32)(stack_bytes / sizeof(__u64));
  else
    evt->stack_depth = 0;

  bpf_ringbuf_submit(evt, 0);
}

// PROCESS LIFECYCLE

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

  // TRACE_EVT_EXEC: previously computed but never submitted, leaving
  // CpuHolderLedger with no authoritative rename signal for a forked-then-
  // exec'd task -- only THREAD_NAME's one-binding-per-tid snapshot, which is
  // wrong if it happens to land pre-exec (the child briefly carries its
  // parent's inherited comm, per handle_fork's own comment). Checked AFTER
  // the auto-track block so a process that just became tracked BY this exec
  // (the common case: a fork+exec child whose new name matches the trace
  // pattern) is included, not only processes tracked before it ran.
  if (is_tracked(pid)) {
    struct montauk_ring_event *ee = bpf_ringbuf_reserve(&events, sizeof(*ee), 0);
    if (ee) {
      ee->type      = TRACE_EVT_EXEC;
      ee->pid       = pid;
      ee->ppid      = 0;
      ee->child_pid = 0;
      bpf_get_current_comm(ee->comm, sizeof(ee->comm));
      __builtin_memcpy(ee->filename, filename, sizeof(ee->filename));
      bpf_ringbuf_submit(ee, 0);
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
  int code = 0;
  if (info) {
    info->exited = 1;
    info->exit_ts = bpf_ktime_get_ns();
    // Exit code from task_struct: (exit_code >> 8) = status, (exit_code & 0x7f) = signal
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task) {
      bpf_probe_read_kernel(&code, sizeof(code), &task->exit_code);
      info->exit_code = code;
    }
  }

  // Abnormal-exit stack snapshot: if the task died via signal OR with a
  // non-zero status, emit a SIGEVT_EXIT_ABNL with the user stack at the
  // point of death. The low 7 bits of exit_code are the signal that killed
  // the task (or 0 if a clean exit(N)); the high byte is the status.
  // This complements signal_deliver — for SIGKILL the kernel doesn't always
  // dispatch a signal_deliver event (the task may never re-enter user mode),
  // so capturing at sched_process_exit catches what signal_deliver misses.
  s32 sig_low = code & 0x7f;
  s32 status  = (code >> 8) & 0xff;
  if (sig_low != 0 || status != 0) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = (u32)pid_tgid;
    emit_signal_event(ctx, SIGEVT_EXIT_ABNL, pid, tid,
                      sig_low, 0 /* sender unknown at exit */, code);
  }

  // Thread cleanup: delete this tid from thread_map
  bpf_map_delete_elem(&thread_map, &pid);
  return 0;
}

// signal_deliver fires when the kernel is about to dispatch a signal to a
// user-mode task. Captures the signal number + sender + user stack so the
// next userspace digest can answer "what was thread X doing when it got
// SIGSEGV?" without WINEDEBUG. Only emits for signals we care about (the
// fatal/anomaly class); arbitrary SIGCHLD / SIGURG noise is filtered.
SEC("tp/signal/signal_deliver")
int handle_signal_deliver(struct trace_event_raw_signal_deliver *ctx) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;
  if (!is_tracked(pid))
    return 0;

  s32 sig = ctx->sig;
  // Whitelist of "interesting" signals — the ones that mean death or
  // memory/state corruption. SIGTERM included because games sometimes use
  // it as a graceful shutdown trigger we want logged.
  switch (sig) {
    case 4:   // SIGILL
    case 6:   // SIGABRT
    case 7:   // SIGBUS
    case 8:   // SIGFPE
    case 9:   // SIGKILL (rarely dispatched here, but try)
    case 11:  // SIGSEGV
    case 5:   // SIGTRAP (INT 3, __debugbreak)
    case 15:  // SIGTERM
      break;
    default:
      return 0;
  }

  u32 tid = (u32)bpf_get_current_pid_tgid();
  emit_signal_event(ctx, SIGEVT_DELIVER, pid, tid, sig,
                    0 /* sender filled by signal_generate if interleaved */,
                    0 /* exit_code irrelevant on deliver */);
  return 0;
}

// NTSYNC HELPERS (used by raw_syscalls handlers below)

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

// SYSCALL TRACING

// Resolve an fd in the current task to its kernel object identity
// (file->private_data). This pointer is the same struct on both sides of an
// SCM_RIGHTS fd pass, so it lets a thread's wait object be matched to the
// thread that signals it — even though the two hold different fd numbers.
static __always_inline __u64 montauk_fd_obj(int fd) {
  if (fd < 0 || fd >= 65536) return 0;
  struct task_struct *t = (struct task_struct *)bpf_get_current_task();
  struct file **fdarr = BPF_CORE_READ(t, files, fdt, fd);
  if (!fdarr) return 0;
  struct file *f = NULL;
  bpf_probe_read_kernel(&f, sizeof(f), &fdarr[fd]);
  if (!f) return 0;
  return (__u64)BPF_CORE_READ(f, private_data);
}

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
      // Record the PROCESS (group_leader) comm, not the running thread's. A
      // multi-threaded process's worker threads can carry their own names,
      // which would mask the process name the --trace pattern matches and
      // leave the process unpromoted. The group_leader is the main thread
      // whose comm is the process identity (the exec'd binary). discovery_entry
      // is keyed by tgid, so this is the right granularity.
      struct task_struct *cur = (struct task_struct *)bpf_get_current_task();
      BPF_CORE_READ_STR_INTO(&de.comm, cur, group_leader, comm);
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

    // Only a group_leader (main-thread) rename changes the PROCESS identity.
    // A worker thread renaming itself must NOT clobber the process comm in
    // discovery_map/proc_map or auto-track on its own name — that is exactly how
    // a worker pool could mask the process name and break promotion. A process
    // that renames its own main thread to its final identity after exec still
    // catches the intended case (tid == tgid). The thread's own comm is updated
    // unconditionally in thread_map below.
    if (tid == pid) {
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
        // Any process that renames its main thread to match the pattern gets
        // auto-tracked immediately. Application-agnostic.
        if (trace_pat.len > 0) {
          if (bpf_substr_match(de.comm, 16, (const char *)trace_pat.pattern, trace_pat.len)) {
            auto_track_pid(pid);
          }
        }
      }
    }

    // Update thread_map if entry exists (per-thread comm — always)
    struct thread_bpf_state *ts = bpf_map_lookup_elem(&thread_map, &tid);
    if (ts) {
      bpf_probe_read_user_str(ts->comm, sizeof(ts->comm), name);
    }
  }

  if (!is_tracked(pid))
    return 0;

  /* FUTEX (x86_64 syscall 202): capture op (arg1: FUTEX_WAIT=0 / FUTEX_WAKE=1
   * plus PRIVATE/CLOCK flags), val (arg2), and uaddr (arg0) for tracked
   * threads. Answers the lost-wakeup question: is a FUTEX_WAKE issued against
   * a blocked worker that then never re-enqueues? Reuses the IO event slots
   * (op->fd, val->result, uaddr->count). */
  if (syscall_id == 202)
    emit_io_event(pid, tid, 202, (s32)arg1, (s64)arg2, arg0, 0);

  /* I/O-WAIT syscalls (poll/ppoll/epoll_wait/epoll_pwait/select/pselect6/
   * recvmsg/recvfrom): a thread blocked here is parked on a producer the way an
   * ntsync waiter is, but in a syscall that may never return (a mainloop in
   * poll() on a socket or fd). Emit a PENDING (result=-999) enter marker so the
   * analyzer can name a thread still parked in it at trace end; the exit
   * handler emits the completion that pairs it. */
  {
    s32 io_fd = -1;
    int is_iowait = 1;
    switch (syscall_id) {
      case 232: case 281: /* epoll_wait / epoll_pwait: arg0 = epfd */
      case 47:  case 45:  /* recvmsg / recvfrom: arg0 = sockfd */
        io_fd = (s32)arg0; break;
      case 7:   case 271: /* poll / ppoll: arg0 = pollfd[], arg1 = nfds */
        if (arg1 > 0) {
          int first_fd = -1;
          bpf_probe_read_user(&first_fd, sizeof(first_fd), (void *)arg0);
          io_fd = first_fd;
        }
        break;
      case 23:  case 270: /* select / pselect6: no single fd */
        io_fd = -1; break;
      case 16: /* ioctl: arg0 = fd, arg1 = cmd. A non-ntsync ioctl that
                * never returns is a genuine blind spot -- e.g. a DRM/GPU
                * driver wait-idle call. ntsync ioctls already get their
                * own richer TRACE_EVT_NTSYNC pending/parked tracking a
                * few lines below; skip the generic marker for those so
                * the same wait isn't double-counted in both iowait and
                * endstate. */
        if (is_ntsync_ioctl((u32)arg1))
          is_iowait = 0;
        else
          io_fd = (s32)arg0;
        break;
      default:
        is_iowait = 0; break;
    }
    if (is_iowait) {
      emit_io_event(pid, tid, syscall_id, io_fd, -999, 0, 0);
      struct thread_bpf_state *iw_ts = bpf_map_lookup_elem(&thread_map, &tid);
      if (iw_ts)
        iw_ts->io_enter_ns = bpf_ktime_get_ns();
    }
  }

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
    new_ts.cur_cpu = -1; // not yet scheduled -> first sched-in is not a migration
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
                // Resolve object identities at entry too: a parked wait never
                // reaches sys_exit, so this is the only place the stuck object
                // gets a real pointer.
                we->obj_ptr = 0;
                __builtin_memset(we->wait_objs, 0, sizeof(we->wait_objs));
                {
                  u32 wn = s->wait_count;
                  if (wn > NTSYNC_MAX_WAIT_FDS) wn = NTSYNC_MAX_WAIT_FDS;
                  #pragma unroll
                  for (u32 wi = 0; wi < NTSYNC_MAX_WAIT_FDS; wi++) {
                    if (wi >= wn) break;
                    we->wait_objs[wi] = montauk_fd_obj((int)s->wait_fds[wi]);
                  }
                }
                bpf_get_current_comm(we->comm, sizeof(we->comm));
                bpf_ringbuf_submit(we, 0);
              }
            }
            // Wait-site stack for INFINITE waits only (the hang-prone ones). A
            // thread parked at trace end never reaches sys_exit, so this names
            // WHERE it blocked (resolved offline against the maps sidecar).
            if (s->timeout_ns == ~0ULL) {
              struct montauk_waitstack_event *ws =
                  bpf_ringbuf_reserve(&events, sizeof(*ws), 0);
              if (ws) {
                ws->type = TRACE_EVT_WAITSTACK;
                ws->pid = pid;
                ws->tid = tid;
                ws->obj_ptr = s->wait_count > 0
                                  ? montauk_fd_obj((int)s->wait_fds[0]) : 0;
                ws->timeout_ns = s->timeout_ns;
                long sb = bpf_get_stack(ctx, ws->stack_user,
                                        sizeof(ws->stack_user), BPF_F_USER_STACK);
                ws->stack_depth = sb > 0 ? (u32)(sb / sizeof(u64)) : 0;
                bpf_get_current_comm(ws->comm, sizeof(ws->comm));
                ws->timestamp_ns = bpf_ktime_get_ns();
                bpf_ringbuf_submit(ws, 0);
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
    // I/O-wait completion: pair the pending enter (above) so a poll/epoll/recv
    // that DID return is not mistaken for a thread still parked in it. Also
    // carries a real enter->exit duration now (iowait_enter above stashes
    // io_enter_ns) -- a generic blocking-wait completion-latency probe, the
    // same shape as pwrite64's, for any consumer parked in poll/epoll_wait/
    // select/recvmsg/a non-ntsync ioctl. Was duration_ns=0 (marker-only)
    // before; iolat's fold() already ignores duration_ns==0 entries, so this
    // is additive and does not change anything that read these events prior.
    s32 snr = ts->syscall_nr;
    if (snr == 7 || snr == 271 || snr == 232 || snr == 281 ||
        snr == 47 || snr == 45 || snr == 23 || snr == 270 ||
        (snr == 16 && !is_ntsync_ioctl((u32)ts->syscall_arg1))) {
      u64 now = bpf_ktime_get_ns();
      u64 dur = (ts->io_enter_ns && now > ts->io_enter_ns) ? (now - ts->io_enter_ns) : 0;
      emit_io_event_dur(pid, tid, snr, -1, ctx->ret, 0, 0, dur);
      ts->io_enter_ns = 0;
    }
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
        // Kernel object identities for cross-fd matching (lost-wakeup resolver):
        // waits resolve each object fd; signal/read ops resolve their own fd.
        evt->obj_ptr = 0;
        __builtin_memset(evt->wait_objs, 0, sizeof(evt->wait_objs));
        if (s->op == NTS_WAIT_ANY || s->op == NTS_WAIT_ALL) {
          u32 wn = s->wait_count;
          if (wn > NTSYNC_MAX_WAIT_FDS) wn = NTSYNC_MAX_WAIT_FDS;
          #pragma unroll
          for (u32 wi = 0; wi < NTSYNC_MAX_WAIT_FDS; wi++) {
            if (wi >= wn) break;
            evt->wait_objs[wi] = montauk_fd_obj((int)s->wait_fds[wi]);
          }
        } else if (s->op != NTS_CREATE_SEM && s->op != NTS_CREATE_MUTEX &&
                   s->op != NTS_CREATE_EVENT) {
          evt->obj_ptr = montauk_fd_obj(s->fd);
        } else if (ctx->ret >= 0) {
          // Create ops: s->fd is the /dev/ntsync device fd, not the object. The
          // new object fd is the ioctl return value (also recorded in
          // evt->result). Resolve its kernel object pointer so every object gets
          // a (pid, fd)->obj_ptr binding at birth — joinable even if the daemon
          // never signals it within the trace window. Consumers key creates on
          // result, signals/reads on fd.
          evt->obj_ptr = montauk_fd_obj((int)ctx->ret);
        }
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

// SCHEDULER STATE

// tp/power/cpu_frequency: the cpufreq core fires this on every P-state
// transition (cpu_id = target CPU, state = new frequency in KHz). Keep only the
// latest MHz per CPU so WAKE2RUN can read the core's frequency at the wake
// instant. Stable tracepoint ABI: 8-byte common header, then state, cpu_id.
struct trace_event_raw_cpu_frequency_compat {
  unsigned long long pad;
  unsigned int state;    // new frequency in KHz
  unsigned int cpu_id;   // target CPU
};

SEC("tp/power/cpu_frequency")
int handle_cpu_frequency(struct trace_event_raw_cpu_frequency_compat *ctx) {
  if (!sched_stream)
    return 0;
  u32 cpu = ctx->cpu_id;
  if (cpu >= TRACE_MAX_CPUS)
    return 0;
  u32 mhz = ctx->state / 1000;  // KHz -> MHz
  bpf_map_update_elem(&cur_freq_mhz, &cpu, &mhz, BPF_ANY);
  return 0;
}

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
    if (prev_state == 0) {
      prev->state = 0; // R (preempted, still runnable)
      // Involuntary preempt: runnable but lost the CPU. Stamp so the next
      // sched-in measures the runqueue wait (bcc runqlat re-enqueue case).
      prev->wake_ns = now;
    } else if (prev_state & 0x01) // TASK_INTERRUPTIBLE
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
    // STATE AT LAST SWITCH-OUT, CAPTURED BEFORE WE RESET IT BELOW: 0 = R (PREEMPTED, STILL
    // RUNNABLE -> A DISPATCH STEAL PULLED IT HERE); S/D = SLEPT (-> THE SCHEDULER PLACED A
    // WOKEN TASK ON THIS CPU AT WAKE = A select_cpu / ENQUEUE SPILL PUSH). MAINTAINED
    // ALWAYS-ON (sched_switch IS NOT sched_stream-GATED), SO THE SPLIT WORKS ON A .prom-ONLY
    // CAPTURE TOO -- NO --trace NEEDED.
    int off_state = next->state;
    next->enter_ns = now;
    next->state = 0; // R (running)
    // ON-CPU + MIGRATION: count a cross-CPU move when the running core changes,
    // and classify it intra- vs cross-domain by the L3 domain of src/dst core.
    int cpu = (int)bpf_get_smp_processor_id();
    int prev_run_cpu = next->cur_cpu;  // src core of this sched-in; stamped on WAKE2RUN
    int cross_domain = 0;  // did this sched-in land on a different cache domain than last run
    if (next->cur_cpu >= 0 && next->cur_cpu != cpu) {
      next->migrations += 1;
      u32 src = (u32)next->cur_cpu, dst = (u32)cpu;
      u32 *sc = (src < TRACE_MAX_CPUS) ? bpf_map_lookup_elem(&cpu_cache_domain, &src) : NULL;
      u32 *dc = (dst < TRACE_MAX_CPUS) ? bpf_map_lookup_elem(&cpu_cache_domain, &dst) : NULL;
      u32 zero = 0;
      struct mig_domain_counters *m = bpf_map_lookup_elem(&mig_domain_counts, &zero);
      // SPILL vs STEAL: A SLEPT-THEN-WOKEN TASK (off_state != R) WAS PLACED ON THIS CPU AT
      // WAKE -- A select_cpu / ENQUEUE SPILL PUSH; A PREEMPTED-STILL-RUNNABLE TASK
      // (off_state == 0) WAS PULLED HERE AT DISPATCH -- A STEAL. THE PATH-BLIND MIGRATION
      // COUNT CANNOT TELL THE TWO APART; ON A SINGLE-CCX BOX (cross ALWAYS 0) THIS SPLIT IS
      // THE ONLY WAY TO SEE WHICH SIDE SCATTERS A THRASHING PAIR.
      int woke = (off_state != 0);
      if (sc && dc) {
        if (*sc == *dc) { if (m) { m->intra += 1; if (woke) m->intra_wake += 1; else m->intra_steal += 1; } }
        else { cross_domain = 1; if (m) { m->cross += 1; if (woke) m->cross_wake += 1; else m->cross_steal += 1; } }
      } else if (m) {
        m->unknown += 1;
      }
    }
    next->cur_cpu = cpu;

    // WAKE-TO-RUN: drain a pending became-runnable stamp into one latency
    // sample. The timestamps are kernel-side (sched_wakeup / preempt -> here),
    // so no userspace measurer is in the path -- the artifact that made wall-
    // clock IPC timing unusable is structurally absent. Tagged cross_domain so the
    // tail can be attributed to cross-domain placement.
    if (sched_stream && next->wake_ns) {
      u64 d = (now > next->wake_ns) ? (now - next->wake_ns) : 0;
      struct montauk_sched_event *we =
          bpf_ringbuf_reserve(&events, sizeof(*we), 0);
      if (we) {
        we->type          = TRACE_EVT_SCHED;
        we->op            = SCHED_OP_WAKE2RUN;
        we->cpu           = (u32)cpu;
        we->pid           = (int)next_tid;
        we->secondary_pid = -1;
        we->last_cpu      = prev_run_cpu;  // migration src core (-1 = no prior run)
        we->sub_idx       = (u32)cross_domain;
        u32 fcpu          = (u32)cpu;
        u32 *fp           = bpf_map_lookup_elem(&cur_freq_mhz, &fcpu);
        we->freq_mhz      = fp ? *fp : 0;  // core freq at wake; 0 if no transition seen
        we->score         = 0;
        we->runtime_ns    = d;
        we->budget_ns     = 0;
        we->timestamp_ns  = now;
        bpf_ringbuf_submit(we, 0);
      }
    }
    next->wake_ns = 0;
    // comm is already set by handle_sys_enter via bpf_get_current_comm()
  }

  // PER-CPU KTHREAD STRAND: a kthread we stamped at wakeup (handle_kpcpu_wakeup)
  // is coming on-CPU. Drain its became-runnable stamp; if it waited past the
  // threshold, emit one strand event. Runs OUTSIDE the thread_map (`next`) gate
  // above -- these kthreads are not in the traced comm group, so `next` is NULL
  // for them. The comm was stamped into the map at wakeup (from the task_struct),
  // so naming the thread needs no tracepoint-ctx dereference here.
  if (sched_stream) {
    struct kpcpu_wait *kw = bpf_map_lookup_elem(&kpcpu_wake, &next_tid);
    if (kw) {
      u64 wake_ns = kw->wake_ns;
      u64 lat = (now > wake_ns) ? (now - wake_ns) : 0;
      if (lat >= kstrand_thresh_ns) {
        struct montauk_kstrand_event *ke =
            bpf_ringbuf_reserve(&events, sizeof(*ke), 0);
        if (ke) {
          ke->type            = TRACE_EVT_KSTRAND;
          ke->tid             = next_tid;
          ke->cpu             = (u32)bpf_get_smp_processor_id();
          ke->nr_cpus_allowed = 1;
          ke->latency_ns      = lat;
          ke->timestamp_ns    = now;
          __builtin_memcpy(ke->comm, kw->comm, sizeof(ke->comm));
          bpf_ringbuf_submit(ke, 0);
        }
      }
      bpf_map_delete_elem(&kpcpu_wake, &next_tid);
    }
  }

  // PER-CPU IDLE BOUNDARY. Emitted for EVERY CPU's idle transitions, not just
  // the traced comm group -- the only event here that is. The traced-group gate
  // above (thread_map/is_tracked) drops swapper, so without this the analyzer
  // can only INFER idleness from coarse PICK gaps and cannot answer "was a CPU
  // idle at this wake instant." A wakee landing on a busy CPU while another sat
  // idle is the placement-race signature; this is the signal that proves it.
  // pid 0 = swapper: next_pid==0 -> CPU enters idle; prev_pid==0 -> CPU leaves
  // idle. One tiny ringbuf event per boundary. Gated on sched_stream (binary
  // --trace-out only) AND sched_detail (--sched-detail, OFF by default): on a
  // CPU-cycling workload (make -jN) this fires on every CPU's every idle flip
  // system-wide -- ~82% of a build capture, a ~6x trace overhead -- so a generic
  // --trace must not pay it. The placement-race / dispatch-stall / kstrand /
  // cold-wake reports that consume CPU_IDLE require --sched-detail; without it they
  // report the idle signal absent, exactly as a pre-CPU_IDLE trace does.
  if (sched_stream && sched_detail && (next_tid == 0 || prev_tid == 0)) {
    u32 idle_cpu = (u32)bpf_get_smp_processor_id();
    struct montauk_sched_event *ie =
        bpf_ringbuf_reserve(&events, sizeof(*ie), 0);
    if (ie) {
      ie->type          = TRACE_EVT_SCHED;
      ie->op            = SCHED_OP_CPU_IDLE;
      ie->cpu           = idle_cpu;
      ie->pid           = 0;
      ie->secondary_pid = -1;
      ie->last_cpu      = -1;
      ie->sub_idx       = (next_tid == 0) ? 1u : 0u;  // 1 = entering idle
      ie->score         = 0;
      ie->runtime_ns    = 0;
      ie->budget_ns     = 0;
      ie->timestamp_ns  = now;
      bpf_ringbuf_submit(ie, 0);
    }
  }

  // THREAD NAME BINDING: one tid->comm record per distinct thread so the holder
  // ledger can name a CPU-bound task whose only appearance is SWITCH_IN (emits no
  // syscall, predates the trace). Deduped via named_tids; sched_stream-gated, so
  // it is one event per thread for the whole capture, not per switch.
  if (sched_stream && next_tid != 0) {
    __u8 one = 1;
    if (bpf_map_update_elem(&named_tids, &next_tid, &one, BPF_NOEXIST) == 0) {
      struct montauk_ring_event *ne =
          bpf_ringbuf_reserve(&events, sizeof(*ne), 0);
      if (ne) {
        ne->type        = TRACE_EVT_THREAD_NAME;
        ne->pid         = next_tid;
        ne->ppid        = 0;
        ne->child_pid   = 0;
        // next_comm is an array inside the tracepoint ctx (PTR_TO_CTX); a bulk
        // memcpy out of it is verifier-rejected (-EACCES), so read it through the
        // probe-read path montauk uses for the exec filename.
        bpf_probe_read_kernel_str(ne->comm, sizeof(ne->comm), ctx->next_comm);
        ne->filename[0] = '\0';
        bpf_ringbuf_submit(ne, 0);
      }
    }
  }

  // SCHED_SWITCH-DERIVED PICK. When no scheduler pick tracepoint is bound
  // (switch_in_fallback, set by the collector post-attach), the next task coming
  // on-CPU is the pick the slice/service reports need -- sched_switch is universal,
  // so this resolves those reports for EEVDF and any scx mode that does not export
  // a pick. Per-switch like CPU_IDLE above (the hog holding a CPU is not in the
  // traced comm group, yet its slice is exactly what we measure); idle excluded
  // (that boundary is CPU_IDLE). Suppressed when the scheduler's own pick stream is
  // present, so it never double-counts. On a pick-less scheduler (EEVDF) under a
  // switch-heavy workload it is a per-switch firehose, the SWITCH_IN sibling of the
  // idle firehose -- so it shares the sched_detail gate (--sched-detail, off by
  // default); the slice/service reports that need it ask for the same flag.
  if (sched_stream && sched_detail && switch_in_fallback && next_tid != 0) {
    struct montauk_sched_event *pe =
        bpf_ringbuf_reserve(&events, sizeof(*pe), 0);
    if (pe) {
      pe->type          = TRACE_EVT_SCHED;
      pe->op            = SCHED_OP_SWITCH_IN;
      pe->cpu           = (u32)bpf_get_smp_processor_id();
      pe->pid           = (int)next_tid;
      pe->secondary_pid = -1;
      pe->last_cpu      = -1;
      pe->sub_idx       = 0;
      pe->freq_mhz      = 0;
      pe->score         = 0;
      pe->runtime_ns    = 0;
      pe->budget_ns     = 0;
      pe->timestamp_ns  = now;
      bpf_ringbuf_submit(pe, 0);
    }
  }

  return 0;
}

// Generic kernel wakeup tracepoint. Field layout mirrors the stable
// sched:sched_wakeup ABI: 8-byte common header, then comm/pid/prio/target_cpu.
// ctx->pid is the woken thread's TID; ctx->target_cpu is the CPU it's being
// made runnable on. Lets us distinguish woken-but-not-dispatched from
// never-woken when a thread strands. Scoped to the traced group (thread_map
// for enrolled threads, proc_map for a main thread where tid==tgid) so this
// high-frequency tracepoint stays near-zero-overhead for everything else.
struct trace_event_raw_sched_wakeup_compat {
  unsigned long long pad;
  char comm[16];
  int  pid;        // woken TID
  int  prio;
  int  target_cpu;
};

SEC("tp/sched/sched_wakeup")
int handle_sched_wakeup(struct trace_event_raw_sched_wakeup_compat *ctx) {
  sched_op_bump(SCHED_OP_WAKEUP);
  if (!sched_stream)
    return 0;

  u32 woken = (u32)ctx->pid;
  struct thread_bpf_state *wt = bpf_map_lookup_elem(&thread_map, &woken);
  // Gate to the traced group: enrolled thread, or a tracked tgid (main thread).
  if (!wt && !is_tracked(woken))
    return 0;
  // Stamp became-runnable time; sched-in drains it into a wake-to-run sample.
  if (wt)
    wt->wake_ns = bpf_ktime_get_ns();

  struct montauk_sched_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e) return 0;
  e->type          = TRACE_EVT_SCHED;
  e->op            = SCHED_OP_WAKEUP;
  e->cpu           = (u32)ctx->target_cpu;
  e->pid           = ctx->pid;
  /* v7.9.0: stamp the WAKER. sched_wakeup fires in try_to_wake_up in the
   * waker's context, so current is the task issuing the wake. Recording it
   * gives every wake its causal edge waker -> wakee, which the analyzer walks
   * to reconstruct the messenger->worker wake chain and attribute request-level
   * latency per hop (the interval schbench reports but per-hop wake2run cannot
   * localize). -1 only for a kernel/IRQ-context wake with no task current. */
  e->secondary_pid = (int)(bpf_get_current_pid_tgid() & 0xffffffffULL);
  e->last_cpu      = -1;
  e->sub_idx       = 0;
  e->score         = 0;
  e->runtime_ns    = 0;
  e->budget_ns     = 0;
  e->timestamp_ns  = bpf_ktime_get_ns();
  bpf_ringbuf_submit(e, 0);
  return 0;
}

// Per-CPU kthread wakeup stamp. The classic tp/sched/sched_wakeup carries only
// pid/comm/target_cpu (no task_struct), so it cannot see nr_cpus_allowed or
// PF_KTHREAD -- the two fields that identify a CPU-bound kernel thread. This BTF
// raw tracepoint gets the task pointer directly. Cheap: two scalar reads gate
// everything; only an actual per-CPU kthread touches the map. Gated on
// sched_stream so it is inert outside binary --trace-out capture. The sched-in
// side (handle_sched_switch) drains the stamp and emits TRACE_EVT_KSTRAND.
SEC("tp_btf/sched_wakeup")
int BPF_PROG(handle_kpcpu_wakeup, struct task_struct *p)
{
  if (!sched_stream)
    return 0;
  if (!(BPF_CORE_READ(p, flags) & PF_KTHREAD))
    return 0;
  if (BPF_CORE_READ(p, nr_cpus_allowed) != 1)
    return 0;
  u32 tid = (u32)BPF_CORE_READ(p, pid);
  struct kpcpu_wait w = {};
  w.wake_ns = bpf_ktime_get_ns();
  // p->comm is a fixed char[16]; read it through CO-RE (a tp_btf task ptr is
  // trusted, so this is verifier-clean -- unlike a tracepoint-ctx array field).
  BPF_CORE_READ_STR_INTO(&w.comm, p, comm);
  // BPF_NOEXIST: keep the EARLIEST pending wake so a re-wakeup of a still-stranded
  // kthread does not reset the clock and hide the true strand duration.
  bpf_map_update_elem(&kpcpu_wake, &tid, &w, BPF_NOEXIST);
  return 0;
}

// SCHED_EXT KICK-STORM COUNTERS
// fentry on the scx kfuncs: each kick / re-enqueue bumps a per-CPU counter that the
// collector reads + deltas every log interval (TRACE_EVT_SCX_STORM). Gated on
// sched_stream so they stay inert outside binary --trace-out capture.
#ifndef SCX_KICK_PREEMPT
#define SCX_KICK_PREEMPT (1ULL << 1)
#endif

SEC("fentry/scx_bpf_kick_cpu")
int BPF_PROG(handle_scx_kick, s32 cpu, u64 flags)
{
  sched_op_bump(SCHED_OP_KICK_ISSUE);
  if (!sched_stream)
    return 0;
  u32 zero = 0;
  struct scx_storm_counters *c = bpf_map_lookup_elem(&scx_storm, &zero);
  if (c) {
    c->kicks++;
    if (flags & SCX_KICK_PREEMPT)
      c->preempt_kicks++;
  }

  // KICK_ISSUE: target cpu being kicked (cpu), issuing cpu (last_cpu), kick
  // flags (score) -- generic to any sched_ext scheduler. Pair against
  // SCHED_OP_RESCHED on the same target cpu to see whether the kick actually
  // resulted in a resched, or was swallowed.
  struct montauk_sched_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e) return 0;
  e->type          = TRACE_EVT_SCHED;
  e->op            = SCHED_OP_KICK_ISSUE;
  e->cpu           = (u32)cpu;
  e->pid           = -1;
  e->secondary_pid = -1;
  e->last_cpu      = (s32)bpf_get_smp_processor_id();
  e->sub_idx       = 0;
  e->score         = flags;
  e->runtime_ns    = 0;
  e->budget_ns     = 0;
  e->timestamp_ns  = bpf_ktime_get_ns();
  bpf_ringbuf_submit(e, 0);
  return 0;
}

SEC("fentry/resched_curr")
int BPF_PROG(handle_resched_curr, struct rq *rq)
{
  sched_op_bump(SCHED_OP_RESCHED);
  if (!sched_stream)
    return 0;

  // RESCHED: resched_curr() fired for a CPU's runqueue -- the actual
  // wake mechanism, regardless of what triggered it (kick, preemption,
  // or anything else). Universal to any scheduling class, not sched_ext-
  // specific. Absence of a RESCHED shortly after a KICK_ISSUE for the same
  // target cpu is the generic signature of a swallowed/lost kick.
  struct montauk_sched_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e) return 0;
  e->type          = TRACE_EVT_SCHED;
  e->op            = SCHED_OP_RESCHED;
  e->cpu           = (u32)BPF_CORE_READ(rq, cpu);
  e->pid           = -1;
  e->secondary_pid = -1;
  e->last_cpu      = (s32)bpf_get_smp_processor_id();
  e->sub_idx       = 0;
  e->score         = 0;
  e->runtime_ns    = 0;
  e->budget_ns     = 0;
  e->timestamp_ns  = bpf_ktime_get_ns();
  bpf_ringbuf_submit(e, 0);
  return 0;
}

SEC("tp/timer/tick_stop")
int handle_tick_stop(struct trace_event_raw_tick_stop *ctx)
{
  sched_op_bump(SCHED_OP_TICK_STOP);
  if (!sched_stream)
    return 0;

  // TICK_STOP: a CPU's periodic tick stop was evaluated (NOHZ_FULL, universal
  // to any tickless-capable kernel, not sched_ext-specific). sub_idx=success
  // (1 actually stopped / 0 blocked by a dependency), score=dependency
  // bitmask (TICK_DEP_MASK_*, meaningful only when sub_idx=0). Correlate
  // against KICK_ISSUE/RESCHED on the same cpu to see whether a CPU went
  // tickless right as a kick targeting it was in flight.
  struct montauk_sched_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e) return 0;
  e->type          = TRACE_EVT_SCHED;
  e->op            = SCHED_OP_TICK_STOP;
  e->cpu           = (u32)bpf_get_smp_processor_id();
  e->pid           = -1;
  e->secondary_pid = -1;
  e->last_cpu      = -1;
  e->sub_idx       = (u32)ctx->success;
  e->score         = (u64)ctx->dependency;
  e->runtime_ns    = 0;
  e->budget_ns     = 0;
  e->timestamp_ns  = bpf_ktime_get_ns();
  bpf_ringbuf_submit(e, 0);
  return 0;
}

SEC("fexit/scx_bpf_reenqueue_local")
int BPF_PROG(handle_scx_reenq, u32 ret)
{
  if (!sched_stream)
    return 0;
  u32 zero = 0;
  struct scx_storm_counters *c = bpf_map_lookup_elem(&scx_storm, &zero);
  if (!c)
    return 0;
  c->reenq += ret;
  return 0;
}

// COMM CHANGE TRACKING

// prctl(PR_SET_NAME) handling merged into handle_sys_enter above.

// FD TRACKING

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

// FILE I/O TRACKING

// lseek (syscall 8)

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

// read (syscall 0)

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

// write (syscall 1)

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

// pread64 (syscall 17)

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

// pwrite64 (syscall 18) -- the synchronous O_DIRECT completion-latency probe.
// A blocking pwrite() on an O_DIRECT fd does not return until the write has
// genuinely completed at the device, so enter->exit wall time on this syscall
// IS the true I/O completion latency; no separate block-layer bio hook needed.

SEC("tp/syscalls/sys_enter_pwrite64")
int handle_pwrite64_enter(struct trace_event_raw_sys_enter *ctx) {
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
  ts->io_whence = (u32)ctx->args[3]; // offset for pwrite64
  ts->io_enter_ns = bpf_ktime_get_ns();
  return 0;
}

SEC("tp/syscalls/sys_exit_pwrite64")
int handle_pwrite64_exit(struct trace_event_raw_sys_exit *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  u32 tid = (u32)pid_tgid;

  if (!is_tracked(pid))
    return 0;

  struct thread_bpf_state *ts = bpf_map_lookup_elem(&thread_map, &tid);
  if (!ts)
    return 0;

  ts->io_result = ctx->ret;
  u64 now = bpf_ktime_get_ns();
  u64 dur = (ts->io_enter_ns && now > ts->io_enter_ns) ? (now - ts->io_enter_ns) : 0;
  ts->io_timestamp_ns = now;
  emit_io_event_dur(pid, tid, 18, ts->io_fd, ctx->ret, ts->io_count, ts->io_whence, dur);
  return 0;
}

// io_getevents (syscall 208) -- the Linux AIO completion-reap probe. A thread
// blocked in io_getevents() does not return until at least min_nr completions
// are ready (or the timeout expires), so enter->exit wall time on this
// syscall is the completion-wait latency for whatever was queued via
// io_submit -- the async-AIO analog of pwrite64's synchronous completion-
// latency probe above. Generic to any Linux AIO consumer (e.g. qemu's
// aio=native drive backend), not specific to any one workload.

SEC("tp/syscalls/sys_enter_io_getevents")
int handle_io_getevents_enter(struct trace_event_raw_sys_enter *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  u32 tid = (u32)pid_tgid;

  if (!is_tracked(pid))
    return 0;

  struct thread_bpf_state *ts = bpf_map_lookup_elem(&thread_map, &tid);
  if (!ts)
    return 0;

  ts->io_fd = (s32)ctx->args[0];    // aio_context_t, not a real fd -- kept only for offender attribution
  ts->io_count = ctx->args[1];      // min_nr requested
  ts->io_enter_ns = bpf_ktime_get_ns();
  return 0;
}

SEC("tp/syscalls/sys_exit_io_getevents")
int handle_io_getevents_exit(struct trace_event_raw_sys_exit *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  u32 tid = (u32)pid_tgid;

  if (!is_tracked(pid))
    return 0;

  struct thread_bpf_state *ts = bpf_map_lookup_elem(&thread_map, &tid);
  if (!ts)
    return 0;

  ts->io_result = ctx->ret;
  u64 now = bpf_ktime_get_ns();
  u64 dur = (ts->io_enter_ns && now > ts->io_enter_ns) ? (now - ts->io_enter_ns) : 0;
  ts->io_timestamp_ns = now;
  emit_io_event_dur(pid, tid, 208, ts->io_fd, ctx->ret, ts->io_count, 0, dur);
  ts->io_enter_ns = 0;
  return 0;
}

// mmap (syscall 9)
//
// File-backed mmap is the path Unity-style asset loaders use when they call
// MapViewOfFile (or, on Linux, mmap directly on a file fd). It bypasses
// pread/read entirely so without this tracepoint a Unity bundle access is
// invisible. We filter out anonymous mappings at BPF (flags & MAP_ANONYMOUS)
// so the ring buffer doesn't get drowned by malloc-arena mmaps.

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS 0x20
#endif

SEC("tp/syscalls/sys_enter_mmap")
int handle_mmap_enter(struct trace_event_raw_sys_enter *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  if (!is_tracked(pid))
    return 0;

  u32 flags = (u32)ctx->args[3];
  if (flags & MAP_ANONYMOUS)
    return 0; // skip anon mappings (malloc arenas, stacks)

  u32 zero = 0;
  struct mmap_scratch *s = bpf_map_lookup_elem(&mmap_scratch_map, &zero);
  if (!s)
    return 0;

  s->length = ctx->args[1];
  s->prot   = (u32)ctx->args[2];
  s->flags  = flags;
  s->fd     = (s32)ctx->args[4];
  s->offset = ctx->args[5];
  return 0;
}

SEC("tp/syscalls/sys_exit_mmap")
int handle_mmap_exit(struct trace_event_raw_sys_exit *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  u32 tid = (u32)pid_tgid;

  if (!is_tracked(pid))
    return 0;

  u32 zero = 0;
  struct mmap_scratch *s = bpf_map_lookup_elem(&mmap_scratch_map, &zero);
  if (!s)
    return 0;

  // Filter again on exit — if enter was skipped (anon) the scratch holds
  // stale data from a previous mmap; skip if flags shows anon.
  if (s->flags & MAP_ANONYMOUS)
    return 0;

  emit_mmap_event(pid, tid, s->fd, (u64)ctx->ret, s->length, s->offset,
                  s->prot, s->flags);
  return 0;
}

// fstat / newfstat (syscall 5)

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

// Scheduler-decision tracepoints (generic). Captures the universal scheduler
// decision points -- enqueue, pick, pick_empty, preempt_tick, preempt_wakeup.
// These programs carry a neutral placeholder SEC and are NOT auto-attached;
// the collector attaches them at runtime to the active scheduler's tracepoints
// (category:name from config), so montauk names no scheduler in source. The
// structs below are the generic decision-event field contract a scheduler
// emits to. Emitted unconditionally (no pid filter) so the scheduler's
// mechanism is visible even before any process group is tracked.

struct trace_event_raw_sched_enqueue {
  unsigned long long pad;
  int          pid;
  int          cpu;
  int          last_cpu;
  unsigned int sub_idx;
  u64          score;
};

struct trace_event_raw_sched_pick {
  unsigned long long pad;
  int pid;
  int cpu;
  u64 score;
  u32 lane;   // dispatch lane that served this pick (0=mirror fast path, else sub+1)
};

struct trace_event_raw_sched_pick_empty {
  unsigned long long pad;
  int cpu;
};

struct trace_event_raw_sched_preempt_tick {
  unsigned long long pad;
  int pid;
  int cpu;
  u64 runtime_ns;
  u64 budget_ns;
};

struct trace_event_raw_sched_preempt_wakeup {
  unsigned long long pad;
  int waker;
  int wakee;
  int cpu;
};

struct trace_event_raw_sched_field_gate {
  unsigned long long pad;
  int cpu;
  int changed;    // 1 = signature moved this gate tick (re-derived); 0 = held
  u64 signature;  // current discrete field signature (regime code / pattern bitmap)
  u64 prev;       // signature at the previous gate tick
};

SEC("tp/sched_decision/enqueue")
int handle_sched_enqueue(struct trace_event_raw_sched_enqueue *ctx) {
  sched_op_bump(SCHED_OP_ENQUEUE);
  if (!sched_stream)
    return 0;
  struct montauk_sched_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e) return 0;
  e->type          = TRACE_EVT_SCHED;
  e->op            = SCHED_OP_ENQUEUE;
  e->cpu           = (u32)ctx->cpu;
  e->pid           = ctx->pid;
  e->secondary_pid = -1;
  e->last_cpu      = ctx->last_cpu;
  e->sub_idx       = ctx->sub_idx;
  e->score         = ctx->score;
  e->runtime_ns    = 0;
  e->budget_ns     = 0;
  e->timestamp_ns  = bpf_ktime_get_ns();
  bpf_ringbuf_submit(e, 0);
  return 0;
}

SEC("tp/sched_decision/pick")
int handle_sched_pick(struct trace_event_raw_sched_pick *ctx) {
  sched_op_bump(SCHED_OP_PICK);
  if (!sched_stream)
    return 0;
  struct montauk_sched_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e) return 0;
  e->type          = TRACE_EVT_SCHED;
  e->op            = SCHED_OP_PICK;
  e->cpu           = (u32)ctx->cpu;
  e->pid           = ctx->pid;
  e->secondary_pid = -1;
  e->last_cpu      = -1;
  e->sub_idx       = ctx->lane;   // dispatch lane (0=mirror, else sub+1)
  e->score         = ctx->score;
  e->runtime_ns    = 0;
  e->budget_ns     = 0;
  e->timestamp_ns  = bpf_ktime_get_ns();
  bpf_ringbuf_submit(e, 0);
  return 0;
}

SEC("tp/sched_decision/pick_empty")
int handle_sched_pick_empty(struct trace_event_raw_sched_pick_empty *ctx) {
  sched_op_bump(SCHED_OP_PICK_EMPTY);
  if (!sched_stream)
    return 0;
  struct montauk_sched_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e) return 0;
  e->type          = TRACE_EVT_SCHED;
  e->op            = SCHED_OP_PICK_EMPTY;
  e->cpu           = (u32)ctx->cpu;
  e->pid           = -1;
  e->secondary_pid = -1;
  e->last_cpu      = -1;
  e->sub_idx       = 0;
  e->score         = 0;
  e->runtime_ns    = 0;
  e->budget_ns     = 0;
  e->timestamp_ns  = bpf_ktime_get_ns();
  bpf_ringbuf_submit(e, 0);
  return 0;
}

SEC("tp/sched_decision/preempt_tick")
int handle_sched_preempt_tick(struct trace_event_raw_sched_preempt_tick *ctx) {
  sched_op_bump(SCHED_OP_PREEMPT_TICK);
  if (!sched_stream)
    return 0;
  struct montauk_sched_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e) return 0;
  e->type          = TRACE_EVT_SCHED;
  e->op            = SCHED_OP_PREEMPT_TICK;
  e->cpu           = (u32)ctx->cpu;
  e->pid           = ctx->pid;
  e->secondary_pid = -1;
  e->last_cpu      = -1;
  e->sub_idx       = 0;
  e->score         = 0;
  e->runtime_ns    = ctx->runtime_ns;
  e->budget_ns     = ctx->budget_ns;
  e->timestamp_ns  = bpf_ktime_get_ns();
  bpf_ringbuf_submit(e, 0);
  return 0;
}

SEC("tp/sched_decision/preempt_wakeup")
int handle_sched_preempt_wakeup(struct trace_event_raw_sched_preempt_wakeup *ctx) {
  sched_op_bump(SCHED_OP_PREEMPT_WAKEUP);
  if (!sched_stream)
    return 0;
  struct montauk_sched_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e) return 0;
  e->type          = TRACE_EVT_SCHED;
  e->op            = SCHED_OP_PREEMPT_WAKEUP;
  e->cpu           = (u32)ctx->cpu;
  e->pid           = ctx->wakee;
  e->secondary_pid = ctx->waker;
  e->last_cpu      = -1;
  e->sub_idx       = 0;
  e->score         = 0;
  e->runtime_ns    = 0;
  e->budget_ns     = 0;
  e->timestamp_ns  = bpf_ktime_get_ns();
  bpf_ringbuf_submit(e, 0);
  return 0;
}

// Structural-reclassification gate. Fires each time an adaptive scheduler
// re-evaluates its discrete workload classification. Low rate (a periodic gate
// tick, not the dispatch hot path), so it streams unconditionally under
// sched_stream. score carries the current field signature, runtime_ns the prior,
// sub_idx the changed bit -- the field-persist report reads whether the signature
// ever moves or is pinned for the whole capture.
SEC("tp/sched_decision/field_gate")
int handle_sched_field_gate(struct trace_event_raw_sched_field_gate *ctx) {
  sched_op_bump(SCHED_OP_FIELD_GATE);
  if (!sched_stream)
    return 0;
  struct montauk_sched_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e) return 0;
  e->type          = TRACE_EVT_SCHED;
  e->op            = SCHED_OP_FIELD_GATE;
  e->cpu           = (u32)ctx->cpu;
  e->pid           = -1;
  e->secondary_pid = -1;
  e->last_cpu      = -1;
  e->sub_idx       = ctx->changed ? 1u : 0u;
  e->score         = ctx->signature;
  e->runtime_ns    = ctx->prev;
  e->budget_ns     = 0;
  e->timestamp_ns  = bpf_ktime_get_ns();
  bpf_ringbuf_submit(e, 0);
  return 0;
}

// Thread enrollment via task iterator. The reactive sys_enter path only learns
// a thread on its FIRST syscall; a process that spawns a burst of threads can
// outrun that and leave most of them untracked. This iterator sweeps every task
// and enrolls each thread whose process is tracked into thread_map, so coverage
// is COMPLETE regardless of how fast threads appear. Driven from userspace each
// scan; scoped purely by proc_map membership -- fully process-agnostic, no /proc.
SEC("iter/task")
int enroll_threads(struct bpf_iter__task *ctx) {
  struct task_struct *task = ctx->task;
  if (!task)
    return 0;

  u32 tgid = BPF_CORE_READ(task, tgid);
  if (!is_tracked(tgid))
    return 0;

  u32 tid = BPF_CORE_READ(task, pid);   // kernel 'pid' field = thread id
  if (bpf_map_lookup_elem(&thread_map, &tid))
    return 0;                            // already enrolled

  struct thread_bpf_state ts = {};
  ts.pid        = tgid;
  ts.tid        = tid;
  ts.syscall_nr = -1;                    // unknown until first syscall
  ts.state      = 0;                     // R; sched_switch refines
  ts.io_fd      = -1;
  BPF_CORE_READ_STR_INTO(&ts.comm, task, comm);
  bpf_map_update_elem(&thread_map, &tid, &ts, BPF_ANY);
  return 0;
}

// HEAP UPROBES — libc malloc/free/realloc/calloc
// Attached at runtime by BpfTraceCollector to /usr/lib/libc.so.6 symbols.
// Pairs entry (size) with uretprobe (return ptr) via per-thread scratch
// keyed by tid in heap_inflight.
//
// Per-event overhead: ~1 hash map insert + 1 lookup + 1 ringbuf reserve.
// Negligible for non-traced threads (is_tracked() check first).
//
// Why heap visibility matters: glibc's "double free or corruption (!prev)"
// abort happens at a malloc/free call site, but the corrupting WRITE can
// be much earlier. With the full allocation timeline we can:
//   - Identify the chunk address that was reported corrupt (from coredump)
//   - Find the malloc that returned that address (its size + return-IP)
//   - Find any free of the same address (double-free detection)
//   - Find any write to addr+N that crosses chunk boundaries

static __always_inline void emit_heap(u32 op, u64 addr, u64 size, u64 new_addr) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  u32 tid = (u32)pid_tgid;
  if (!is_tracked(pid)) return;
  struct montauk_heap_event *e =
      bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e) return;
  e->type         = TRACE_EVT_HEAP;
  e->pid          = pid;
  e->tid          = tid;
  e->op           = op;
  e->addr         = addr;
  e->size         = size;
  e->new_addr     = new_addr;
  e->timestamp_ns = bpf_ktime_get_ns();
  bpf_get_current_comm(e->comm, sizeof(e->comm));
  bpf_ringbuf_submit(e, 0);
}

// Caller-stack companion to emit_heap, gated on the .rodata size filter.
static __always_inline void emit_heapstack(void *ctx, u32 op, u64 addr, u64 size) {
  if (!heap_stack_size || size != heap_stack_size) return;
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  if (!is_tracked(pid)) return;
  struct montauk_heapstack_event *e =
      bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e) return;
  e->type         = TRACE_EVT_HEAPSTACK;
  e->pid          = pid;
  e->tid          = (u32)pid_tgid;
  e->op           = op;
  e->addr         = addr;
  e->size         = size;
  e->_pad         = 0;
  e->timestamp_ns = bpf_ktime_get_ns();
  bpf_get_current_comm(e->comm, sizeof(e->comm));
  long stack_bytes = bpf_get_stack(ctx, e->stack_user, sizeof(e->stack_user),
                                   BPF_F_USER_STACK);
  e->stack_depth = stack_bytes > 0 ? (u32)(stack_bytes / sizeof(__u64)) : 0;
  bpf_ringbuf_submit(e, 0);
}

SEC("uprobe")
int BPF_KPROBE(uprobe_malloc, size_t size) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  if (!is_tracked(pid)) return 0;
  u32 tid = (u32)pid_tgid;
  struct heap_scratch s = { .size = size, .old_addr = 0, .op = HEAP_OP_MALLOC };
  bpf_map_update_elem(&heap_inflight, &tid, &s, BPF_ANY);
  return 0;
}

SEC("uretprobe")
int BPF_KRETPROBE(uretprobe_malloc, void *ret) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 tid = (u32)pid_tgid;
  struct heap_scratch *s = bpf_map_lookup_elem(&heap_inflight, &tid);
  if (!s) return 0;
  emit_heap(HEAP_OP_MALLOC, (u64)ret, s->size, 0);
  emit_heapstack(ctx, HEAP_OP_MALLOC, (u64)ret, s->size);
  bpf_map_delete_elem(&heap_inflight, &tid);
  bpf_map_delete_elem(&free_echo_guard, &tid);
  return 0;
}

SEC("uprobe")
int BPF_KPROBE(uprobe_free, void *ptr) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  if (!is_tracked(pid)) return 0;
  u32 tid = (u32)pid_tgid;
  u64 now = bpf_ktime_get_ns();
  struct free_echo *last = bpf_map_lookup_elem(&free_echo_guard, &tid);
  if (last && last->ptr == (u64)ptr && now - last->ts <= FREE_ECHO_WINDOW_NS)
    return 0;  /* duplicate probe delivery of the free just emitted */
  struct free_echo cur = { .ptr = (u64)ptr, .ts = now };
  bpf_map_update_elem(&free_echo_guard, &tid, &cur, BPF_ANY);
  /* free has no return value worth recording — emit at entry directly. */
  emit_heap(HEAP_OP_FREE, (u64)ptr, 0, 0);
  return 0;
}

SEC("uprobe")
int BPF_KPROBE(uprobe_realloc, void *old_ptr, size_t size) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  if (!is_tracked(pid)) return 0;
  u32 tid = (u32)pid_tgid;
  struct heap_scratch s = { .size = size, .old_addr = (u64)old_ptr,
                            .op = HEAP_OP_REALLOC };
  bpf_map_update_elem(&heap_inflight, &tid, &s, BPF_ANY);
  return 0;
}

SEC("uretprobe")
int BPF_KRETPROBE(uretprobe_realloc, void *ret) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 tid = (u32)pid_tgid;
  struct heap_scratch *s = bpf_map_lookup_elem(&heap_inflight, &tid);
  if (!s) return 0;
  /* addr = old pointer (input), new_addr = return value, size = requested */
  emit_heap(HEAP_OP_REALLOC, s->old_addr, s->size, (u64)ret);
  bpf_map_delete_elem(&heap_inflight, &tid);
  bpf_map_delete_elem(&free_echo_guard, &tid);
  return 0;
}

SEC("uprobe")
int BPF_KPROBE(uprobe_calloc, size_t nmemb, size_t size) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  if (!is_tracked(pid)) return 0;
  u32 tid = (u32)pid_tgid;
  struct heap_scratch s = { .size = nmemb * size, .old_addr = 0,
                            .op = HEAP_OP_CALLOC };
  bpf_map_update_elem(&heap_inflight, &tid, &s, BPF_ANY);
  return 0;
}

SEC("uretprobe")
int BPF_KRETPROBE(uretprobe_calloc, void *ret) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 tid = (u32)pid_tgid;
  struct heap_scratch *s = bpf_map_lookup_elem(&heap_inflight, &tid);
  if (!s) return 0;
  emit_heap(HEAP_OP_CALLOC, (u64)ret, s->size, 0);
  emit_heapstack(ctx, HEAP_OP_CALLOC, (u64)ret, s->size);
  bpf_map_delete_elem(&heap_inflight, &tid);
  bpf_map_delete_elem(&free_echo_guard, &tid);
  return 0;
}

// ABORT-PATH UPROBES — libc __assert_fail / __libc_message / abort
// Attached at runtime by BpfTraceCollector to libc, same best-effort path as
// the heap uprobes. glibc prints its fatal diagnostics (assert text, "double
// free or corruption", fortify/stack-smash reports via __libc_message) to the
// dying process's stderr and then raises SIGABRT. The SIGNAL event already
// records the death; these record WHY — the abort text and the caller stack
// at the abort call site, before SEH/signal handling can smear it.
// __libc_message is internal and may not resolve on a stripped libc; abort()
// still fires for that path (malloc_printerr → __libc_message → abort) and
// carries the caller stack.

static __always_inline void emit_abort(void *ctx, u32 func, u32 line,
                                       const char *msg, const char *loc) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  if (!is_tracked(pid)) return;
  struct montauk_abort_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e) return;
  e->type         = TRACE_EVT_ABORT;
  e->pid          = pid;
  e->tid          = (u32)pid_tgid;
  e->func         = func;
  e->line         = line;
  e->timestamp_ns = bpf_ktime_get_ns();
  bpf_get_current_comm(e->comm, sizeof(e->comm));
  e->msg[0] = 0;
  e->loc[0] = 0;
  if (msg) bpf_probe_read_user_str(e->msg, sizeof(e->msg), msg);
  if (loc) bpf_probe_read_user_str(e->loc, sizeof(e->loc), loc);
  long stack_bytes = bpf_get_stack(ctx, e->stack_user, sizeof(e->stack_user),
                                   BPF_F_USER_STACK);
  e->stack_depth = stack_bytes > 0 ? (u32)(stack_bytes / sizeof(__u64)) : 0;
  bpf_ringbuf_submit(e, 0);
}

SEC("uprobe")
int BPF_KPROBE(uprobe_assert_fail, const char *assertion, const char *file,
               unsigned int line) {
  emit_abort(ctx, ABORT_FN_ASSERT_FAIL, line, assertion, file);
  return 0;
}

// __libc_message(fmt, ...): glibc's fatal-error printer (malloc_printerr,
// __fortify_fail, ...). Callers pass the human-readable text as the first
// vararg of a "%s\n"-style fmt — capture both fmt and that first vararg.
SEC("uprobe")
int BPF_KPROBE(uprobe_libc_message, const char *fmt, const char *arg1) {
  emit_abort(ctx, ABORT_FN_LIBC_MESSAGE, 0, arg1, fmt);
  return 0;
}

SEC("uprobe")
int BPF_KPROBE(uprobe_abort) {
  emit_abort(ctx, ABORT_FN_ABORT, 0, NULL, NULL);
  return 0;
}

// Keyed-event uprobes on ntdll.so. Critical sections (loader_section, etc.)
// block/wake here with the CRITICAL_SECTION address as arg1 ("key"):
//   NtWaitForKeyedEvent(HANDLE handle, const void *key, BOOLEAN, const LARGE_INTEGER*)
//   NtReleaseKeyedEvent(HANDLE handle, const void *key, BOOLEAN, const LARGE_INTEGER*)
// Capturing the key reveals who waits on / releases each lock by identity.
SEC("uprobe")
int BPF_KPROBE(uprobe_keyed_wait, void *handle, void *key) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;
  if (!is_tracked(pid)) return 0;
  emit_keyedevt(KEVT_WAIT, (u64)key);
  return 0;
}

SEC("uprobe")
int BPF_KPROBE(uprobe_keyed_release, void *handle, void *key) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;
  if (!is_tracked(pid)) return 0;
  emit_keyedevt(KEVT_RELEASE, (u64)key);
  return 0;
}

// Wait-site uprobes, attached to an operator-named function pair (default
// Wine's NtWaitForSingleObject/NtWaitForMultipleObjects -- see
// MONTAUK_WAITSTACK_FUNC1/2 in BpfTraceCollector.cpp). These sit ABOVE the raw
// syscall-enter in the call stack, so bpf_get_stack here can reach a caller
// that the syscall-leaf WAITSTACK in handle_sys_enter resolves only to the
// libc wrapper. Gated to INFINITE waits (NULL timeout pointer = the hooked
// function's "no timeout" convention) to bound volume to the hang-prone class,
// same intent as the syscall-enter path.
// Raw stack + registers for the offline scan. bpf_get_stack's frame-pointer walk
// is useless on frame-pointer-less code (no FP -- it returns frame 0 then
// garbage), so instead we capture RIP + a slice of the stack at RSP and let
// the analyzer resolve each stack word against the maps sidecar to name the
// caller.
static __always_inline void emit_wait_rawstack(void *ctx, u64 obj) {
  u64 pt = bpf_get_current_pid_tgid();
  u32 pid = pt >> 32;
  if (!is_tracked(pid)) return;
  struct pt_regs *regs = (struct pt_regs *)ctx;
  struct montauk_rawstack_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e) return;
  e->type = TRACE_EVT_RAWSTACK;
  e->pid = pid;
  e->tid = (u32)pt;
  e->rip = PT_REGS_IP(regs);
  e->rsp = PT_REGS_SP(regs);
  e->rbp = PT_REGS_FP(regs);
  e->obj_ptr = obj;
  long n = bpf_probe_read_user(e->stack, TRACE_RAWSTACK_BYTES, (void *)e->rsp);
  e->stack_len = (n == 0) ? TRACE_RAWSTACK_BYTES : 0;
  bpf_get_current_comm(e->comm, sizeof(e->comm));
  e->timestamp_ns = bpf_ktime_get_ns();
  bpf_ringbuf_submit(e, 0);
}

// NtWaitForSingleObject(HANDLE, BOOLEAN alertable, PLARGE_INTEGER timeout)
SEC("uprobe")
int BPF_KPROBE(uprobe_wait_single, void *handle, u64 alertable, void *timeout) {
  if (timeout) return 0; // NULL timeout = infinite
  emit_wait_rawstack(ctx, (u64)handle);
  return 0;
}

// NtWaitForMultipleObjects(ULONG count, const HANDLE *handles,
//                          OBJECT_WAIT_TYPE, BOOLEAN alertable, PLARGE_INTEGER timeout)
SEC("uprobe")
int BPF_KPROBE(uprobe_wait_multiple, u64 count, void *handles, u64 wtype,
               u64 alertable, void *timeout) {
  if (timeout) return 0; // NULL timeout = infinite
  emit_wait_rawstack(ctx, 0);
  return 0;
}
