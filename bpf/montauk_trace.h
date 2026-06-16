// montauk trace: shared types between BPF (C) and userspace (C++)
// All structures must be identical on both sides.

#ifndef MONTAUK_TRACE_BPF_H
#define MONTAUK_TRACE_BPF_H

// When included from C++ userspace, use Linux kernel types
#ifndef __BPF__
#include <linux/types.h>
#endif

// Max tracked processes and threads in BPF maps
#define TRACE_MAX_PIDS      256
#define TRACE_MAX_THREADS   2048  // fork-storm bench (e.g. hackbench -g 24) spawns ~960 threads + churn
#define TRACE_MAX_FDS       4096
#define TRACE_MAX_DISCOVERY 4096  // discovery map: all processes seen by sys_enter
#define TRACE_PATTERN_MAX   32   // max pattern length for BPF-side matching
#define TRACE_MAX_CPUS      256   // cpu_ccx map size; logical-CPU index space

// BPF-side pattern for immediate exec matching (no userspace roundtrip).
// Userspace writes this once at startup. BPF reads it on every exec.
struct trace_pattern {
  char  pattern[TRACE_PATTERN_MAX]; // lowercase search pattern
  __u8  len;                        // actual length (0 = disabled)
};

// Discovery entry: lightweight pid→comm for pattern matching
struct discovery_entry {
  __u32 pid;
  char  comm[16];
};

// Ring buffer event types
enum montauk_event_type {
  TRACE_EVT_FORK        = 1,
  TRACE_EVT_EXEC        = 2,
  TRACE_EVT_EXIT        = 3,
  TRACE_EVT_COMM_CHANGE = 4,
  TRACE_EVT_IO          = 5,
  TRACE_EVT_NTSYNC      = 6,
  TRACE_EVT_SCHED       = 7,
  TRACE_EVT_HEAP        = 8,  // libc malloc/free/realloc/calloc uprobes
  TRACE_EVT_SIGNAL      = 9,  // tp/signal/signal_deliver + abnormal exit stacks
  TRACE_EVT_MMAP        = 10, // file-backed mmap (anon mappings filtered out)
  TRACE_EVT_PROVIDER    = 11, // userspace-appended provider snapshot (never emitted by BPF)
  TRACE_EVT_ABORT       = 12, // libc abort-path uprobes (__assert_fail/__libc_message/abort)
  TRACE_EVT_HEAPSTACK   = 13, // caller stack for size-filtered malloc/calloc (MONTAUK_HEAP_STACK_SIZE)
  TRACE_EVT_KEYEDEVT    = 14, // ntdll keyed-event uprobes (critical-section wait/release; key = CS addr)
};

// Provider snapshot record (userspace-appended to the binary trace log;
// BPF never emits this type). The fixed header below is followed by
// payload_len bytes of the provider's raw Prometheus text within the same
// length-prefixed record.
struct montauk_provider_event {
  __u32 type;          // TRACE_EVT_PROVIDER
  __u32 _pad0;
  __u64 timestamp_ns;  // CLOCK_MONOTONIC at scrape, same base as BPF events
  char  name[32];      // provider runtime name, NUL-padded
  __u32 payload_len;   // bytes of Prometheus text following this struct
  __u32 _pad1;
};

// File-backed mmap event. Captures fd, length, prot, flags, offset, return
// address for every file-backed mmap. Anonymous mappings are filtered out
// at BPF (flags & MAP_ANONYMOUS) so the trace stays scoped to file I/O.
// This is the only path that surfaces mmap'd asset access — Unity bundles,
// shared libraries, etc. don't show in pread/read traces when the game
// uses MapViewOfFile.
struct montauk_mmap_event {
  __u32 type;          // TRACE_EVT_MMAP
  __u32 pid;
  __u32 tid;
  __s32 fd;            // file fd; anon mappings are filtered before emit
  __u64 addr;          // return value from mmap
  __u64 length;        // arg1
  __u64 offset;        // arg5 — file offset of mapping
  __u32 prot;          // arg2 (PROT_READ=1, PROT_WRITE=2, PROT_EXEC=4)
  __u32 flags;         // arg3 (MAP_SHARED=1, MAP_PRIVATE=2, MAP_FIXED=0x10, MAP_ANONYMOUS=0x20)
  __u64 timestamp_ns;
  char  comm[16];
};

// Per-CPU scratch for mmap arg passing (sys_enter -> sys_exit).
struct mmap_scratch {
  __s32 fd;
  __u32 prot;
  __u32 flags;
  __u32 _pad0;
  __u64 length;
  __u64 offset;
};

// Signal event subtype — distinguishes "signal delivered to running thread"
// (fatal-signal capture, with stack snapshot) from "abnormal exit captured
// when sched_process_exit fires with non-zero exit code" (postmortem stack).
enum signal_event_kind {
  SIGEVT_DELIVER    = 0,  // tp/signal/signal_deliver — synchronous capture
  SIGEVT_EXIT_ABNL  = 1,  // sched_process_exit, exit_code != 0 — postmortem
};

// Max stack frames captured via bpf_get_stack. 32 is generous for typical
// crashes (Wine SEH dispatcher + game stack rarely exceed 16); the verifier
// limits us to ~127 anyway, but allocating 32 * 8 = 256 bytes per event
// keeps ringbuf pressure manageable.
#define TRACE_STACK_MAX_FRAMES 32

struct montauk_signal_event {
  __u32 type;                            // TRACE_EVT_SIGNAL
  __u32 pid;
  __u32 tid;
  __u32 kind;                            // signal_event_kind
  __s32 signal_nr;                       // SIGSEGV=11, SIGABRT=6, SIGBUS=7, SIGILL=4, SIGTRAP=5, SIGKILL=9, etc.
                                         //   For SIGEVT_EXIT_ABNL: low 7 bits of task->exit_code (0 = clean exit reached)
  __s32 sender_pid;                      // tp/signal/signal_generate: who sent it (0 = kernel/self/unknown)
  __s32 exit_code;                       // SIGEVT_EXIT_ABNL: full exit_code from task_struct; else 0
  __u32 stack_depth;                     // number of valid frames in stack_user[]
  __u64 stack_user[TRACE_STACK_MAX_FRAMES]; // user-mode IPs, frame 0 = innermost
  __u64 timestamp_ns;
  char  comm[16];
  // Per-thread state at the moment of the signal — looked up from
  // thread_map by tid. Answers "what syscall was this thread executing
  // when it got killed?" without WINEDEBUG. Critical for crashes whose
  // stack capture is shallow (frame pointer omitted, DWARF unwind fails).
  __s32 syscall_nr;                      // -1 = not in syscall; else syscall number
  __s32 io_fd;                           // last I/O syscall's fd (-1 = none)
  __u64 syscall_arg0;                    // first syscall arg at signal time
  __u64 syscall_arg1;                    // second syscall arg
};

// Abort-path function identifiers (subtype of TRACE_EVT_ABORT).
enum abort_fn {
  ABORT_FN_ASSERT_FAIL  = 0,  // __assert_fail(assertion, file, line, function)
  ABORT_FN_LIBC_MESSAGE = 1,  // __libc_message(fmt, ...) — glibc fatal-error printer
  ABORT_FN_ABORT        = 2,  // abort()
};

#define TRACE_ABORT_MSG_MAX 128

// Abort-path event. glibc prints its fatal diagnostics ("double free or
// corruption", assert text, fortify/stack-smash reports) to the dying
// process's stderr and then raises SIGABRT. The SIGNAL event records the
// death; this records WHY: the abort text and the caller stack captured at
// the abort call site itself, before the SEH/signal machinery runs.
struct montauk_abort_event {
  __u32 type;          // TRACE_EVT_ABORT
  __u32 pid;
  __u32 tid;
  __u32 func;          // abort_fn
  __u32 line;          // __assert_fail only; else 0
  __u32 stack_depth;   // number of valid frames in stack_user[]
  __u64 stack_user[TRACE_STACK_MAX_FRAMES]; // user-mode IPs, frame 0 = innermost
  __u64 timestamp_ns;
  char  comm[16];
  char  msg[TRACE_ABORT_MSG_MAX]; // assert: assertion expr; libc_message: first vararg ("%s" payload)
  char  loc[TRACE_ABORT_MSG_MAX]; // assert: source file; libc_message: fmt string
};

// Heap-allocation caller-stack event. Emitted ALONGSIDE the regular
// TRACE_EVT_HEAP record when the requested size equals the filter the
// collector loaded into .rodata from MONTAUK_HEAP_STACK_SIZE (0 = off).
// Purpose: the glibc top-chunk/!prev corruption class presents as a linear
// overrun of one specific allocation size; the caller stack of that
// allocation names the owning code path without a debugger attached.
struct montauk_heapstack_event {
  __u32 type;          // TRACE_EVT_HEAPSTACK
  __u32 pid;
  __u32 tid;
  __u32 op;            // heap_op (HEAP_OP_MALLOC or HEAP_OP_CALLOC)
  __u64 addr;          // return value of the allocation
  __u64 size;          // requested size (== the .rodata filter)
  __u32 stack_depth;   // number of valid frames in stack_user[]
  __u32 _pad;
  __u64 stack_user[TRACE_STACK_MAX_FRAMES]; // user-mode IPs, frame 0 = innermost
  __u64 timestamp_ns;
  char  comm[16];
};

// Keyed-event uprobe record. Wine critical sections (including loader_section)
// wait/wake via NtWaitForKeyedEvent/NtReleaseKeyedEvent in ntdll.so, passing
// the CRITICAL_SECTION address as the "key". Capturing that key makes critical
// sections traceable by lock identity — the layer futex/ntsync capture misses.
enum keyedevt_op {
  KEVT_WAIT    = 0,  // NtWaitForKeyedEvent  — a thread blocks entering the CS
  KEVT_RELEASE = 1,  // NtReleaseKeyedEvent  — the owner leaves and wakes a waiter
};
struct montauk_keyedevt_event {
  __u32 type;          // TRACE_EVT_KEYEDEVT
  __u32 pid;
  __u32 tid;
  __u32 op;            // keyedevt_op
  __u64 key;           // CRITICAL_SECTION address (NtWaitForKeyedEvent arg1)
  __u64 timestamp_ns;
  char  comm[16];
};

// Heap operation types (subtype of TRACE_EVT_HEAP).
// Captured via uprobes on libc.so.6 — gives per-allocation visibility that
// the syscall-level trace can't (libc's arena allocator services most
// malloc calls without touching the kernel).
enum heap_op {
  HEAP_OP_MALLOC  = 0,
  HEAP_OP_FREE    = 1,
  HEAP_OP_REALLOC = 2,
  HEAP_OP_CALLOC  = 3,
};

struct montauk_heap_event {
  __u32 type;          // TRACE_EVT_HEAP
  __u32 pid;
  __u32 tid;
  __u32 op;            // heap_op
  __u64 addr;          // malloc/calloc: return value; free/realloc: input pointer
  __u64 size;          // requested size (free: 0)
  __u64 new_addr;      // realloc: new pointer (else 0)
  __u64 timestamp_ns;  // ktime_get_ns
  char  comm[16];
};

// Scheduler-decision tracepoint events. Op identifies which decision point
// fired. These decision tracepoints are attached at RUNTIME to whatever the
// active scheduler exposes (the category:name pairs come from config, see
// BpfTraceCollector) -- montauk binds by the generic role below and names no
// scheduler in source. The field layout here is the generic decision-event
// contract a scheduler emits to.
enum sched_trace_op {
  SCHED_OP_ENQUEUE        = 1,
  SCHED_OP_PICK           = 2,
  SCHED_OP_PICK_EMPTY     = 3,
  SCHED_OP_PREEMPT_TICK   = 4,
  SCHED_OP_PREEMPT_WAKEUP = 5,
  SCHED_OP_WAKEUP         = 6,  // generic kernel tp/sched/sched_wakeup: woken pid + target_cpu
  SCHED_OP_WAKE2RUN       = 7,  // wake-to-run (runqueue) latency: pid=wakee, cpu=run CPU,
                                //   runtime_ns=delta ns (became-runnable -> ran), sub_idx=cross_ccx(0|1)
  SCHED_OP_CPU_IDLE       = 8,  // per-CPU idle boundary (pid 0 in/out of sched_switch),
                                //   cpu=CPU, sub_idx=1 entering idle / 0 leaving idle. Emitted
                                //   UNCONDITIONALLY (not gated to the traced comm group) so the
                                //   analyzer can reconstruct exact per-CPU occupancy at any instant.
};

// Per-CPU aggregation of scheduler-decision counts, indexed by sched_trace_op.
// The decision tracepoints fire on the dispatch hot path; counting per-CPU
// (one bump, no shared ringbuf reserve) keeps tracing near-zero-overhead there.
// Userspace sums across CPUs at snapshot time. Per-event streaming is opt-in
// (binary --trace-out only); the contract struct above is the streamed form.
#define MONTAUK_SCHED_OP_MAX 9   /* index by sched_trace_op (1..8); 0 unused */
struct sched_op_counters {
  __u64 op[MONTAUK_SCHED_OP_MAX];
};

// Per-CPU migration classification counters. The sched_switch hot path bumps
// these on every cross-core move of a traced thread, classified by whether the
// source and destination CPUs share an L3/CCX domain (looked up in cpu_ccx).
// Userspace sums across CPUs at snapshot time. These globals survive traced-
// thread churn: a fork-storm exits ~1000 short-lived threads whose per-thread
// thread_bpf_state.migrations counts evaporate from thread_map; these do not.
struct mig_ccx_counters {
  __u64 intra;    // src and dst CPUs in the same CCX (shared L3)
  __u64 cross;    // src and dst in different CCX domains (Infinity-Fabric c2c)
  __u64 unknown;  // a CPU index outside cpu_ccx (topology not pushed / out of range)
};

struct montauk_sched_event {
  __u32 type;           // TRACE_EVT_SCHED
  __u32 op;             // sched_trace_op
  __u32 cpu;
  __s32 pid;            // primary pid (enqueue/pick/preempt_tick: target; wakeup: wakee)
  __s32 secondary_pid;  // wakeup waker; preempt_tick & pick: -1
  __s32 last_cpu;       // enqueue only; else -1
  __u32 sub_idx;        // enqueue only; else 0
  __u64 score;          // enqueue/pick; else 0
  __u64 runtime_ns;     // preempt_tick only
  __u64 budget_ns;      // preempt_tick only
  __u64 timestamp_ns;
};

// ntsync operation types (mapped from ioctl nr 0x80-0x8D)
enum ntsync_trace_op {
  NTS_CREATE_SEM    = 0,
  NTS_SEM_RELEASE   = 1,
  NTS_WAIT_ANY      = 2,
  NTS_WAIT_ALL      = 3,
  NTS_CREATE_MUTEX  = 4,
  NTS_MUTEX_UNLOCK  = 5,
  NTS_MUTEX_KILL    = 6,
  NTS_CREATE_EVENT  = 7,
  NTS_EVENT_SET     = 8,
  NTS_EVENT_RESET   = 9,
  NTS_EVENT_PULSE   = 10,
  NTS_SEM_READ      = 11,
  NTS_MUTEX_READ    = 12,
  NTS_EVENT_READ    = 13,
};

// ntsync ring buffer event: emitted on every ntsync ioctl exit
// for tracked processes. Captures create, signal, and wait operations.
#define NTSYNC_MAX_WAIT_FDS 8

struct montauk_ntsync_event {
  __u32 type;              // TRACE_EVT_NTSYNC
  __u32 pid;
  __u32 tid;
  __u8  op;                // ntsync_trace_op
  __u8  _pad0[3];
  __s32 fd;                // ioctl fd (device fd for create/wait, object fd for signal)
  __s64 result;            // ioctl return value
  __u64 timestamp_ns;      // ktime_get_ns() at completion
  __u32 arg0;              // create: param0 / signal: prev_state
  __u32 arg1;              // create: param1
  __u64 timeout_ns;        // wait: timeout from ntsync_wait_args
  __u32 wait_count;        // wait: number of objects
  __u32 wait_index;        // wait: OUT — which object signaled (count = alert)
  __u32 wait_owner;        // wait: thread ID for mutex acquisition
  __u32 wait_alert;        // wait: alert event fd
  __u32 wait_fds[NTSYNC_MAX_WAIT_FDS]; // wait: first 8 object fds
  __u64 obj_ptr;           // create/signal: kernel ntsync object pointer (file->private_data)
  __u64 wait_objs[NTSYNC_MAX_WAIT_FDS]; // wait: per-fd kernel object pointer (SCM_RIGHTS-stable identity)
  char  comm[16];
};

// Per-CPU scratch for ioctl ntsync enter → exit state passing
struct ntsync_scratch {
  __u32 pid;
  __u8  op;                // ntsync_trace_op
  __u8  _pad0[3];
  __s32 fd;
  __u64 arg_ptr;           // userspace pointer to ioctl arg struct
  __u32 arg0;
  __u32 arg1;
  __u64 timeout_ns;
  __u32 wait_count;
  __u32 wait_owner;
  __u32 wait_alert;
  __u32 wait_fds[NTSYNC_MAX_WAIT_FDS];
};

// Ring buffer event (kernel → userspace)
struct montauk_ring_event {
  __u32 type;
  __u32 pid;
  __u32 ppid;
  __u32 child_pid;
  char  comm[16];
  char  filename[64];  // exec'd filename from tracepoint (not /proc)
};

// I/O ring event: emitted on every read/write/lseek/pread64/fstat exit
// for tracked processes. Carries full syscall details for event-level tracing.
struct montauk_io_event {
  __u32 type;       // TRACE_EVT_IO
  __u32 pid;
  __u32 tid;
  __s32 syscall_nr; // syscall number (0=read, 1=write, 8=lseek, 5=fstat, 17=pread64)
  __s32 fd;
  __s64 result;     // return value (bytes read/written, new offset, or -errno)
  __u64 count;      // read/write: byte count; lseek: offset arg
  __u32 whence;     // lseek whence (0=SET, 1=CUR, 2=END)
  char  comm[16];
  __u64 timestamp_ns;  // CLOCK_MONOTONIC (bpf_ktime_get_ns); lets the decoder
                       // reconstruct elapsed/wall like montauk_sched_event
};

// Per-thread state (BPF map value, read by userspace)
struct thread_bpf_state {
  __u32 pid;
  __u32 tid;
  __u8  state;        // 0=R, 1=S, 2=D, 3=T, 4=Z
  __s32 syscall_nr;   // -1 = running (not in syscall)
  __u64 syscall_arg0; // first arg (ioctl cmd, futex op, fd, etc.)
  __u64 syscall_arg1; // second arg (futex addr, ioctl arg, etc.)
  __u64 runtime_ns;   // accumulated on-CPU time
  __u64 enter_ns;     // timestamp of last sched-in (for delta)
  __u64 wake_ns;      // became-runnable timestamp pending a run (0 = none); drained at
                      //   sched-in to emit wake-to-run latency. Set on sched_wakeup and
                      //   on involuntary preempt (prev still runnable) for runqueue-wait.
  char  comm[16];

  // File I/O tracking: captures last I/O syscall details per thread
  __s32 io_fd;            // fd involved in last I/O syscall (-1 = none)
  __u64 io_count;         // read/write: byte count; lseek: offset argument
  __u32 io_whence;        // lseek whence (0=SET, 1=CUR, 2=END)
  __s64 io_result;        // return value (bytes read/written, new offset, or -errno)
  __u64 io_timestamp_ns;  // ktime_get_ns() when I/O completed

  // On-CPU placement / migration (fork-storm shape: ping-pong vs stable)
  __s32 cur_cpu;          // CPU last seen on-CPU (-1 = never scheduled yet)
  __u64 migrations;       // count of cross-CPU moves (on-CPU core changes)
};

// Per-PID process info (BPF map value)
// Lifecycle fields updated by sched tracepoints — no ring buffer needed.
// Userspace reads periodically (same as thread_map).
struct proc_bpf_info {
  __u32 pid;
  __u32 ppid;
  __u8  tracked;      // 1 = in traced group
  __u8  is_root;      // 1 = matched pattern directly
  __u8  exited;       // 1 = process has exited
  __u8  _pad0;
  __s32 exit_code;    // exit status (from sched_process_exit)
  __u64 fork_ts;      // ktime_get_ns() at fork
  __u64 exec_ts;      // ktime_get_ns() at exec (0 = no exec)
  __u64 exit_ts;      // ktime_get_ns() at exit (0 = still alive)
  char  comm[16];
  char  exec_file[64]; // binary path from execve (truncated)
};

// Per-PID fd entry (BPF map value)
struct fd_bpf_entry {
  __u32 pid;
  __s32 fd_num;
  __u8  type;         // 0=file, 1=pipe, 2=socket, 3=device, 4=eventfd, 5=anon_inode
  char  target[64];   // best-effort name from openat filename or type string
};

// fd_table key: composite pid+fd
struct fd_key {
  __u32 pid;
  __s32 fd;
};

#endif // MONTAUK_TRACE_BPF_H
