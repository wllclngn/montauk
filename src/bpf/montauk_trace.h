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
#define TRACE_MAX_CPUS      256   // cpu_cache_domain map size; logical-CPU index space
#define MONTAUK_DROP_SLOTS  25    // drop-counter slots, indexed by event type
                                  // (slot 0 = out-of-range catchall); one past
                                  // the enum's top value. It sizes the DROPS
                                  // record, so a reader takes the slot count
                                  // from the record's length: A capture written
                                  // with fewer slots still reads

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
  TRACE_EVT_MMAP        = 10, // file-backed mmap, and anonymous mappings made executable (other anon mappings filtered out)
  TRACE_EVT_PROVIDER    = 11, // userspace-appended provider snapshot (never emitted by BPF)
  TRACE_EVT_ABORT       = 12, // libc abort-path uprobes (__assert_fail/abort)
  TRACE_EVT_HEAPSTACK   = 13, // caller stack for size-filtered malloc/calloc (MONTAUK_HEAP_STACK_SIZE)
  TRACE_EVT_KEYEDEVT    = 14, // ntdll keyed-event uprobes (critical-section wait/release; key = CS addr)
  TRACE_EVT_KSTRAND     = 15, // per-CPU kernel-thread dispatch strand (became-runnable -> ran latency over threshold)
  TRACE_EVT_WAITSTACK   = 16, // user stack at an INFINITE ntsync wait-enter (names where a parked thread blocks)
  TRACE_EVT_SCX_STORM   = 17, // per-interval sched_ext kick/reenqueue counters (cpu_release storm)
  TRACE_EVT_THREAD_NAME = 18, // tid->comm binding, deduped (one per tid), so the holder ledger can name a CPU-bound task that predates the trace and emits no syscall (montauk_ring_event payload)
  TRACE_EVT_RAWSTACK    = 19, // raw user stack slice + RIP/RSP/RBP at an INFINITE wait-enter, for offline DWARF .eh_frame unwinding (FP-less Wine code)
  TRACE_EVT_DROPS       = 20, // cumulative ring-drop counter snapshot (userspace-appended at drain cadence; BPF never emits this type)
  TRACE_EVT_PATTERN     = 21, // the whole --trace pattern when the header's field cannot hold it (first record; userspace only)
  TRACE_EVT_FUTEX       = 22, // a futex wait a traced thread enters and leaves: its word, expected value and deadline
  TRACE_EVT_FUTEXSTACK  = 23, // user stack at a futex wait-enter with no deadline (names where a parked thread blocks)
  TRACE_EVT_SYSCALL     = 24, // one syscall a traced thread made: number, arguments, result, duration, return address and paths (opt-in class)
};

// Drop-counter snapshot record. Userspace samples the BPF drop_counts map
// each drain tick and appends one of these when any counter moved (plus a
// final one at capture end). Values are FREE-RUNNING CUMULATIVE totals per
// event type, summed across CPUs: snapshots are idempotent, survive losing a
// snapshot record themselves, and let the analyzer bound the loss inside any
// window by differencing the nearest bracketing snapshots. The writer_*
// fields carry the disk path's own accounting (records handed to the disk
// path, records that reached the file buffer, write errors), so a capture
// whose tail was lost to a full disk says so in the bytes that landed.
struct montauk_drop_event {
  __u32 type;                        // TRACE_EVT_DROPS
  __u32 _pad;
  __u64 ts_ns;                       // monotonic, same clock as every record
  __u64 dropped[MONTAUK_DROP_SLOTS]; // cumulative reserve failures per type
  __u64 writer_attempted;            // records handed to the disk path
  __u64 writer_errors;               // failed write() calls on the trace fd
  __u64 writer_lost_bytes;           // bytes dropped when a flush aborted
};

#ifndef __BPF__
// A drop record as this build lays it out, from one written with any slot
// count: The slots the record carries (the rest zero), then the three writer
// counters from its tail. 0 when the record is too short to be one.
static inline int montauk_drop_read(const void *data, __u32 len, struct montauk_drop_event *out) {
  const __u32 head = 16, tail = 3 * sizeof(__u64);
  if (len < head + tail + sizeof(__u64)) return 0;
  __u32 slots = (len - head - tail) / sizeof(__u64);
  if (slots > MONTAUK_DROP_SLOTS) slots = MONTAUK_DROP_SLOTS;
  const unsigned char *p = (const unsigned char *)data;
  __builtin_memset(out, 0, sizeof(*out));
  __builtin_memcpy(out, p, head);
  __builtin_memcpy(out->dropped, p + head, slots * sizeof(__u64));
  __builtin_memcpy((unsigned char *)out + __builtin_offsetof(struct montauk_drop_event, writer_attempted),
                   p + len - tail, tail);
  return 1;
}
#endif

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

// sched_ext kick-storm counters. BPF maintains these per-CPU; the collector reads
// + deltas them each log interval and appends one TRACE_EVT_SCX_STORM sample. Names
// the cpu_release kick-storm -- a REAL IPI storm (preempt-kick dominant) vs IDLE
// re-enqueue churn -- directly from the trace, no scheduler-stdout scrape.
struct scx_storm_counters {
  __u64 kicks;          // scx_bpf_kick_cpu calls
  __u64 preempt_kicks;  // ... of which carried SCX_KICK_PREEMPT (the real IPIs)
  __u64 reenq;          // tasks re-enqueued via scx_bpf_reenqueue_local (return count)
};

struct montauk_scx_storm_event {
  __u32 type;           // TRACE_EVT_SCX_STORM
  __u32 interval_ms;    // wall interval this delta covers (for rate = delta / interval)
  __u64 kicks;          // deltas over the interval, summed across CPUs
  __u64 preempt_kicks;
  __u64 reenq;
  __u64 timestamp_ns;
};

// File-backed mmap event. Captures fd, length, prot, flags, offset, return
// address for every file-backed mmap, and for an anonymous mapping made with
// PROT_EXEC (code mapped by hand, a JIT's). Other anonymous mappings are
// filtered out at BPF so the trace stays scoped to file I/O and code.
// This is the only path that surfaces mmap'd asset access — Unity bundles,
// shared libraries, etc. don't show in pread/read traces when the game
// uses MapViewOfFile.
struct montauk_mmap_event {
  __u32 type;          // TRACE_EVT_MMAP
  __u32 pid;
  __u32 tid;
  __s32 fd;            // file fd; -1 for an anonymous executable mapping (other anon ones are filtered)
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
// crashes (an exception-dispatcher-plus-app stack rarely exceeds 16); the
// verifier limits us to ~127 anyway, but allocating 32 * 8 = 256 bytes per
// event keeps ringbuf pressure manageable.
#define TRACE_STACK_MAX_FRAMES 32

// What a delivery's disposition did. An ignored signal is dropped by the
// kernel when it is generated and never delivered, so its row is stamped at
// generation, in the sender's moment, with no stack.
enum signal_disposition {
  SIGDISP_NONE    = 0,  // an abnormal exit, or a capture older than v8.15.0
  SIGDISP_DEFAULT = 1,  // the default action: termination, a core, or nothing
  SIGDISP_IGNORED = 2,  // SIG_IGN
  SIGDISP_CAUGHT  = 3,  // a handler runs
};

// The bytes of user stack a signal record copies from its stack pointer.
#define TRACE_SIGNAL_STACK_BYTES 4096
// The record's length before it carried its disposition and user context.
#define MONTAUK_SIGNAL_EVENT_V1_SIZE 336

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
  // What the signal's disposition did with it, and the interrupted user
  // context: The registers and the top of the user stack, which --analyze
  // unwinds offline by .eh_frame where frame pointers stop. An older capture's
  // record ends at syscall_arg1 and reads with these zero.
  __u32 disposition;                     // signal_disposition
  __u32 user_stack_len;                  // bytes of user_stack[] read from user_sp (0 = none)
  __u64 user_ip;
  __u64 user_sp;
  __u64 user_bp;
  __u8  user_stack[TRACE_SIGNAL_STACK_BYTES];
};

// Abort-path function identifiers (subtype of TRACE_EVT_ABORT).
enum abort_fn {
  ABORT_FN_ASSERT_FAIL  = 0,  // __assert_fail(assertion, file, line, function)
  ABORT_FN_LIBC_MESSAGE = 1,  // __libc_message(fmt, ...): older captures only
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
  char  msg[TRACE_ABORT_MSG_MAX]; // assert: assertion expr; abort: glibc's __abort_msg text
  char  loc[TRACE_ABORT_MSG_MAX]; // assert: source file
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

// User stack captured at an INFINITE ntsync wait-enter. A thread parked at trace
// end never reaches sys_exit, so its LAST waitstack names WHERE in the code it is
// blocked (resolved against the maps sidecar -> module+offset). Gated to
// infinite-timeout waits to bound volume -- those are exactly the hang-prone
// ones that become dead-producer parks.
struct montauk_waitstack_event {
  __u32 type;          // TRACE_EVT_WAITSTACK
  __u32 pid;
  __u32 tid;
  __u32 stack_depth;   // number of valid frames in stack_user[]
  __u64 obj_ptr;       // first waited object's kernel ptr (0 if none) -- correlates to endstate
  __u64 timeout_ns;    // always infinite here (the gate)
  __u64 stack_user[TRACE_STACK_MAX_FRAMES]; // user-mode IPs, frame 0 = innermost
  __u64 timestamp_ns;
  char  comm[16];
};

// futex_waitv's command in a TRACE_EVT_FUTEX record. No futex op is 127, so the
// low seven bits name it beside the real commands, with FUTEX_PRIVATE_FLAG (128)
// and FUTEX_CLOCK_REALTIME (256) above them as futex(2) carries them: Its first
// waiter's FUTEX2_PRIVATE is the same bit, and its clockid CLOCK_REALTIME sets
// the clock flag.
#define MONTAUK_FUTEX_CMD_WAITV 127

// A futex wait a traced thread enters and leaves, as an enter (result -999) and
// a leave (the call's return) per thread: FUTEX_WAIT, FUTEX_WAIT_BITSET,
// FUTEX_WAIT_REQUEUE_PI, FUTEX_LOCK_PI, FUTEX_LOCK_PI2 and futex_waitv, with the
// word's address, the value the wait expects there and the deadline as the call
// gave it. A thread whose last enter has no leave is parked on that word; a
// restart the kernel makes inside the wait (-ERESTARTSYS and its kin) is no
// leave, since the wait goes on. The futex syscall's io record rides beside it
// for every futex call, waits and wakes alike; this one is the wait's own.
struct montauk_futex_event {
  __u32 type;          // TRACE_EVT_FUTEX
  __u32 pid;
  __u32 tid;
  __u32 op;            // the futex op with its flags; MONTAUK_FUTEX_CMD_WAITV for futex_waitv
  __u64 uaddr;         // the word (futex_waitv: its first waiter's)
  __u64 val;           // the value the wait expects (futex_waitv: its first waiter's)
  __s64 result;        // -999 at enter; the syscall's return at leave
  __u64 timeout_ns;    // the call's timespec in ns, ~0 for none: relative for a
                       // FUTEX_WAIT without FUTEX_CLOCK_REALTIME, absolute otherwise
  __u32 nr_futexes;    // futex_waitv's count of words; 1 otherwise
  __u32 _pad;
  __u64 timestamp_ns;
  char  comm[16];
};

// User stack at a futex wait-enter with no deadline, the futex twin of
// WAITSTACK: A thread parked on a futex at trace end never leaves, so its last
// futexstack names WHERE in the code it is blocked, and uaddr keys it to the
// wait it was taken for. Gated to waits with no deadline, as WAITSTACK is, to
// bound volume.
struct montauk_futexstack_event {
  __u32 type;          // TRACE_EVT_FUTEXSTACK
  __u32 pid;
  __u32 tid;
  __u32 stack_depth;   // number of valid frames in stack_user[]
  __u64 uaddr;         // the word the wait is on
  __u64 stack_user[TRACE_STACK_MAX_FRAMES]; // user-mode IPs, frame 0 = innermost
  __u64 timestamp_ns;
  char  comm[16];
};

// Raw user stack slice + register state at an INFINITE wait-enter, for OFFLINE
// DWARF .eh_frame unwinding. The WAITSTACK bpf_get_stack frame-pointer walk yields
// only frame 0 for Wine/luajit code (no frame pointers), so the analyzer rebuilds
// the call chain from raw bytes + each module's .eh_frame CFI -- which needs the
// registers (RIP/RSP/RBP) and a slice of the stack at and above RSP.
#define TRACE_RAWSTACK_BYTES 1024
struct montauk_rawstack_event {
  __u32 type;          // TRACE_EVT_RAWSTACK
  __u32 pid;
  __u32 tid;
  __u32 stack_len;     // valid bytes captured into stack[] (0 = read failed)
  __u64 rip;           // instruction pointer at the wait (innermost frame PC)
  __u64 rsp;           // stack pointer -- stack[] holds the bytes at [rsp, rsp+stack_len)
  __u64 rbp;           // frame base pointer
  __u64 obj_ptr;       // waited handle/object (0 if none)
  __u64 timestamp_ns;
  __u8  stack[TRACE_RAWSTACK_BYTES];
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
  // The aligned allocators: An aligned request never passes through malloc,
  // and glibc can serve one from a block just freed, so without these a block
  // taken back this way reads as freed twice. Each carries its alignment.
  HEAP_OP_POSIX_MEMALIGN = 4,
  HEAP_OP_ALIGNED_ALLOC  = 5,
  HEAP_OP_MEMALIGN       = 6,
  HEAP_OP_VALLOC         = 7,  // page-aligned
  HEAP_OP_PVALLOC        = 8,  // page-aligned, size rounded up to pages
};

struct montauk_heap_event {
  __u32 type;          // TRACE_EVT_HEAP
  __u32 pid;
  __u32 tid;
  __u32 op;            // heap_op
  __u64 addr;          // malloc/calloc: return value; free/realloc: input pointer
  __u64 size;          // requested size (free: 0)
  union {
    __u64 new_addr;    // realloc: new pointer
    __u64 align;       // the aligned allocators: the alignment asked for
  };
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
                                //   runtime_ns=delta ns (became-runnable -> ran), sub_idx=cross_domain(0|1)
  SCHED_OP_CPU_IDLE       = 8,  // per-CPU idle boundary (pid 0 in/out of sched_switch),
                                //   cpu=CPU, sub_idx=1 entering idle / 0 leaving idle. Emitted
                                //   UNCONDITIONALLY (not gated to the traced comm group) so the
                                //   analyzer can reconstruct exact per-CPU occupancy at any instant.
  SCHED_OP_SWITCH_IN      = 9,  // sched_switch-derived pick: the next task coming on-CPU
                                //   (pid=next tid, cpu=CPU). Emitted UNCONDITIONALLY, like
                                //   CPU_IDLE, but only when no sched_decision/pick tracepoint is
                                //   bound (switch_in_fallback) -- so slice/service derive picks
                                //   from the universal sched_switch for any scheduler (EEVDF, or
                                //   an scx mode that does not export pick). Idle is CPU_IDLE.
  SCHED_OP_FIELD_GATE     = 10, // an adaptive scheduler's structural-reclassification gate --
                                //   fired each time the scheduler re-evaluates its discrete
                                //   workload classification (the "field"). score = current field
                                //   signature (a discrete code/bitmap), runtime_ns = previous
                                //   signature, sub_idx = 1 if the signature CHANGED this tick (the
                                //   gate re-derived) / 0 if it HELD (the gate persisted the prior
                                //   classification), cpu = reporting CPU. The field-persist report
                                //   measures whether the signature moves over the capture (a live
                                //   classifier) or is pinned to one value (a latched classifier
                                //   that cannot distinguish two operating states it committed
                                //   between at start). Generic: any adaptive scheduler with a
                                //   discrete regime/field gate emits to this role.
  SCHED_OP_KICK_ISSUE     = 11, // a kick was issued at a CPU (kfunc scx_bpf_kick_cpu, any sched_ext
                                //   scheduler, any workload -- generic to the framework, not tied to
                                //   one scheduler). cpu=target CPU being kicked, last_cpu=issuing CPU,
                                //   score=kick flags (SCX_KICK_* bitmask), pid=-1. Pair against
                                //   SCHED_OP_RESCHED on the same target cpu within a short window to
                                //   see whether an issued kick actually resulted in a resched, or was
                                //   swallowed (e.g. by the idle-kick skip-check racing a CPU's own
                                //   idle-entry decision).
  SCHED_OP_RESCHED        = 12, // resched_curr() fired for a CPU's runqueue -- the actual mechanism
                                //   that would wake a CPU sitting idle, regardless of what triggered it
                                //   (a kick, preemption, or anything else). cpu=target CPU (rq->cpu),
                                //   last_cpu=CPU executing resched_curr, pid=-1. The absence of a
                                //   RESCHED shortly after a KICK_ISSUE for the same target CPU is the
                                //   direct, generic signature of a swallowed/lost kick.
  SCHED_OP_TICK_STOP      = 13, // a CPU's periodic tick stop was evaluated (kernel tp/timer/tick_stop,
                                //   universal to any NOHZ_FULL-capable kernel, not sched_ext-specific).
                                //   cpu=the CPU evaluating its own tick, sub_idx=success (1 tick
                                //   actually stopped / 0 blocked by a dependency), score=dependency
                                //   bitmask (TICK_DEP_MASK_*, valid only when sub_idx=0), pid=-1.
                                //   Correlate against KICK_ISSUE/RESCHED on the same CPU to see whether
                                //   a CPU went tickless right as a kick targeting it was in flight.
  SCHED_OP_DSQ_INSERT     = 14, // a task was placed into a sched_ext dispatch queue (kfunc
                                //   scx_bpf_dsq_insert / _vtime, any scx scheduler). pid=task,
                                //   cpu=CPU executing the insert, score=the RAW dsq_id.
                                //   The dsq_id is self-describing on every scx scheduler that
                                //   uses per-CPU queues: an id below the CPU count names a
                                //   specific CPU, anything above it is a shared pool. So this
                                //   alone separates a placement that NAMES a destination from
                                //   one that drops the task into a pool for whichever CPU wins
                                //   the drain race -- the two produce migrations for entirely
                                //   different reasons and admit opposite fixes.
  SCHED_OP_DSQ_DRAIN      = 15, // a CPU consumed from a dispatch queue (kfunc
                                //   scx_bpf_dsq_move_to_local). cpu=the DRAINING CPU,
                                //   score=the raw dsq_id, pid=-1 (the kfunc does not name the
                                //   task). Pair with the next SWITCH_IN on the same CPU to
                                //   recover which task it was: if that task last ran elsewhere,
                                //   the migration was decided at DRAIN time by the race, not at
                                //   placement time by a policy.
  SCHED_OP_MIGRATE        = 16, // a task changed CPU (tp/sched/sched_migrate_task).
                                //   pid=task, cpu=DESTINATION, last_cpu=SOURCE,
                                //   sub_idx=the CPU that EXECUTED the move.
                                //   set_task_cpu runs in the decider's context, so
                                //   comparing sub_idx against the src/dst pair names
                                //   WHO decided: sub_idx==dst is a destination PULL,
                                //   sub_idx==src a source PUSH, anything else a
                                //   third-party PLACE (on a wake, the waker). A plain
                                //   tracepoint with no trampoline and no struct_ops
                                //   association, and class-agnostic, so it attributes
                                //   a non-sched_ext scheduler on the same axis -- which
                                //   a dsq kfunc probe structurally cannot.
};

// Per-CPU aggregation of scheduler-decision counts, indexed by sched_trace_op.
// The decision tracepoints fire on the dispatch hot path; counting per-CPU
// (one bump, no shared ringbuf reserve) keeps tracing near-zero-overhead there.
// Userspace sums across CPUs at snapshot time. Per-event streaming is opt-in
// (binary --trace-out only); the contract struct above is the streamed form.
#define MONTAUK_SCHED_OP_MAX 17  /* index by sched_trace_op (1..16); 0 unused */
struct sched_op_counters {
  __u64 op[MONTAUK_SCHED_OP_MAX];
};

// Per-CPU migration classification counters. The sched_switch hot path bumps
// these on every cross-core move of a traced thread, classified by whether the
// source and destination CPUs share an L3/cache domain domain (looked up in cpu_cache_domain).
// Userspace sums across CPUs at snapshot time. These globals survive traced-
// thread churn: a fork-storm exits ~1000 short-lived threads whose per-thread
// thread_bpf_state.migrations counts evaporate from thread_map; these do not.
struct mig_domain_counters {
  __u64 intra;    // src and dst CPUs in the same cache domain (shared L3)
  __u64 cross;    // src and dst in different cache domain domains (cross-domain interconnect)
  __u64 unknown;  // a CPU index outside cpu_cache_domain (topology not pushed / out of range)
  __u64 intra_wake;   // intra-domain move of a SLEPT-then-woken task: WAKE-PLACEMENT (select_cpu / enqueue spill push)
  __u64 intra_steal;  // intra-domain move of a PREEMPTED still-runnable task: dispatch-side STEAL/pull
  __u64 cross_wake;   // cross-domain wake-placement
  __u64 cross_steal;  // cross-domain steal
};

struct montauk_sched_event {
  __u32 type;           // TRACE_EVT_SCHED
  __u32 op;             // sched_trace_op
  __u32 cpu;
  __s32 pid;            // primary pid (enqueue/pick/preempt_tick: target; wakeup: wakee)
  __s32 secondary_pid;  // wakeup waker; preempt_tick & pick: -1
  __s32 last_cpu;       // enqueue only; else -1
  __u32 sub_idx;        // enqueue only; else 0
  __u32 freq_mhz;       // WAKE2RUN only: target CPU core freq (MHz) at wake from the
                        //   cpu_frequency timeline; 0 = unknown (no transition seen yet)
                        //   or other ops. Fills prior alignment pad -- no record growth.
  __u64 score;          // enqueue/pick; else 0
  __u64 runtime_ns;     // preempt_tick only
  __u64 budget_ns;      // preempt_tick only
  __u64 timestamp_ns;
};

// Per-CPU kernel-thread dispatch-strand event. Emitted system-wide (NOT scoped
// to the traced comm group, like SCHED_OP_CPU_IDLE) when a per-CPU kthread
// (PF_KTHREAD with nr_cpus_allowed == 1 -- ksoftirqd/N, bound kworkers, btrfs
// endio workers, the scx watchdog workfn) finally comes on-CPU after a
// became-runnable -> ran latency >= kstrand_thresh_ns. These threads can ONLY
// run on their one bound CPU, so a scheduler that strands them behind a long
// slice wedges every fsync/writeback waiter on the system into D state without
// tripping the runnable-stall watchdog (the victims are in D, not R). The run
// CPU here IS the bound CPU; the analyzer correlates it against CPU_IDLE to
// split a HELD strand (CPU busy through the wait -- scheduler fault) from a
// DARK one (CPU idle, tickless, no rescue scan). Gated on sched_stream.
struct montauk_kstrand_event {
  __u32 type;             // TRACE_EVT_KSTRAND
  __u32 tid;              // the per-CPU kthread's tid
  __u32 cpu;              // run CPU == the kthread's single allowed CPU
  __u32 nr_cpus_allowed;  // == 1 by construction (kept for forward-compat / sanity)
  __u64 latency_ns;       // became-runnable -> ran (the strand duration)
  __u64 timestamp_ns;     // ktime_get_ns at sched-in
  char  comm[16];         // next_comm from the sched_switch tracepoint
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

// Ring buffer event (kernel → userspace): fork, exec, exit, comm and thread
// names. An exec record is this struct and then path_len bytes of the whole
// filename and argv_len bytes of the argument vector, each argument ended by a
// NUL. A capture written before v8.15.0 ends its records at filename, and the
// analyzer reads the fields after it as zero (MONTAUK_RING_EVENT_V1_SIZE).
struct montauk_ring_event {
  __u32 type;
  __u32 pid;
  __u32 ppid;          // exec: the parent process at exec time; fork: the forking process's parent
  __u32 child_pid;     // fork: the new task
  char  comm[16];
  char  filename[64];  // exec'd filename from tracepoint (not /proc), cut at 64
  __u64 timestamp_ns;  // CLOCK_MONOTONIC, as every other record
  __u16 path_len;      // exec: bytes of the whole filename after this struct
  __u16 argv_len;      // exec: bytes of the argument vector after the filename
  __s32 exit_code;     // exit: the status as wait(2) reports it
};
#define MONTAUK_RING_EVENT_V1_SIZE 96

// One syscall a traced thread made, emitted at its exit (the syscall class,
// opt-in). A record is this struct and then path_len bytes of the first path
// the call names and path2_len of the second, no NUL: openat's path, both of
// rename's, and for readlink and readlinkat the target the kernel returned.
struct montauk_syscall_event {
  __u32 type;          // TRACE_EVT_SYSCALL
  __u32 pid;
  __u32 tid;
  __s32 nr;            // x86-64 syscall number
  __u64 arg0, arg1, arg2, arg3, arg4, arg5;
  __s64 result;        // the return value; a negative errno on failure
  __u64 timestamp_ns;  // at exit
  __u64 duration_ns;   // entry to exit
  __u64 ip;            // the user address the call returns to, after its syscall instruction
  __u64 vma_start;     // the mapping holding ip, when resolved
  __u64 vma_end;
  __u8  resolved;      // 1 when the mapping holding ip was found
  __u8  anon;          // 1 when no file backs that mapping: code mapped by hand, JIT, injected
  __u16 path_len;
  __u16 path2_len;
  __u16 _pad;
  char  comm[16];
};
#define MONTAUK_SC_PATH_MAX 4096   // the most --trace-path-bytes takes, per path
#define MONTAUK_SC_NR_WORDS 8      // the syscall-number filter: 512 numbers as a bitmap

// I/O ring event: emitted on every read/write/lseek/pread64/pwrite64/fstat exit
// for tracked processes. Carries full syscall details for event-level tracing.
struct montauk_io_event {
  __u32 type;       // TRACE_EVT_IO
  __u32 pid;
  __u32 tid;
  __s32 syscall_nr; // syscall number (0=read, 1=write, 8=lseek, 5=fstat, 17=pread64, 18=pwrite64)
  __s32 fd;
  __s64 result;     // return value (bytes read/written, new offset, or -errno)
  __u64 count;      // read/write: byte count; lseek: offset arg
  __u32 whence;     // lseek whence (0=SET, 1=CUR, 2=END)
  char  comm[16];
  __u64 timestamp_ns;  // CLOCK_MONOTONIC (bpf_ktime_get_ns); lets the decoder
                       // reconstruct elapsed/wall like montauk_sched_event
  __u64 duration_ns;   // enter->exit wall time for this syscall (0 if not tracked
                       // for this syscall_nr, e.g. reused pre-existing read/write
                       // events that predate enter-timestamp capture); the true
                       // block-I/O completion latency for a synchronous O_DIRECT
                       // pwrite64 -- the syscall itself doesn't return until the
                       // write completes, so there is no separate bio-layer hook
                       // to add.
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
  __u64 io_enter_ns;      // ktime_get_ns() at syscall entry, for duration_ns at exit.
                          // Set/used by pwrite64 (synchronous O_DIRECT completion),
                          // io_getevents (Linux AIO completion-reap), and the generic
                          // iowait syscalls (poll/ppoll/epoll_wait/epoll_pwait/
                          // recvmsg/recvfrom/select/pselect6/non-ntsync ioctl). Only
                          // one syscall is ever in flight per thread, so sharing this
                          // field across call sites is safe.

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
