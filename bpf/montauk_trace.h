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
#define TRACE_MAX_THREADS   1024
#define TRACE_MAX_FDS       4096
#define TRACE_MAX_DISCOVERY 4096  // discovery map: all processes seen by sys_enter
#define TRACE_PATTERN_MAX   32   // max pattern length for BPF-side matching

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
  char  comm[16];

  // File I/O tracking: captures last I/O syscall details per thread
  __s32 io_fd;            // fd involved in last I/O syscall (-1 = none)
  __u64 io_count;         // read/write: byte count; lseek: offset argument
  __u32 io_whence;        // lseek whence (0=SET, 1=CUR, 2=END)
  __s64 io_result;        // return value (bytes read/written, new offset, or -errno)
  __u64 io_timestamp_ns;  // ktime_get_ns() when I/O completed
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
