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
};

// Per-PID process info (BPF map value)
struct proc_bpf_info {
  __u32 pid;
  __u32 ppid;
  __u8  tracked;      // 1 = in traced group
  __u8  is_root;      // 1 = matched pattern directly
  char  comm[16];
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
