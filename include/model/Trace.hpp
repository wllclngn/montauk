#pragma once
#include <array>
#include <cstdint>

namespace montauk::model {

struct ThreadSample {
  int32_t  pid{};
  int32_t  tid{};
  char     state{'?'};              // R/S/D/T/Z from /proc/pid/task/tid/stat
  double   cpu_pct{};
  uint64_t utime{};
  uint64_t stime{};
  int      syscall_nr{-1};          // -1 = running or unreadable
  uint64_t syscall_arg1{};          // ioctl cmd, futex op
  uint64_t syscall_arg2{};          // futex addr
  char     comm[24]{};              // /proc comm is max 16 chars + padding
  char     wchan[48]{};             // kernel wait function name
  char     syscall_name[24]{};      // decoded name or raw number string

  // I/O syscall details (from BPF io_* fields)
  int32_t  io_fd{-1};
  uint64_t io_count{};
  uint32_t io_whence{};
  int64_t  io_result{};
  uint64_t io_timestamp_ns{};

  // On-CPU placement / migration (from BPF cur_cpu / migrations)
  int32_t  cur_cpu{-1};
  uint64_t migrations{};
};

struct FdSample {
  int32_t pid{};
  int     fd_num{-1};
  char    target[128]{};            // readlink result: "/dev/ntsync", "pipe:[12345]"
};

struct TracedProcess {
  int32_t  pid{};
  int32_t  ppid{};
  bool     is_root{false};
  bool     exited{false};
  int32_t  exit_code{};
  uint64_t fork_ts{};
  uint64_t exec_ts{};
  uint64_t exit_ts{};
  char     cmd[128]{};
  char     exec_file[64]{};
};

struct NtsyncSample {
  int32_t  pid{};
  int32_t  tid{};
  uint8_t  op{};           // ntsync_trace_op enum
  int32_t  fd{};
  int64_t  result{};
  uint64_t timestamp_ns{};
  uint32_t arg0{};         // create: param0 / signal: prev_state
  uint32_t arg1{};         // create: param1
  uint64_t timeout_ns{};
  uint32_t wait_count{};
  uint32_t wait_index{};
  uint32_t wait_owner{};
  uint32_t wait_alert{};
  uint32_t wait_fds[8]{};  // first 8 object fds
  char     comm[24]{};
};

struct TraceSnapshot {
  static constexpr int MAX_PROCS   = 64;
  static constexpr int MAX_THREADS = 256;
  static constexpr int MAX_FDS     = 256;
  static constexpr int MAX_NTSYNC  = 512;

  std::array<TracedProcess, MAX_PROCS> procs{};
  int procs_count{};

  std::array<ThreadSample, MAX_THREADS> threads{};
  int thread_count{};

  std::array<FdSample, MAX_FDS> fds{};
  int fd_count{};

  std::array<NtsyncSample, MAX_NTSYNC> ntsync_events{};
  int ntsync_count{};

  // Scheduler-decision counts, indexed by sched_trace_op (1..6), summed across
  // CPUs. Non-zero only when the active scheduler binds decision tracepoints;
  // index 6 (wakeup) comes from the generic kernel sched_wakeup tracepoint.
  std::array<uint64_t, 7> sched_op_total{};

  // Migration classification (cumulative since attach, summed across CPUs from
  // the BPF mig_ccx_counts map): a fork-storm's core-hopping split by whether
  // the move stayed within an L3 cache domain or crossed cross-domain interconnect. The
  // intra-heavy signature is the intra-domain L2-refill cost; cross is the cross-domain cost.
  uint64_t mig_intra_domain{};
  uint64_t mig_cross_domain{};
  uint64_t mig_unknown_domain{};
  uint64_t mig_intra_wake{};   // intra-domain wake-placements (select_cpu / enqueue spill push)
  uint64_t mig_intra_steal{};  // intra-domain dispatch steals (pull)
  uint64_t mig_cross_wake{};
  uint64_t mig_cross_steal{};

  bool     waiting_for_match{false};
  uint64_t seq{};
};

} // namespace montauk::model
