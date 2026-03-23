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
};

struct FdSample {
  int32_t pid{};
  int     fd_num{-1};
  char    target[128]{};            // readlink result: "/dev/ntsync", "pipe:[12345]"
};

struct TracedProcess {
  int32_t pid{};
  int32_t ppid{};
  bool    is_root{false};           // matched pattern directly vs. inherited child
  char    cmd[128]{};
};

struct TraceSnapshot {
  static constexpr int MAX_PROCS   = 64;
  static constexpr int MAX_THREADS = 256;
  static constexpr int MAX_FDS     = 256;

  std::array<TracedProcess, MAX_PROCS> procs{};
  int procs_count{};

  std::array<ThreadSample, MAX_THREADS> threads{};
  int thread_count{};

  std::array<FdSample, MAX_FDS> fds{};
  int fd_count{};

  bool     waiting_for_match{false};
  uint64_t seq{};
};

} // namespace montauk::model
