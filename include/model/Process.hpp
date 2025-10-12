#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace montauk::model {

struct ProcSample {
  int32_t pid{};
  int32_t ppid{};
  uint64_t utime{};  // jiffies
  uint64_t stime{};  // jiffies
  uint64_t total_time{}; // utime+stime
  uint64_t rss_kb{};
  double   cpu_pct{}; // 0..100 (overall machine)
  // True when this row had /proc churn (could not read/parse this cycle)
  bool     churn{false};
  // Optional GPU metrics (per process)
  bool     has_gpu_util{false};
  double   gpu_util_pct{0.0};
  // Raw NVML per-process util for this cycle (not smoothed)
  bool     has_gpu_util_raw{false};
  double   gpu_util_pct_raw{0.0};
  bool     has_gpu_mem{false};
  uint64_t gpu_mem_kb{0};
  std::string user_name;
  std::string cmd;
  std::string exe_path;
};

struct ProcessSnapshot {
  std::vector<ProcSample> processes; // sorted by cpu desc
  size_t total_processes{};
  size_t running_processes{};
  // Number of processes enriched with full cmdline+user this cycle
  size_t enriched_count{};
  // Number of processes tracked after top-K cap
  size_t tracked_count{};
  // State breakdown (counts)
  size_t state_running{};   // 'R'
  size_t state_sleeping{};  // 'S' + 'D'
  size_t state_zombie{};    // 'Z'
  // System-wide thread statistics
  size_t total_threads{};      // Total threads across all processes
  size_t threads_max{};        // System limit from /proc/sys/kernel/threads-max
};

} // namespace montauk::model
