#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace montauk::model {

// Enum to distinguish between transient read failures and actual security-relevant churn
enum class ChurnReason {
  None,        // No issues reading /proc for this process
  ReadFailed,  // Transient /proc read error (not security-relevant)
};

struct ProcSample {
  int32_t pid{};
  uint64_t total_time{}; // utime+stime, jiffies
  uint64_t rss_kb{};
  double   cpu_pct{}; // 0..100 (overall machine)
  ChurnReason churn_reason{ChurnReason::None};
  // Optional GPU metrics (per process)
  bool     has_gpu_util{false};
  double   gpu_util_pct{0.0};
  bool     has_gpu_mem{false};
  uint64_t gpu_mem_kb{0};
  std::string user_name;
  std::string cmd;
  std::string exe_path;
  // Extra stat-derived signals for anomaly enrichment (all-process, free from
  // the /proc/PID/stat line the collectors already parse).
  uint64_t flt_raw{0};      // cumulative minor+major faults; rate derived in enrichment
  int      thread_count{1}; // /proc/PID/stat num_threads
  // Cumulative context-switch counters from /proc/PID/status, read for EVERY
  // process. The rate is what the anomaly fusion wants; the raw totals live here
  // so the delta can be taken across frames the way flt_raw's is.
  uint64_t vctx_raw{0};     // voluntary: gave up the CPU (blocked, yielded)
  uint64_t nvctx_raw{0};    // involuntary: was preempted
  // Cross-sectional anomaly enrichment (AnomalyEnrichment): fused score over the
  // live process population, higher = more anomalous, with the dominant feature.
  double  fault_delta{0.0};   // per-frame page-fault increase (feature 3); stateful, set in enrichment
  // Per-frame involuntary context switches. The axis the other five cannot see:
  // a process being PREEMPTED hard shows up here and nowhere else -- cpu% says
  // it ran, rss says nothing, and thread count is static.
  double  ctxsw_delta{0.0};
  double  anomaly_score{0.0};
  int8_t  anomaly_axis{-1};   // 0=cpu 1=rss 2=gpu 3=faults 4=threads 5=ctxsw; -1 = none
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
};

} // namespace montauk::model
