#pragma once
#include "model/Pmu.hpp"
#include <chrono>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace montauk::collectors {

// Per-CPU hardware performance counter collector built on perf_event_open(2)
// in COUNTING mode (no sampling, no mmap ring). Targets AMD Zen 2 (Ryzen 5
// 3600): 12 logical CPUs, 2 cache domains.
//
// Counters are opened lazily on the first sample() call. If perf_event_open
// is denied (perf_event_paranoid, EACCES/EPERM) or unsupported (ENODEV), the
// collector marks itself unavailable, logs ONE stderr line, and every later
// sample() becomes a cheap no-op returning true. It never crashes or spams.
class PmuCollector {
public:
  PmuCollector() = default;
  ~PmuCollector();
  PmuCollector(const PmuCollector&) = delete;
  PmuCollector& operator=(const PmuCollector&) = delete;

  // Read all counters, compute interval deltas, and fill `out`. Returns true
  // even when unavailable (resilient: callers ignore the value like cpu_).
  [[nodiscard]] bool sample(montauk::model::PmuSnapshot& out);

  // Declare the set of processes to attribute counters to. Idempotent: pids
  // already attached keep their counters (and therefore their cumulative
  // totals) across calls, pids that disappear are closed, new pids are opened.
  // Called every producer tick with whatever the operator's --pmu-comm /
  // --pmu-pid selection currently resolves to.
  //
  // Independent of the per-CPU path in both directions: this works at
  // perf_event_paranoid 2 where the per-CPU path cannot open at all, so a box
  // with the system-wide PMU off still gets per-process attribution.
  void set_process_targets(const std::vector<std::pair<int, std::string>>& pids);

private:
  // One opened counter fd plus its rolling last value.
  struct Counter {
    int      fd{-1};
    int      cpu{-1};
    uint64_t last{0};
    bool     has_last{false};
  };

  void init();          // lazy one-time open of every fd
  void close_all();     // close every open fd
  uint64_t read_delta(Counter& c); // read fd, return delta vs last, update last

  // Open one counting-mode fd for (type, config) on logical `cpu`. Returns the
  // fd or -1 on failure (sets first_open_errno_ on the first failure seen).
  int open_one(uint32_t type, uint64_t config, int cpu);

  // Open one counting-mode fd for (type, config) against `pid`, all CPUs,
  // inheriting into children. Separate from open_one because the two differ in
  // more than an argument: this one may succeed where that one is forbidden,
  // and must not record its errno into the per-CPU diagnosis.
  int open_one_proc(uint32_t type, uint64_t config, int pid);

  void fill_per_process(montauk::model::PmuSnapshot& out);

  bool initialized_{false};
  bool available_{false};
  bool l3_available_{false};
  int  first_open_errno_{0};

  // Core PMU per-CPU counters (4 events x nr online CPUs).
  std::vector<Counter> l2_miss_;
  std::vector<Counter> l2_ref_;
  std::vector<Counter> instr_;
  std::vector<Counter> cycles_;
  // Optional scheduler-relevant counters (SW ctx-switch/migrations, HW branch
  // miss). Opened best-effort; an fd of -1 (unsupported) just reads 0.
  std::vector<Counter> ctxsw_;
  std::vector<Counter> migr_;
  std::vector<Counter> branch_;
  // Memory-stall attribution: which of the two answers to "why is this
  // memory-bound thing slow" applies -- address translation, or the data not
  // being resident. Best-effort like the three above.
  std::vector<Counter> dtlb_;
  std::vector<Counter> cachemiss_;

  // One attached process. Opened with pid=<target>, cpu=-1, inherit=1 --
  // permitted at paranoid 2 with no privilege, unlike everything above.
  struct ProcTarget {
    int         pid{-1};
    std::string comm;
    Counter     instr, cycles, dtlb, cachemiss;
    uint64_t    total_instr{}, total_cycles{}, total_dtlb{}, total_cachemiss{};
  };
  std::vector<ProcTarget> procs_;
  bool proc_available_{false};
  int  first_proc_errno_{0};
  bool proc_warned_{false};
  // True when the per-process opens had to drop to user-space-only
  // (paranoid >= 2). Published, not hidden: it changes what the numbers
  // mean.
  bool proc_user_only_{false};

  // amd_l3 uncore: one (access, miss) pair per L3 cache domain cpu.
  struct L3Domain {
    int     domain_cpu{-1};
    Counter access;
    Counter miss;
  };
  std::vector<L3Domain> l3_;

  std::chrono::steady_clock::time_point last_sample_time_{};
  bool has_last_time_{false};

  // Running sums of the per-interval aggregates, for the _total families.
  uint64_t total_instructions_{}, total_cycles_{}, total_context_switches_{};
  uint64_t total_cpu_migrations_{}, total_branch_misses_{}, total_l2_misses_{};
  uint64_t total_dtlb_{}, total_cache_misses_{};
};

} // namespace montauk::collectors
