#pragma once
#include "model/Pmu.hpp"
#include <chrono>
#include <cstdint>
#include <vector>

namespace montauk::collectors {

// Per-CPU hardware performance counter collector built on perf_event_open(2)
// in COUNTING mode (no sampling, no mmap ring). Targets AMD Zen 2 (Ryzen 5
// 3600): 12 logical CPUs, 2 CCX / 2 L3 domains.
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

  bool initialized_{false};
  bool available_{false};
  bool l3_available_{false};
  int  first_open_errno_{0};

  // Core PMU per-CPU counters (4 events x nr online CPUs).
  std::vector<Counter> l2_miss_;
  std::vector<Counter> l2_ref_;
  std::vector<Counter> instr_;
  std::vector<Counter> cycles_;

  // amd_l3 uncore: one (access, miss) pair per CCX/L3 domain cpu.
  struct L3Domain {
    int     domain_cpu{-1};
    Counter access;
    Counter miss;
  };
  std::vector<L3Domain> l3_;

  std::chrono::steady_clock::time_point last_sample_time_{};
  bool has_last_time_{false};
};

} // namespace montauk::collectors
