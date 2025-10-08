#pragma once
#include <cstdint>
#include <vector>
#include <string>

namespace montauk::model {

struct CpuTimes {
  uint64_t user{}, nice{}, system{}, idle{}, iowait{}, irq{}, softirq{}, steal{};
  uint64_t total() const { return user + nice + system + idle + iowait + irq + softirq + steal; }
  uint64_t work()  const { return user + nice + system + irq + softirq + steal; }
};

struct CpuSnapshot {
  CpuTimes total_times{};
  std::vector<CpuTimes> per_core;
  double usage_pct{};              // aggregate percent 0..100
  std::vector<double> per_core_pct; // optional
  std::string model;               // CPU model name (static)
  int physical_cores{0};           // best-effort physical core count (per socket sum)
  int logical_threads{0};          // total logical CPUs (threads)
  // Optional breakdown of utilization over last interval (percent of total time)
  double pct_user{0.0};
  double pct_system{0.0};
  double pct_iowait{0.0};
  double pct_irq{0.0};
  double pct_steal{0.0};
};

} // namespace montauk::model
