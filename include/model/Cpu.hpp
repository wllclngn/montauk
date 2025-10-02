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
};

} // namespace montauk::model
