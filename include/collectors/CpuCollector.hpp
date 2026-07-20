#pragma once
#include "model/Snapshot.hpp"
#include <chrono>

namespace montauk::collectors {

class CpuCollector {
public:
  CpuCollector() = default;
  [[nodiscard]] bool sample(montauk::model::CpuSnapshot& out);
private:
  montauk::model::CpuTimes last_total_{};
  std::vector<montauk::model::CpuTimes> last_per_{};
  std::vector<montauk::model::CpuTimes> per_scratch_{};  // reused parse buffer
  std::vector<std::string> freq_paths_{};  // per-core cpufreq paths, built once
  bool has_last_{false};
  std::string cpu_model_{};
  int physical_cores_{0};   // summed per-socket "cpu cores" from /proc/cpuinfo
  uint64_t last_ctxt_{0};
  uint64_t last_intr_{0};
  std::chrono::steady_clock::time_point last_sample_time_{};
};

} // namespace montauk::collectors
