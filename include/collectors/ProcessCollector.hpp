#pragma once
#include "model/Snapshot.hpp"
#include "collectors/IProcessCollector.hpp"
#include <unordered_map>
#include <chrono>

namespace montauk::collectors {

class ProcessCollector : public IProcessCollector {
public:
  // min_interval_ms governs how often we compute; extra calls within the interval no-op
  explicit ProcessCollector(unsigned min_interval_ms = 500, size_t max_procs = 256, size_t enrich_top_n = 256);
  bool init() override { return true; }
  void shutdown() override {}
  const char* name() const override { return "Traditional /proc Scanner"; }
  bool sample(montauk::model::ProcessSnapshot& out) override;
private:
  std::unordered_map<int32_t, uint64_t> last_per_proc_{}; // pid -> total_time
  uint64_t last_cpu_total_{};
  bool have_last_{false};
  unsigned min_interval_ms_{};
  size_t max_procs_{};
  size_t enrich_top_n_{};
  std::chrono::steady_clock::time_point last_run_{};
  unsigned ncpu_{0};
};

} // namespace montauk::collectors
