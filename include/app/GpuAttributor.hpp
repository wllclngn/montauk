#pragma once
#include <unordered_map>
#include <unordered_set>
#include <chrono>
#include "model/Snapshot.hpp"
#include "collectors/FdinfoProcessCollector.hpp"

namespace montauk::app {

// Unifies per-process GPU attribution across NVML (NVIDIA) and DRM fdinfo (AMD/Intel).
// Applies smoothing/hold/decay and fallbacks; updates Snapshot process fields and NVML diagnostics.
class GpuAttributor {
public:
  using Clock = std::chrono::steady_clock;
  GpuAttributor();
  ~GpuAttributor();
  // Enrich snapshot 's' with per-process GPU%. Called periodically (~1 Hz recommended).
  void enrich(montauk::model::Snapshot& s);

private:
  struct GpuSmooth { double ema{0.0}; Clock::time_point last_sample{}; Clock::time_point last_running{}; };
  std::unordered_map<int, GpuSmooth> gpu_smooth_;
  montauk::collectors::FdinfoProcessCollector fdinfo_{};

#ifdef MONTAUK_HAVE_NVML
  bool nvml_inited_{false};
  bool nvml_ok_{false};
  std::vector<unsigned long long> nvml_last_proc_ts_per_dev_{};
  Clock::time_point last_nvml_sample_tp_{};
  void ensure_nvml_init();
  void nvml_shutdown_if_needed();
#endif
};

} // namespace montauk::app

