#pragma once
#include <chrono>
#include <memory>
#include <thread>
#include <stop_token>
#include <unordered_map>
#include "app/SnapshotBuffers.hpp"
#include "collectors/MemoryCollector.hpp"
#include "collectors/GpuCollector.hpp"
#include "collectors/CpuCollector.hpp"
#include "collectors/PmuCollector.hpp"
#include "collectors/NetCollector.hpp"
#include "collectors/DiskCollector.hpp"
#include "collectors/FsCollector.hpp"
#include "collectors/ProviderCollector.hpp"
#include "collectors/IProcessCollector.hpp"
#include "app/Alerts.hpp"
#include "collectors/ThermalCollector.hpp"

namespace montauk::app {

class GpuAttributor; // forward decl

class Producer {
public:
  explicit Producer(SnapshotBuffers& buffers);
  void start();
  void stop();
  ~Producer();

  // Opt into hardware PMU sampling (perf_event_open: L2 miss/ref, IPC,
  // per-CCX L3). PMU data exists for the trace→analyze pipeline, not the
  // monitor — it needs CAP_PERFMON or perf_event_paranoid<=0, which the
  // plain TUI must never demand. main.cpp calls this only when --trace
  // is active. Must be called before start().
  void enable_pmu() { pmu_enabled_ = true; }

#ifdef MONTAUK_TESTING
  // Test-only helper: apply a set of per-process GPU samples (pid->util%)
  // to the given ProcessSnapshot while updating the rolling cache. A TTL
  // is applied so intermittent sample windows still display stable values.
  void test_apply_gpu_samples(const std::unordered_map<int,int>& pid_to_gpu,
                              montauk::model::ProcessSnapshot& procs,
                              std::chrono::steady_clock::time_point now_tp);
#endif

private:
  void run(std::stop_token st);
  SnapshotBuffers& buffers_;
  std::jthread thread_{};
  // collectors
  montauk::collectors::CpuCollector cpu_{};
  montauk::collectors::PmuCollector pmu_{};
  bool pmu_enabled_{false};  // see enable_pmu()
  montauk::collectors::MemoryCollector mem_{};
  montauk::collectors::GpuCollector gpu_{};
  montauk::collectors::NetCollector net_{};
  montauk::collectors::DiskCollector disk_{};
  montauk::collectors::FsCollector fs_{};
  montauk::collectors::ProviderCollector providers_{};
  // Process collector (event-driven if available, else traditional)
  std::unique_ptr<montauk::collectors::IProcessCollector> proc_;
  montauk::app::AlertEngine alerts_{};
  montauk::collectors::ThermalCollector thermal_{};
  // Rolling cache of per-process GPU util with a short TTL to avoid flicker between NVML sample windows (test helper)
  std::unordered_map<int, std::pair<int, std::chrono::steady_clock::time_point>> last_proc_gpu_;
  // Unified GPU attributor (NVML + fdinfo)
  std::unique_ptr<montauk::app::GpuAttributor> gpu_attr_;
};

#ifdef MONTAUK_TESTING
inline void Producer::test_apply_gpu_samples(const std::unordered_map<int,int>& pid_to_gpu,
                                             montauk::model::ProcessSnapshot& procs,
                                             std::chrono::steady_clock::time_point now_tp) {
  for (const auto& kv : pid_to_gpu) {
    last_proc_gpu_[kv.first] = std::make_pair(kv.second, now_tp);
  }
  const auto ttl = std::chrono::milliseconds(2000);
  for (auto& p : procs.processes) {
    auto it = pid_to_gpu.find(p.pid);
    if (it != pid_to_gpu.end()) {
      p.has_gpu_util = true; p.gpu_util_pct = (double)it->second; continue;
    }
    auto it2 = last_proc_gpu_.find(p.pid);
    if (it2 != last_proc_gpu_.end() && (now_tp - it2->second.second) <= ttl) {
      p.has_gpu_util = true; p.gpu_util_pct = (double)it2->second.first; continue;
    }
  }
  for (auto it = last_proc_gpu_.begin(); it != last_proc_gpu_.end(); ) {
    if ((now_tp - it->second.second) > ttl) it = last_proc_gpu_.erase(it); else ++it;
  }
}
#endif

} // namespace montauk::app
