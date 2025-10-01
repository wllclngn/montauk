#pragma once
#include <chrono>
#include <thread>
#include <stop_token>
#include <unordered_map>
#include "app/SnapshotBuffers.hpp"
#include "collectors/MemoryCollector.hpp"
#include "collectors/GpuCollector.hpp"
#include "collectors/CpuCollector.hpp"
#include "collectors/NetCollector.hpp"
#include "collectors/DiskCollector.hpp"
#include "collectors/ProcessCollector.hpp"
#include "app/Alerts.hpp"
#include "collectors/ThermalCollector.hpp"

namespace lsm::app {

class GpuAttributor; // forward decl

class Producer {
public:
  explicit Producer(SnapshotBuffers& buffers);
  void start();
  void stop();
  ~Producer();

#ifdef LSM_TESTING
  // Test-only helper: apply a set of per-process GPU samples (pid->util%)
  // to the given ProcessSnapshot while updating the rolling cache. A TTL
  // is applied so intermittent sample windows still display stable values.
  void test_apply_gpu_samples(const std::unordered_map<int,int>& pid_to_gpu,
                              lsm::model::ProcessSnapshot& procs,
                              std::chrono::steady_clock::time_point now_tp);
#endif

private:
  void run(std::stop_token st);
  SnapshotBuffers& buffers_;
  std::jthread thread_{};
  // collectors
  lsm::collectors::CpuCollector cpu_{};
  lsm::collectors::MemoryCollector mem_{};
  lsm::collectors::GpuCollector gpu_{};
  lsm::collectors::NetCollector net_{};
  lsm::collectors::DiskCollector disk_{};
  // Use a smaller min interval to allow fast warm-up pre-samples; normal cadence is still 1s
  lsm::collectors::ProcessCollector proc_{100};
  lsm::app::AlertEngine alerts_{};
  lsm::collectors::ThermalCollector thermal_{};
  // Rolling cache of per-process GPU util with a short TTL to avoid flicker between NVML sample windows (test helper)
  std::unordered_map<int, std::pair<int, std::chrono::steady_clock::time_point>> last_proc_gpu_;
  // Unified GPU attributor (NVML + fdinfo)
  lsm::app::GpuAttributor* gpu_attr_{nullptr};
};

#ifdef LSM_TESTING
inline void Producer::test_apply_gpu_samples(const std::unordered_map<int,int>& pid_to_gpu,
                                             lsm::model::ProcessSnapshot& procs,
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

} // namespace lsm::app
