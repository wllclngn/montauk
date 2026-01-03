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
#include "collectors/FsCollector.hpp"
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
  montauk::collectors::MemoryCollector mem_{};
  montauk::collectors::GpuCollector gpu_{};
  montauk::collectors::NetCollector net_{};
  montauk::collectors::DiskCollector disk_{};
  montauk::collectors::FsCollector fs_{};
  // Process collector (event-driven if available, else traditional)
  std::unique_ptr<montauk::collectors::IProcessCollector> proc_;
  montauk::app::AlertEngine alerts_{};
  montauk::collectors::ThermalCollector thermal_{};
  // Rolling cache of per-process GPU util with a short TTL to avoid flicker between NVML sample windows (test helper)
  std::unordered_map<int, std::pair<int, std::chrono::steady_clock::time_point>> last_proc_gpu_;
  // Unified GPU attributor (NVML + fdinfo)
  montauk::app::GpuAttributor* gpu_attr_{nullptr};
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
