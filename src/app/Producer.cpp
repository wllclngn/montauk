#include "app/Producer.hpp"
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include "app/GpuAttributor.hpp"
#include "util/Churn.hpp"
#include "collectors/ProcessCollector.hpp"
#include "collectors/NetlinkProcessCollector.hpp"

using namespace std::chrono;

namespace montauk::app {

Producer::Producer(SnapshotBuffers& buffers) : buffers_(buffers) {
  // Choose process collector: try netlink first, then fallback to traditional
  const char* force = std::getenv("MONTAUK_COLLECTOR");
  auto make_traditional = [](){
    // Default to ~100ms min interval to allow quick warm-up; steady cadence remains ~1s
    return std::unique_ptr<montauk::collectors::IProcessCollector>(new montauk::collectors::ProcessCollector(100));
  };

#ifdef __linux__
  if (force && std::strcmp(force, "traditional") == 0) {
    proc_ = make_traditional();
  } else {
    // Try netlink unless forced traditional
    auto netlink = std::unique_ptr<montauk::collectors::IProcessCollector>(new montauk::collectors::NetlinkProcessCollector(256));
    if (force && std::strcmp(force, "netlink") == 0) {
      if (!netlink->init()) {
        std::fprintf(stderr, "Netlink collector unavailable (need CAP_NET_ADMIN?). Falling back to traditional.\n");
        proc_ = make_traditional();
      } else {
        proc_ = std::move(netlink);
      }
    } else {
      if (netlink->init()) {
        proc_ = std::move(netlink);
      } else {
        proc_ = make_traditional();
      }
    }
  }
#else
  (void)force;
  proc_ = make_traditional();
#endif
}

void Producer::start() {
  if (thread_.joinable()) return;
  thread_ = std::jthread([this](std::stop_token st){ run(st); });
}

void Producer::stop() {
  if (thread_.joinable()) thread_.request_stop();
}

Producer::~Producer() { stop(); }

void Producer::run(std::stop_token st) {
  // Small helper: compute kernel tick in milliseconds for warm-up pacing
  auto tick_ms = []{
    long hz = ::sysconf(_SC_CLK_TCK);
    int t = (hz > 0) ? static_cast<int>(1000 / hz) : 10; // typical: 10ms when HZ=100
    if (t < 4) t = 4;
    if (t > 20) t = 20;
    return t;
  }();

  // per-collector cadence
  auto next_cpu = steady_clock::now();
  auto next_mem = steady_clock::now();
  auto next_gpu = steady_clock::now();
  auto next_net = steady_clock::now();
  auto next_disk = steady_clock::now();
  auto next_proc = steady_clock::now();
  auto next_therm = steady_clock::now();
  const auto cpu_interval = 500ms;
  const auto mem_interval = 500ms;
  const auto gpu_interval = 1000ms;
  const auto net_interval = 1000ms;
  const auto disk_interval = 1000ms;
  const auto proc_interval = 1000ms;
  const auto therm_interval = 2000ms;
  // Publish cadence to smooth UI updates (stable rhythm independent of collector jitter)
  const auto pub_interval = 250ms;
  auto next_pub = steady_clock::now() + pub_interval;
  // Throttle heavy NVML per-process sampling to ~1s to keep UI snappy
  auto next_nvml = steady_clock::now();
  const auto nvml_interval = 1000ms;
  if (!gpu_attr_) gpu_attr_ = new montauk::app::GpuAttributor();

  // HOT start warm-up: take fast pre-samples so first publish has real deltas
  {
    auto& s = buffers_.back();
    // Seed with an initial read for all
    cpu_.sample(s.cpu);
    mem_.sample(s.mem);
    gpu_.sample(s.vram);
    net_.sample(s.net);
    disk_.sample(s.disk);
    if (proc_) proc_->sample(s.procs);
    thermal_.sample(s.thermal);

    // Time budget for warm-up (~180ms max)
    auto warm_start = steady_clock::now();
    auto warm_deadline = warm_start + 200ms;

    // CPU + Processes: a few tick-spaced reads to establish deltas
    for (int i = 0; i < 3 && !st.stop_requested(); ++i) {
      auto now = steady_clock::now(); if (now >= warm_deadline) break;
      auto rem = duration_cast<milliseconds>(warm_deadline - now);
      auto nap = milliseconds(std::min<int>(tick_ms, static_cast<int>(rem.count())));
      if (nap.count() > 0) std::this_thread::sleep_for(nap);
      cpu_.sample(s.cpu);
      if (proc_) proc_->sample(s.procs);
    }

    // Net + Disk: short spaced reads for non-zero bps/util
    for (int i = 0; i < 2 && !st.stop_requested(); ++i) {
      auto now = steady_clock::now(); if (now >= warm_deadline) break;
      auto rem = duration_cast<milliseconds>(warm_deadline - now);
      auto nap = milliseconds(std::min<int>(60, std::max<int>(10, static_cast<int>(rem.count()))));
      if (nap.count() > 0) std::this_thread::sleep_for(nap);
      net_.sample(s.net);
      disk_.sample(s.disk);
    }

    // Re-sample memory/thermal/gpu once (non-rate or slow-changing)
    mem_.sample(s.mem);
    thermal_.sample(s.thermal);
    gpu_.sample(s.vram);

    // Generate alerts and publish once — first visible frame uses this snapshot
    {
      auto a = alerts_.evaluate(s);
      s.alerts.clear();
      for (auto& it : a) s.alerts.push_back(montauk::model::AlertItem{it.severity, it.message});
    }
    buffers_.publish();
  }

  (void)0; // no-op placeholder; keep code structure
  while (!st.stop_requested()) {
    auto now = steady_clock::now();
    bool ran = false;
    auto& s = buffers_.back();
    if (now >= next_cpu) { cpu_.sample(s.cpu); next_cpu = now + cpu_interval; ran = true; }
    if (now >= next_mem) { mem_.sample(s.mem); next_mem = now + mem_interval; ran = true; }
    if (now >= next_gpu) { gpu_.sample(s.vram); next_gpu = now + gpu_interval; ran = true; }
    if (now >= next_net) { net_.sample(s.net); next_net = now + net_interval; ran = true; }
    if (now >= next_disk){ disk_.sample(s.disk); next_disk = now + disk_interval; ran = true; }
    if (now >= next_proc){ if (proc_) proc_->sample(s.procs); next_proc = now + proc_interval; ran = true; }
    if (now >= next_therm){ thermal_.sample(s.thermal); next_therm = now + therm_interval; ran = true; }
    bool time_to_publish = false;
    if (now >= next_pub) { time_to_publish = true; next_pub = now + pub_interval; }
    bool nvml_ran = false;
    if (now >= next_nvml) nvml_ran = true;
    if (ran || time_to_publish || nvml_ran) {
      {
        auto a = alerts_.evaluate(s);
        s.alerts.clear();
        for (auto& it : a) s.alerts.push_back(montauk::model::AlertItem{it.severity, it.message});
      }
      // Populate churn diagnostics for SYSTEM sticky line
      s.churn.recent_2s_events = montauk::util::count_recent_ms(2000);
      s.churn.recent_2s_proc   = montauk::util::count_recent_kind_ms(montauk::util::ChurnKind::Proc, 2000);
      s.churn.recent_2s_sys    = montauk::util::count_recent_kind_ms(montauk::util::ChurnKind::Sysfs, 2000);
      // Enrich per-process GPU utilization using NVML (best effort, throttled)
      if (nvml_ran) {
        // Attribute per-process GPU% across NVML/fdinfo backends
        gpu_attr_->enrich(s);
        next_nvml = now + nvml_interval;
      }
      buffers_.publish();
    }
    // sleep until the earliest next_due or next_pub, bounded
    auto next_due = std::min({next_cpu, next_mem, next_gpu, next_net, next_disk, next_proc, next_therm, next_pub});
    auto sleep_for = duration_cast<milliseconds>(next_due - steady_clock::now());
    if (sleep_for < 20ms) {
      sleep_for = 20ms;
    }
    if (sleep_for > 100ms) {
      sleep_for = 100ms;
    }
    std::this_thread::sleep_for(sleep_for);
  }
  // Cleanup after loop
  if (gpu_attr_) { delete gpu_attr_; gpu_attr_ = nullptr; }
}

// test_apply_gpu_samples is defined inline in Producer.hpp under MONTAUK_TESTING

} // namespace montauk::app
