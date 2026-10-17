#pragma once
#include <atomic>
#include <chrono>
#include <memory>
#include <thread>
#include <stop_token>
#include <string>
#include <unordered_map>
#include <vector>
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
  // Per-process sampling cadence. Public because a per-process cpu_pct is a
  // delta over this window and is only meaningful once a full one has closed:
  // the hot-start warm-up pre-samples a few ticks apart, and at that width the
  // whole-jiffy quantization dominates (one jiffy of error is most of the
  // window), which is what makes a one-shot read far above 100% per core.
  static constexpr std::chrono::milliseconds kProcessInterval{1000};

  explicit Producer(SnapshotBuffers& buffers);
  void start();
  void stop();
  ~Producer();

  // WHERE THE PRODUCER'S CPU GOES, stage by stage. Off unless asked for:
  // When on, each stage of the steady collection loop is bracketed by the
  // thread's own CPU clock, so a stage's total is CPU this thread spent in it
  // and nothing else on the box. The warm-up is not counted. Read the totals
  // only after stop(), which joins the thread.
  enum class Stage : uint8_t {
    Cpu, Pmu, Memory, Gpu, Net, Disk, Fs, Processes, Thermal, Providers,
    Alerts, GpuAttribution, Anomalies, Changepoint, History, Count
  };
  struct StageCost { const char* name; uint64_t calls; uint64_t cpu_ns; };
  void enable_stage_timing() { stage_timing_ = true; }
  [[nodiscard]] std::vector<StageCost> stage_costs() const;

  // Opt into hardware PMU sampling (perf_event_open: L2 miss/ref, IPC,
  // per-cache-domain L3). PMU data exists for the trace→analyze pipeline, not the
  // monitor — it needs CAP_PERFMON or perf_event_paranoid<=0, which the
  // plain TUI must never demand. main.cpp calls this only when --trace
  // is active. Must be called before start().
  void enable_pmu() { pmu_enabled_ = true; }

  // Per-process PMU attribution: attach hardware counters to the processes the
  // operator names, by command substring and/or explicit pid. Unlike
  // enable_pmu()'s per-CPU counters this needs NO privilege and NO sysctl
  // (perf_event_open with pid >= 0 and cpu == -1 is permitted at
  // perf_event_paranoid 2), so it is deliberately NOT gated behind --trace --
  // gating it there would put it behind BPF and root and defeat the point.
  // Selection is re-resolved every process tick, so a workload started after
  // montauk is picked up when it appears.
  void set_pmu_process_filter(std::string comm_substr, std::vector<int> pids) {
    pmu_comm_ = std::move(comm_substr);
    pmu_pids_ = std::move(pids);
    pmu_proc_enabled_ = !pmu_comm_.empty() || !pmu_pids_.empty();
  }

  // Count of completed per-process samples. The hot-start warm-up fires
  // several only a kernel tick apart, so a delta taken across them is
  // quantized noise (most processes accrue no jiffy at all and read 0, an
  // unlucky one catches a whole jiffy and reads far above 100% per core). A
  // consumer that needs a trustworthy per-process cpu_pct -- the --json
  // one-shot -- waits for this to advance past its post-warm-up value, which
  // only a steady-loop sample a full kProcessInterval later can do.
  uint64_t process_samples() const noexcept {
    return process_samples_.load(std::memory_order_acquire);
  }

private:
  void run(std::stop_token st);
  template <class F> void timed(Stage s, F&& f);
  bool stage_timing_{false};
  std::array<uint64_t, static_cast<size_t>(Stage::Count)> stage_calls_{};
  std::array<uint64_t, static_cast<size_t>(Stage::Count)> stage_ns_{};
  SnapshotBuffers& buffers_;
  std::jthread thread_{};
  // collectors
  montauk::collectors::CpuCollector cpu_{};
  montauk::collectors::PmuCollector pmu_{};
  bool pmu_enabled_{false};  // see enable_pmu()
  bool pmu_proc_enabled_{false};   // see set_pmu_process_filter()
  std::string pmu_comm_;
  std::vector<int> pmu_pids_;
  // Resolve pmu_comm_/pmu_pids_ against the live process list and hand the
  // result to the collector. Cheap: a substring scan over an already-collected
  // snapshot, and the collector keeps existing attachments untouched.
  void refresh_pmu_targets(const montauk::model::ProcessSnapshot& procs);
  std::atomic<uint64_t> process_samples_{0};  // see process_samples()
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
  // Per-pid cumulative fault count from the previous cycle; the anomaly
  // enrichment derives its fault-delta feature from this and refreshes it.
  std::unordered_map<int32_t, uint64_t> anomaly_prev_faults_;
  // Same shape, for the involuntary context-switch axis.
  std::unordered_map<int32_t, uint64_t> anomaly_prev_ctxsw_;
  // Unified GPU attributor (NVML + fdinfo)
  std::unique_ptr<montauk::app::GpuAttributor> gpu_attr_;
};

} // namespace montauk::app
