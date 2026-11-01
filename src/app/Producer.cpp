#include "app/Producer.hpp"
#include "util/Log.hpp"
#include "app/ChartHistories.hpp"
#include "app/AnomalyEnrichment.hpp"
#include <unistd.h>
#include <sys/timerfd.h>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <vector>
#include "app/GpuAttributor.hpp"
#include "ui/Config.hpp"
#include "util/Churn.hpp"
#include "collectors/ProcessCollector.hpp"
#include "collectors/NetlinkProcessCollector.hpp"
#ifdef MONTAUK_HAVE_KERNEL
#include "collectors/KernelProcessCollector.hpp"
#endif

using namespace std::chrono;

namespace montauk::app {

namespace {
// Machine load-regime changepoint: the divergence between a FAST and a SLOW
// exponential moving average of the aggregate-CPU history montauk already keeps
// in ChartHistories. ~0 when steady (fast tracks slow), rising and HOLDING while
// the regime shifts (fast jumps, slow lags), decaying once slow catches the new
// level. A z-score residual (sublimation_ewma_scores) was tried first and
// rejected: A sustained shift inflates its own variance and hides itself, and
// low-variance idle jitter reads as noise -- verified backwards end to end.
// Read in the Producer thread (the sole writer) just before this frame is pushed
// (recent() sees the prior frames; the current point is folded in last); zero
// until eight frames of history have accrued.
double cpu_changepoint(const montauk::model::Snapshot& s) {
  auto hist = chart_histories().cpu_total.recent(64);  // oldest->newest fractions
  if (hist.size() < 8) return 0.0;
  const double a_fast = 0.40, a_slow = 0.06;
  double fast = hist[0], slow = hist[0];
  for (size_t i = 1; i < hist.size(); ++i) {
    fast += a_fast * (static_cast<double>(hist[i]) - fast);
    slow += a_slow * (static_cast<double>(hist[i]) - slow);
  }
  const double cur = s.cpu.usage_pct / 100.0;          // current, cpu_total's units
  fast += a_fast * (cur - fast);
  slow += a_slow * (cur - slow);
  const double div = fast - slow;
  return div < 0.0 ? -div : div;
}
}  // namespace

Producer::Producer(SnapshotBuffers& buffers) : buffers_(buffers) {
  const auto& pcfg = montauk::ui::config().process;
  int max_procs = pcfg.max_procs;
  if (max_procs < 32) max_procs = 32;
  if (max_procs > 4096) max_procs = 4096;
  int enrich_top = pcfg.enrich_top_n;
  if (enrich_top < 0) enrich_top = 0;
  if (enrich_top > max_procs) enrich_top = max_procs;
  const auto& collector = pcfg.collector;
  auto make_traditional = [&](){
    // Default to ~100ms min interval to allow quick warm-up; steady cadence remains ~1s
    return std::unique_ptr<montauk::collectors::IProcessCollector>(new montauk::collectors::ProcessCollector(100, (size_t)max_procs, (size_t)enrich_top));
  };

  if (collector == "traditional" || collector == "procfs") {
    proc_ = make_traditional();
#ifdef MONTAUK_HAVE_KERNEL
  } else if (collector == "kernel") {
    auto kpc = std::unique_ptr<montauk::collectors::IProcessCollector>(new montauk::collectors::KernelProcessCollector());
    if (kpc->init()) {
      proc_ = std::move(kpc);
    } else {
      montauk::util::log_error("Kernel module unavailable. Falling back to netlink.");
      auto netlink = std::unique_ptr<montauk::collectors::IProcessCollector>(new montauk::collectors::NetlinkProcessCollector((size_t)max_procs, (size_t)enrich_top));
      if (netlink->init()) {
        proc_ = std::move(netlink);
      } else {
        proc_ = make_traditional();
      }
    }
#endif
  } else if (collector == "netlink") {
    auto netlink = std::unique_ptr<montauk::collectors::IProcessCollector>(new montauk::collectors::NetlinkProcessCollector((size_t)max_procs, (size_t)enrich_top));
    if (!netlink->init()) {
      montauk::util::log_error("Netlink collector unavailable (need CAP_NET_ADMIN?). Falling back to traditional.");
      proc_ = make_traditional();
    } else {
      proc_ = std::move(netlink);
    }
  } else {
    // Auto-detect: try kernel module first (if built), then netlink, then traditional
#ifdef MONTAUK_HAVE_KERNEL
    auto kpc = std::unique_ptr<montauk::collectors::IProcessCollector>(new montauk::collectors::KernelProcessCollector());
    if (kpc->init()) {
      proc_ = std::move(kpc);
    } else
#endif
    {
      auto netlink = std::unique_ptr<montauk::collectors::IProcessCollector>(new montauk::collectors::NetlinkProcessCollector((size_t)max_procs, (size_t)enrich_top));
      if (netlink->init()) {
        proc_ = std::move(netlink);
      } else {
        proc_ = make_traditional();
      }
    }
  }
}

void Producer::start() {
  if (thread_.joinable()) return;
  thread_ = std::jthread([this](std::stop_token st){ run(st); });
}

void Producer::stop() {
  if (!thread_.joinable()) return;
  thread_.request_stop();
  thread_.join();
}

Producer::~Producer() { stop(); }

// Resolve the operator's selection to a concrete pid set. A pid named
// explicitly is attached whether or not it appears in the process snapshot
// (the collector's top-K cap is a display concern, not a measurement one); a
// comm substring matches against the same cmd string the TUI shows.
void Producer::refresh_pmu_targets(const montauk::model::ProcessSnapshot& procs) {
  std::vector<std::pair<int, std::string>> targets;
  for (int pid : pmu_pids_) targets.emplace_back(pid, std::string());
  if (!pmu_comm_.empty()) {
    // Never match montauk itself. The selection is a substring of the whole
    // command line, and montauk's own line contains the pattern it was given --
    // so without this the observer measures itself and reports a process the
    // operator never asked about. --trace excludes its own chain for the same
    // reason.
    const int self = static_cast<int>(::getpid());
    for (const auto& p : procs.processes) {
      if (p.pid == self) continue;
      if (p.cmd.find(pmu_comm_) == std::string::npos) continue;
      bool dup = false;
      for (const auto& t : targets) if (t.first == p.pid) { dup = true; break; }
      if (!dup) targets.emplace_back(p.pid, p.cmd);
    }
  }
  pmu_.set_process_targets(targets);
}

static uint64_t thread_cpu_ns() {
  timespec ts{};
  ::clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts);
  return static_cast<uint64_t>(ts.tv_sec) * 1000000000ull + static_cast<uint64_t>(ts.tv_nsec);
}

template <class F> void Producer::timed(Stage s, F&& f) {
  if (!stage_timing_) { f(); return; }
  const uint64_t t0 = thread_cpu_ns();
  f();
  stage_ns_[static_cast<size_t>(s)] += thread_cpu_ns() - t0;
  stage_calls_[static_cast<size_t>(s)]++;
}

std::vector<Producer::StageCost> Producer::stage_costs() const {
  static constexpr const char* names[] = {
    "cpu", "pmu", "memory", "gpu", "net", "disk", "fs", "processes", "thermal",
    "providers", "alerts", "gpu-attribution", "anomalies", "changepoint", "history",
  };
  static_assert(std::size(names) == static_cast<size_t>(Stage::Count));
  std::vector<StageCost> out;
  for (size_t i = 0; i < std::size(names); i++) out.push_back({names[i], stage_calls_[i], stage_ns_[i]});
  return out;
}

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
  auto next_pmu = steady_clock::now();
  auto next_mem = steady_clock::now();
  auto next_gpu = steady_clock::now();
  auto next_net = steady_clock::now();
  auto next_disk = steady_clock::now();
  auto next_fs = steady_clock::now();
  auto next_proc = steady_clock::now();
  auto next_therm = steady_clock::now();
  auto next_prov = steady_clock::now();
  const auto cpu_interval = 500ms;
  const auto pmu_interval = 500ms;
  const auto mem_interval = 500ms;
  const auto gpu_interval = 1000ms;
  const auto net_interval = 1000ms;
  const auto disk_interval = 1000ms;
  const auto fs_interval = 5000ms;
  const auto proc_interval = Producer::kProcessInterval;
  const auto therm_interval = 2000ms;
  // Provider scrapes hit unix sockets with a bounded timeout; keep them off
  // the fast path
  const auto prov_interval = 1000ms;
  // Publish cadence to smooth UI updates (stable rhythm independent of collector jitter)
  const auto pub_interval = 250ms;
  auto next_pub = steady_clock::now() + pub_interval;
  // Throttle heavy NVML per-process sampling to ~1s to keep UI snappy
  auto next_nvml = steady_clock::now();
  const auto nvml_interval = 1000ms;
  if (!gpu_attr_) gpu_attr_ = std::make_unique<montauk::app::GpuAttributor>(nvml_interval);

  // HOT start warm-up: take fast pre-samples so first publish has real deltas
  {
    auto& s = buffers_.begin_write();
    // Seed with an initial read for all.
    // Return values intentionally ignored: collectors may fail transiently
    // (e.g., /proc unavailable), but we continue with stale data for resilience.
    if (proc_) { s.collector_name = proc_->name(); }
    (void)cpu_.sample(s.cpu);
    if (pmu_enabled_) (void)pmu_.sample(s.pmu);
    (void)mem_.sample(s.mem);
    (void)gpu_.sample(s.vram);
    (void)net_.sample(s.net);
    (void)disk_.sample(s.disk);
    (void)fs_.sample(s.fs);
    (void)providers_.sample(s.providers);
    if (proc_) { (void)proc_->sample(s.procs); process_samples_.fetch_add(1, std::memory_order_release); }
    // Attach before the first PMU read so the warm-up interval is already
    // attributed rather than discarded.
    if (pmu_proc_enabled_) { refresh_pmu_targets(s.procs); (void)pmu_.sample(s.pmu); }
    (void)thermal_.sample(s.thermal);

    // Time budget for warm-up (~180ms max)
    auto warm_start = steady_clock::now();
    auto warm_deadline = warm_start + 200ms;

    // CPU + Processes: a few tick-spaced reads to establish deltas
    for (int i = 0; i < 3 && !st.stop_requested(); ++i) {
      auto now = steady_clock::now(); if (now >= warm_deadline) break;
      auto rem = duration_cast<milliseconds>(warm_deadline - now);
      auto nap = milliseconds(std::min<int>(tick_ms, static_cast<int>(rem.count())));
      if (nap.count() > 0) std::this_thread::sleep_for(nap);
      (void)cpu_.sample(s.cpu);
      if (proc_) { (void)proc_->sample(s.procs); process_samples_.fetch_add(1, std::memory_order_release); }
    }

    // Net + Disk: short spaced reads for non-zero bps/util
    for (int i = 0; i < 2 && !st.stop_requested(); ++i) {
      auto now = steady_clock::now(); if (now >= warm_deadline) break;
      auto rem = duration_cast<milliseconds>(warm_deadline - now);
      auto nap = milliseconds(std::min<int>(60, std::max<int>(10, static_cast<int>(rem.count()))));
      if (nap.count() > 0) std::this_thread::sleep_for(nap);
      (void)net_.sample(s.net);
      (void)disk_.sample(s.disk);
    }

    // Re-sample memory/thermal/gpu once (non-rate or slow-changing)
    (void)mem_.sample(s.mem);
    (void)thermal_.sample(s.thermal);
    (void)gpu_.sample(s.vram);
    
    // Enrich GPU attribution once at startup for stable NVML display
    if (gpu_attr_) gpu_attr_->enrich(s);

    // Generate alerts and publish once — first visible frame uses this snapshot
    {
      auto a = alerts_.evaluate(s);
      s.alerts.clear();
      for (auto& it : a) s.alerts.push_back(montauk::model::AlertItem{it.severity, it.message});
    }
    montauk::app::enrich_anomalies(s.procs, anomaly_prev_faults_, anomaly_prev_ctxsw_);
    s.cpu.changepoint_score = cpu_changepoint(s);  // before push: reads prior frames
    chart_histories().push_snapshot(s);
    buffers_.publish();
    buffers_.carry_forward();
  }

  // Main collection loop. Sample return values intentionally ignored for resilience.
  //
  // The anomaly fusion reads fault and context-switch DELTAS against the
  // previous process sample, so it runs on a publish that carries a fresh one
  // and on no other: Run again over the same sample, every delta is zero, the
  // two axes drop out as constant, and the scores alternate between a six-axis
  // and a four-axis ranking. The carried buffer keeps the last scores.
  bool procs_fresh = false;
  // THE WAIT IS A DEADLINE, and the kernel has an object for one: A timerfd on
  // CLOCK_MONOTONIC (steady_clock's clock) armed at the absolute time the next
  // collector is due, so a late wake does not push every later one back the
  // way a relative sleep does. A box that will not make one sleeps as before.
  const int tfd = ::timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
  while (!st.stop_requested()) {
    auto now = steady_clock::now();
    bool ran = false;
    auto& s = buffers_.begin_write();
    if (now >= next_cpu) { timed(Stage::Cpu, [&]{ (void)cpu_.sample(s.cpu); }); next_cpu = now + cpu_interval; ran = true; }
    if (now >= next_pmu) {
      // Re-resolve the per-process selection before every read, so a workload
      // that starts (or restarts) mid-run is picked up rather than needing
      // montauk to have been launched after it.
      if (pmu_enabled_ || pmu_proc_enabled_) {
        timed(Stage::Pmu, [&]{
          if (pmu_proc_enabled_) refresh_pmu_targets(s.procs);
          (void)pmu_.sample(s.pmu);
        });
        ran = true;
      }
      next_pmu = now + pmu_interval;
    }
    if (now >= next_mem) { timed(Stage::Memory, [&]{ (void)mem_.sample(s.mem); }); next_mem = now + mem_interval; ran = true; }
    if (now >= next_gpu) { timed(Stage::Gpu, [&]{ (void)gpu_.sample(s.vram); }); next_gpu = now + gpu_interval; ran = true; }
    if (now >= next_net) { timed(Stage::Net, [&]{ (void)net_.sample(s.net); }); next_net = now + net_interval; ran = true; }
    if (now >= next_disk){ timed(Stage::Disk, [&]{ (void)disk_.sample(s.disk); }); next_disk = now + disk_interval; ran = true; }
    if (now >= next_fs)  { timed(Stage::Fs, [&]{ (void)fs_.sample(s.fs); });     next_fs  = now + fs_interval; ran = true; }
    if (now >= next_proc){ if (proc_) { timed(Stage::Processes, [&]{ (void)proc_->sample(s.procs); }); process_samples_.fetch_add(1, std::memory_order_release); procs_fresh = true; } next_proc = now + proc_interval; ran = true; }
    if (now >= next_therm){ timed(Stage::Thermal, [&]{ (void)thermal_.sample(s.thermal); }); next_therm = now + therm_interval; ran = true; }
    if (now >= next_prov){ timed(Stage::Providers, [&]{ (void)providers_.sample(s.providers); }); next_prov = now + prov_interval; ran = true; }
    bool time_to_publish = false;
    if (now >= next_pub) { time_to_publish = true; next_pub = now + pub_interval; }
    bool nvml_ran = false;
    if (now >= next_nvml) nvml_ran = true;
    if (ran || time_to_publish || nvml_ran) {
      if (proc_) { s.collector_name = proc_->name(); }
      timed(Stage::Alerts, [&]{
        auto a = alerts_.evaluate(s);
        s.alerts.clear();
        for (auto& it : a) s.alerts.push_back(montauk::model::AlertItem{it.severity, it.message});
      });
      // Populate churn diagnostics for SYSTEM sticky line
      s.churn.recent_2s_events = montauk::util::count_recent_ms(2000);
      s.churn.recent_2s_proc   = montauk::util::count_recent_kind_ms(montauk::util::ChurnKind::Proc, 2000);
      s.churn.recent_2s_sys    = montauk::util::count_recent_kind_ms(montauk::util::ChurnKind::Sysfs, 2000);
      // Enrich per-process GPU utilization using NVML (best effort, throttled)
      if (nvml_ran) {
        // Attribute per-process GPU% across NVML/fdinfo backends
        timed(Stage::GpuAttribution, [&]{ gpu_attr_->enrich(s); });
        next_nvml = now + nvml_interval;
      }
      if (procs_fresh) {
        timed(Stage::Anomalies, [&]{ montauk::app::enrich_anomalies(s.procs, anomaly_prev_faults_, anomaly_prev_ctxsw_); });
        procs_fresh = false;
      }
      timed(Stage::Changepoint, [&]{ s.cpu.changepoint_score = cpu_changepoint(s); });  // before push: reads prior frames
      timed(Stage::History, [&]{ chart_histories().push_snapshot(s); });
      buffers_.publish();
      buffers_.carry_forward();
    }
    // Wait until the earliest next_due or next_pub, held to 20..100 ms from now.
    const auto next_due = std::min({next_cpu, next_pmu, next_mem, next_gpu, next_net, next_disk, next_proc, next_therm, next_prov, next_pub});
    const auto at = steady_clock::now();
    const auto wake = std::clamp(next_due, at + 20ms, at + 100ms);
    if (tfd >= 0) {
      const auto ns = duration_cast<nanoseconds>(wake.time_since_epoch()).count();
      itimerspec its{};
      its.it_value.tv_sec = ns / 1000000000;
      its.it_value.tv_nsec = ns % 1000000000;
      uint64_t expirations = 0;
      if (::timerfd_settime(tfd, TFD_TIMER_ABSTIME, &its, nullptr) == 0)
        while (::read(tfd, &expirations, sizeof expirations) < 0 && errno == EINTR) {}
      else std::this_thread::sleep_until(wake);
    } else {
      std::this_thread::sleep_until(wake);
    }
  }
  if (tfd >= 0) ::close(tfd);
  // gpu_attr_ cleanup handled by unique_ptr destructor
}


} // namespace montauk::app
