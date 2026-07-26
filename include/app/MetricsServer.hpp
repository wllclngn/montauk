#pragma once

#include <cstdint>
#include <array>
#include <string>
#include <algorithm>
#include <thread>
#include "app/SnapshotBuffers.hpp"
#include "app/TraceBuffers.hpp"
#include "model/Snapshot.hpp"

namespace montauk::app {

// One process's anomaly feature vector over the FULL fused population (not just
// the displayed top_procs). Order matches sublimation_anomaly_fuse's input
// columns exactly (cpu%, rss, gpu%, fault delta, thread count), so a caller --
// vector's montauk_anomalies -- can reproduce montauk's population-relative
// score by feeding this matrix to the same learn-lane primitive. JSON-only; the
// Prometheus face keeps the per-process anomaly_score gauge it already emits.
struct AnomalyFeatureRow {
  int64_t pid;
  double cpu_pct, rss_kb, gpu_util_pct, fault_delta, thread_count;
};

// Bounded snapshot for metrics serialization.
// Fixed-size top_procs array: no heap allocation during seqlock copy.
struct MetricsSnapshot {
  montauk::model::CpuSnapshot cpu;
  montauk::model::PmuSnapshot pmu;
  montauk::model::Memory mem;
  montauk::model::GpuVram vram;
  montauk::model::NetSnapshot net;
  montauk::model::DiskSnapshot disk;
  montauk::model::FsSnapshot fs;
  std::vector<montauk::model::Provider> providers;
  montauk::model::Thermal thermal;
  size_t total_processes{}, running_processes{};
  size_t state_sleeping{}, state_zombie{}, total_threads{};
  static constexpr int MAX_TOP_PROCS = 64;
  std::array<montauk::model::ProcSample, MAX_TOP_PROCS> top_procs{};
  int top_procs_count{};
  // The full population the anomaly fusion ran over (up to max_procs), so the
  // emitted score is reproducible against the same set it was judged against.
  std::vector<AnomalyFeatureRow> anomaly_features;
};

// Serialize a MetricsSnapshot into Prometheus text exposition format (version 0.0.4).
[[nodiscard]] std::string snapshot_to_prometheus(const MetricsSnapshot& snap);

// Serialize a MetricsSnapshot into one structured JSON object (see JsonSerializer.cpp).
// The `montauk --json` one-shot surface: an agent reads live system state as JSON.
[[nodiscard]] std::string snapshot_to_json(const MetricsSnapshot& snap);

// Serialize a TraceSnapshot into Prometheus text exposition format.
[[nodiscard]] std::string trace_to_prometheus(const montauk::model::TraceSnapshot& snap);

// Serialize a TraceSnapshot into one structured JSON object (see TraceRender.cpp).
[[nodiscard]] std::string trace_to_json(const montauk::model::TraceSnapshot& snap);

// Read a TraceSnapshot from TraceBuffers under the buffer's reuse guard.
[[nodiscard]] inline montauk::model::TraceSnapshot read_trace_snapshot(const TraceBuffers& buffers) {
  return buffers.read([](const montauk::model::TraceSnapshot& s) { return s; });
}

// Read a bounded MetricsSnapshot from SnapshotBuffers under the reuse guard.
[[nodiscard]] inline MetricsSnapshot read_metrics_snapshot(const SnapshotBuffers& buffers) {
  return buffers.read([](const montauk::model::Snapshot& s) {
    MetricsSnapshot ms{};
    ms.cpu = s.cpu;
    ms.pmu = s.pmu;
    ms.mem = s.mem;
    ms.vram = s.vram;
    ms.net = s.net;
    ms.disk = s.disk;
    ms.fs = s.fs;
    ms.providers = s.providers;
    ms.thermal = s.thermal;
    ms.total_processes = s.procs.total_processes;
    ms.running_processes = s.procs.running_processes;
    ms.state_sleeping = s.procs.state_sleeping;
    ms.state_zombie = s.procs.state_zombie;
    ms.total_threads = s.procs.total_threads;
    int n = std::min(static_cast<int>(s.procs.processes.size()), MetricsSnapshot::MAX_TOP_PROCS);
    std::copy_n(s.procs.processes.begin(), n, ms.top_procs.begin());
    ms.top_procs_count = n;
    // Carry the FULL fused population's features (not just the displayed top_procs)
    // so the anomaly score is reproducible against the same set it was judged on.
    ms.anomaly_features.reserve(s.procs.processes.size());
    for (const auto& p : s.procs.processes)
      ms.anomaly_features.push_back({p.pid, p.cpu_pct, static_cast<double>(p.rss_kb),
                                     p.has_gpu_util ? p.gpu_util_pct : 0.0,
                                     p.fault_delta, static_cast<double>(p.thread_count)});
    return ms;
  });
}

class MetricsServer {
public:
  MetricsServer(const SnapshotBuffers& buffers, uint16_t port,
                const TraceBuffers* trace = nullptr);
  ~MetricsServer();
  MetricsServer(const MetricsServer&) = delete;
  MetricsServer& operator=(const MetricsServer&) = delete;

  void start();
  void stop();

private:
  void run(std::stop_token st);
  void handle_client(int client_fd);

  const SnapshotBuffers& buffers_;
  const TraceBuffers* trace_{nullptr};
  uint16_t port_;
  int listen_fd_{-1};
  int stop_eventfd_{-1};
  std::jthread thread_;
};

} // namespace montauk::app
