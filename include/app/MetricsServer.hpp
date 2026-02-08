#pragma once

#include <cstdint>
#include <array>
#include <string>
#include <algorithm>
#include <thread>
#include "app/SnapshotBuffers.hpp"
#include "model/Snapshot.hpp"

namespace montauk::app {

// Bounded snapshot for metrics serialization.
// Fixed-size top_procs array: no heap allocation during seqlock copy.
struct MetricsSnapshot {
  montauk::model::CpuSnapshot cpu;
  montauk::model::Memory mem;
  montauk::model::GpuVram vram;
  montauk::model::NetSnapshot net;
  montauk::model::DiskSnapshot disk;
  montauk::model::FsSnapshot fs;
  montauk::model::Thermal thermal;
  size_t total_processes{}, running_processes{};
  size_t state_sleeping{}, state_zombie{}, total_threads{};
  static constexpr int MAX_TOP_PROCS = 64;
  std::array<montauk::model::ProcSample, MAX_TOP_PROCS> top_procs{};
  int top_procs_count{};
};

// Serialize a MetricsSnapshot into Prometheus text exposition format (version 0.0.4).
[[nodiscard]] std::string snapshot_to_prometheus(const MetricsSnapshot& snap);

// Read a bounded MetricsSnapshot from SnapshotBuffers via seqlock.
[[nodiscard]] inline MetricsSnapshot read_metrics_snapshot(const SnapshotBuffers& buffers) {
  MetricsSnapshot ms{};
  uint64_t seq_before, seq_after;
  do {
    seq_before = buffers.seq();
    const auto& s = buffers.front();
    ms.cpu = s.cpu;
    ms.mem = s.mem;
    ms.vram = s.vram;
    ms.net = s.net;
    ms.disk = s.disk;
    ms.fs = s.fs;
    ms.thermal = s.thermal;
    ms.total_processes = s.procs.total_processes;
    ms.running_processes = s.procs.running_processes;
    ms.state_sleeping = s.procs.state_sleeping;
    ms.state_zombie = s.procs.state_zombie;
    ms.total_threads = s.procs.total_threads;
    int n = std::min(static_cast<int>(s.procs.processes.size()), MetricsSnapshot::MAX_TOP_PROCS);
    std::copy_n(s.procs.processes.begin(), n, ms.top_procs.begin());
    ms.top_procs_count = n;
    seq_after = buffers.seq();
  } while (seq_before != seq_after);
  return ms;
}

class MetricsServer {
public:
  MetricsServer(const SnapshotBuffers& buffers, uint16_t port);
  ~MetricsServer();
  MetricsServer(const MetricsServer&) = delete;
  MetricsServer& operator=(const MetricsServer&) = delete;

  void start();
  void stop();

private:
  void run(std::stop_token st);
  void handle_client(int client_fd);

  const SnapshotBuffers& buffers_;
  uint16_t port_;
  int listen_fd_{-1};
  int stop_eventfd_{-1};
  std::jthread thread_;
};

} // namespace montauk::app
