#pragma once

#include <cstdint>
#include "app/SnapshotBuffers.hpp"

#ifdef MONTAUK_HAVE_URING

#include <thread>
#include <stop_token>
#include <array>
#include <string>
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
  [[nodiscard]] MetricsSnapshot read_metrics_snapshot();

  const SnapshotBuffers& buffers_;
  uint16_t port_;
  int listen_fd_{-1};
  int stop_eventfd_{-1};
  std::jthread thread_;
};

} // namespace montauk::app

#else // !MONTAUK_HAVE_URING -- stub: always-valid no-op interface

namespace montauk::app {

class MetricsServer {
public:
  MetricsServer(const SnapshotBuffers&, uint16_t) {}
  ~MetricsServer() = default;
  MetricsServer(const MetricsServer&) = delete;
  MetricsServer& operator=(const MetricsServer&) = delete;
  void start() {}
  void stop() {}
};

} // namespace montauk::app

#endif // MONTAUK_HAVE_URING
