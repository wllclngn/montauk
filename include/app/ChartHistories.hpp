#pragma once

#include "model/Snapshot.hpp"
#include "util/History.hpp"
#include <cstddef>
#include <mutex>

namespace montauk::app {

// Producer-owned ring buffers feeding the chart widgets. One buffer per
// charted metric; all share the same capacity (history_seconds × refresh_hz).
// In-RAM, not persisted. Mutex-guarded so the producer (writer) and render
// loop (reader) can access concurrently at 4Hz without racing.
//
// Accessed via the chart_histories() singleton so collectors, the producer,
// and ChartPanel widgets share the same instance without having to thread it
// through every constructor.
struct ChartHistories {
  mutable std::mutex mu;

  // Percentages (stored in [0, 1]): CPU total, GPU util, VRAM used,
  // GPU memory bandwidth, encoder util, decoder util, system memory used.
  montauk::util::History<float> cpu_total;
  montauk::util::History<float> gpu_util;
  montauk::util::History<float> vram_used;
  montauk::util::History<float> gpu_mem;
  montauk::util::History<float> enc;
  montauk::util::History<float> dec;
  montauk::util::History<float> mem_used;

  // NETWORK: raw bytes/sec. NetworkPanel normalizes by the window max when
  // rasterizing so RX and TX share a scale.
  montauk::util::History<float> net_rx;
  montauk::util::History<float> net_tx;

  explicit ChartHistories(std::size_t capacity);

  // Push one sample per metric from a freshly-published Snapshot.
  void push_snapshot(const montauk::model::Snapshot& s);

  // Change capacity (clears all buffers).
  void resize(std::size_t capacity);
};

// Refresh rate the producer publishes at. Matches the 250ms pub_interval
// in Producer::run(). Used to convert history_seconds → buffer capacity.
constexpr int kChartRefreshHz = 4;

// Lazy-initialized singleton. Capacity derived from [chart] history_seconds
// in the TOML config on first access.
ChartHistories& chart_histories();

} // namespace montauk::app
