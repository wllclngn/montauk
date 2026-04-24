#include "app/ChartHistories.hpp"
#include "ui/Config.hpp"

namespace montauk::app {

ChartHistories::ChartHistories(std::size_t capacity)
    : cpu_total(capacity),
      gpu_util(capacity),
      vram_used(capacity),
      gpu_mem(capacity),
      enc(capacity),
      dec(capacity),
      mem_used(capacity),
      net_rx(capacity),
      net_tx(capacity) {}

void ChartHistories::resize(std::size_t capacity) {
  std::lock_guard<std::mutex> lock(mu);
  cpu_total.resize(capacity);
  gpu_util.resize(capacity);
  vram_used.resize(capacity);
  gpu_mem.resize(capacity);
  enc.resize(capacity);
  dec.resize(capacity);
  mem_used.resize(capacity);
  net_rx.resize(capacity);
  net_tx.resize(capacity);
}

void ChartHistories::push_snapshot(const montauk::model::Snapshot& s) {
  std::lock_guard<std::mutex> lock(mu);
  cpu_total.push(static_cast<float>(s.cpu.usage_pct / 100.0));
  gpu_util.push(static_cast<float>(s.vram.gpu_util_pct / 100.0));
  vram_used.push(static_cast<float>(s.vram.used_pct / 100.0));
  gpu_mem.push(static_cast<float>(s.vram.mem_util_pct / 100.0));
  enc.push(static_cast<float>(s.vram.enc_util_pct / 100.0));
  dec.push(static_cast<float>(s.vram.dec_util_pct / 100.0));
  mem_used.push(static_cast<float>(s.mem.used_pct / 100.0));
  net_rx.push(static_cast<float>(s.net.agg_rx_bps));
  net_tx.push(static_cast<float>(s.net.agg_tx_bps));
}

ChartHistories& chart_histories() {
  static ChartHistories inst = []() {
    int sec = montauk::ui::config().chart.history_seconds;
    if (sec < 1) sec = 60;
    if (sec > 3600) sec = 3600;
    return ChartHistories(static_cast<std::size_t>(sec * kChartRefreshHz));
  }();
  return inst;
}

} // namespace montauk::app
