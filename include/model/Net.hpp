#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace lsm::model {

struct NetIf {
  std::string name;
  uint64_t rx_bytes{};
  uint64_t tx_bytes{};
  double rx_bps{};
  double tx_bps{};
  double last_ts{}; // seconds
};

struct NetSnapshot {
  std::vector<NetIf> interfaces;
  double agg_rx_bps{};
  double agg_tx_bps{};
};

} // namespace lsm::model

