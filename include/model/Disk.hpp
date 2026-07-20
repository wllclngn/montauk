#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace montauk::model {

struct DiskDev {
  std::string name;

  // calculated
  double read_bps{};
  double write_bps{};
  double util_pct{};
};

struct DiskSnapshot {
  std::vector<DiskDev> devices;
  double total_read_bps{};
  double total_write_bps{};
};

} // namespace montauk::model

