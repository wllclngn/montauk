#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace montauk::model {

struct DiskDev {
  std::string name;
  uint64_t reads_completed{};
  uint64_t writes_completed{};
  uint64_t sectors_read{};
  uint64_t sectors_written{};
  uint64_t time_in_io_ms{};

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

