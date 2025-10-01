#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace lsm::model {

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
  // prev for delta
  uint64_t prev_reads_completed{};
  uint64_t prev_writes_completed{};
  uint64_t prev_sectors_read{};
  uint64_t prev_sectors_written{};
  uint64_t prev_time_in_io_ms{};
  double   prev_sample_ts{};
};

struct DiskSnapshot {
  std::vector<DiskDev> devices;
  double total_read_bps{};
  double total_write_bps{};
};

} // namespace lsm::model

