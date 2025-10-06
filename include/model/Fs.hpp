#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace montauk::model {

struct FsMount {
  std::string device;      // e.g., /dev/nvme0n1p2 or UUID=...
  std::string mountpoint;  // e.g., /
  std::string fstype;      // e.g., ext4, xfs, btrfs, f2fs
  uint64_t total_bytes{};
  uint64_t used_bytes{};
  uint64_t avail_bytes{};
  double   used_pct{};     // 0..100
};

struct FsSnapshot {
  std::vector<FsMount> mounts; // filtered, user-visible filesystems
};

} // namespace montauk::model

