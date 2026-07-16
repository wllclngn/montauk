#include "collectors/FsCollector.hpp"

#include <sys/statvfs.h>
#include <fstream>
#include <sstream>
#include <unordered_set>
#include <utility>

#include "sublimation_order.hpp"  // after std headers (c23_compat unreachable macro)

namespace montauk::collectors {

static bool is_pseudo_fs(const std::string& fstype) {
  static const std::unordered_set<std::string> bad = {
    "proc","sysfs","devtmpfs","devpts","tmpfs","cgroup","cgroup2","pstore","securityfs",
    "bpf","autofs","mqueue","hugetlbfs","configfs","debugfs","tracefs","nsfs","ramfs",
    "fusectl","fuse.portal","overlay"
  };
  return bad.count(fstype) != 0;
}

static uint64_t to_bytes(unsigned long long v) { return static_cast<uint64_t>(v); }

bool FsCollector::sample(montauk::model::FsSnapshot& out) {
  out.mounts.clear();
  std::ifstream f("/proc/self/mounts");
  if (!f) return false;
  std::string line;
  while (std::getline(f, line)) {
    if (line.empty()) continue;
    std::istringstream ls(line);
    std::string device, mountpoint, fstype, opts; int dump=0, passno=0;
    if (!(ls >> device >> mountpoint >> fstype >> opts >> dump >> passno)) continue;
    if (is_pseudo_fs(fstype)) continue;
    // Skip read-only special mounts like snap squashfs etc.
    if (fstype == "squashfs") continue;

    struct statvfs vfs{};
    if (::statvfs(mountpoint.c_str(), &vfs) != 0) continue;
    uint64_t total = to_bytes(vfs.f_blocks) * vfs.f_frsize;
    uint64_t avail = to_bytes(vfs.f_bavail) * vfs.f_frsize;
    uint64_t used = (total > avail) ? (total - avail) : 0ULL;
    double used_pct = (total > 0) ? (100.0 * (double)used / (double)total) : 0.0;

    montauk::model::FsMount m;
    m.device = device;
    m.mountpoint = mountpoint;
    m.fstype = fstype;
    m.total_bytes = total;
    m.avail_bytes = avail;
    m.used_bytes = used;
    m.used_pct = used_pct;
    out.mounts.push_back(std::move(m));
  }
  // Sort by used% desc, then used bytes desc: LSD-composed stable index
  // sorts, minor key (used bytes) first, major key (used%) second.
  sublimation_order_u64(out.mounts, true,
                        [](const montauk::model::FsMount& m) { return m.used_bytes; });
  sublimation_order_f64(out.mounts, true,
                        [](const montauk::model::FsMount& m) { return m.used_pct; });
  return true;
}

} // namespace montauk::collectors

