// FsCollector: /proc/self/mounts parsing through the mapped reader
// (MONTAUK_PROC_ROOT sandbox) plus pseudo-fs filtering.
#include "minitest.hpp"
#include "env_guard.hpp"
#include "collectors/FsCollector.hpp"
#include <filesystem>
#include <fstream>
#include <unistd.h>

namespace fs = std::filesystem;

TEST(fs_collector_reads_mounts_with_proc_root) {
  auto root = fs::temp_directory_path() / fs::path("montauk_test_fs_") / fs::path(std::to_string(::getpid()));
  fs::create_directories(root / "proc/self");
  // Mountpoint must exist for statvfs; the fixture root itself works. A
  // pseudo-fs line and a squashfs line must be filtered out.
  std::ofstream(root / "proc/self/mounts")
      << "/dev/sda1 " << root.string() << " ext4 rw,relatime 0 0\n"
      << "proc /proc proc rw,nosuid 0 0\n"
      << "/dev/loop3 /snap/foo squashfs ro 0 0\n";
  TempRootGuard proc_root("MONTAUK_PROC_ROOT", root.string());
  montauk::collectors::FsCollector c;
  montauk::model::FsSnapshot s{};
  ASSERT_TRUE(c.sample(s));
  ASSERT_EQ(s.mounts.size(), (size_t)1);
  ASSERT_EQ(s.mounts[0].mountpoint, root.string());
  ASSERT_EQ(s.mounts[0].fstype, std::string("ext4"));
  ASSERT_TRUE(s.mounts[0].total_bytes > 0);
}
