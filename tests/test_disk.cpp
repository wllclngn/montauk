#include "minitest.hpp"
#include "collectors/DiskCollector.hpp"
#include <filesystem>
#include <fstream>
#include <thread>
#include <unistd.h>

namespace fs = std::filesystem;

static fs::path make_root_disk() {
  auto root = fs::temp_directory_path() / fs::path("montauk_test_disk_") / fs::path(std::to_string(::getpid()));
  fs::create_directories(root / "proc");
  return root;
}

TEST(disk_collector_parses_and_deltas) {
  auto root = make_root_disk();
  std::ofstream(root / "proc/diskstats") << "   8       0 sda 100 0 1000 0  200 0 2000 0  0  100 0\n";
  setenv("MONTAUK_PROC_ROOT", root.c_str(), 1);
  montauk::collectors::DiskCollector c; montauk::model::DiskSnapshot s{};
  ASSERT_TRUE(c.sample(s));
  std::this_thread::sleep_for(std::chrono::milliseconds(120));
  std::ofstream(root / "proc/diskstats") << "   8       0 sda 150 0 2000 0  260 0 2600 0  0  160 0\n";
  ASSERT_TRUE(c.sample(s));
  ASSERT_TRUE(s.total_read_bps > 0.0 || s.total_write_bps > 0.0);
}

TEST(disk_collector_util_percent) {
  namespace fs = std::filesystem;
  auto root = fs::temp_directory_path() / fs::path("montauk_test_disk_util_") / fs::path(std::to_string(::getpid()));
  fs::create_directories(root / "proc");
  // initial sample with low time in io
  std::ofstream(root / "proc/diskstats") << "   8       0 sda 100 0 1000 0  200 0 2000 0  0  100 0\n";
  setenv("MONTAUK_PROC_ROOT", root.c_str(), 1);
  montauk::collectors::DiskCollector c; montauk::model::DiskSnapshot s{};
  ASSERT_TRUE(c.sample(s));
  // second sample with increased sectors and time in IO
  std::this_thread::sleep_for(std::chrono::milliseconds(150));
  std::ofstream(root / "proc/diskstats") << "   8       0 sda 150 0 2000 0  260 0 2600 0  0  300 0\n"; // tios increased by 200ms
  ASSERT_TRUE(c.sample(s));
  // util% should be > 0 and <= 100
  bool any = false;
  for (auto& d : s.devices) { if (d.name == "sda") { any = true; ASSERT_TRUE(d.util_pct >= 0.0 && d.util_pct <= 100.0); ASSERT_TRUE(d.util_pct > 0.0); } }
  ASSERT_TRUE(any);
}
