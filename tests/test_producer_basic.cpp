#include "minitest.hpp"
#include "app/Producer.hpp"
#include <filesystem>
#include <fstream>
#include <thread>
#include <unistd.h>

namespace fs = std::filesystem;

static fs::path make_root_prod() {
  auto root = fs::temp_directory_path() / fs::path("lsm_cpp_test_prod_") / fs::path(std::to_string(::getpid()));
  fs::create_directories(root / "proc/net");
  // meminfo
  std::ofstream(root / "proc/meminfo") <<
    "MemTotal:       1048576 kB\n"
    "MemAvailable:    524288 kB\n";
  // stat (two samples OK; producer will progress)
  std::ofstream(root / "proc/stat") << "cpu  100 0 100 1000 0 0 0 0\n"
                                        "cpu0 100 0 100 1000 0 0 0 0\n";
  // net
  std::ofstream(root / "proc/net/dev") <<
    "Inter-|   Receive                                                |  Transmit\n"
    " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"
    "eth0: 1000 0 0 0 0 0 0 0  2000 0 0 0 0 0 0 0\n";
  // diskstats
  std::ofstream(root / "proc/diskstats") << "   8       0 sda 100 0 1000 0  200 0 2000 0  0  100 0\n";
  return root;
}

TEST(producer_publishes_snapshots) {
  auto root = make_root_prod();
  setenv("LSM_PROC_ROOT", root.c_str(), 1);
  lsm::app::SnapshotBuffers buffers; lsm::app::Producer producer(buffers);
  producer.start();
  std::this_thread::sleep_for(std::chrono::milliseconds(600));
  auto seq1 = buffers.seq();
  ASSERT_TRUE(seq1 > 0);
  // mutate fixtures to let deltas occur
  std::ofstream(root / "proc/stat") << "cpu  150 0 150 1100 0 0 0 0\n"
                                        "cpu0 150 0 150 1100 0 0 0 0\n";
  std::ofstream(root / "proc/net/dev") <<
    "Inter-|   Receive                                                |  Transmit\n"
    " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"
    "eth0: 11000 0 0 0 0 0 0 0  22000 0 0 0 0 0 0 0\n";
  std::ofstream(root / "proc/diskstats") << "   8       0 sda 150 0 2000 0  260 0 2600 0  0  160 0\n";
  std::this_thread::sleep_for(std::chrono::milliseconds(800));
  auto seq2 = buffers.seq();
  ASSERT_TRUE(seq2 > seq1);
  producer.stop();
}

