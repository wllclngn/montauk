// Producer: end-to-end snapshot pipeline (collectors -> SnapshotBuffers).
#include "minitest.hpp"
#include "env_guard.hpp"
#include "app/Producer.hpp"
#include <filesystem>
#include <fstream>
#include <thread>
#include <unistd.h>

namespace fs = std::filesystem;

static fs::path make_root_prod() {
  auto root = fs::temp_directory_path() / fs::path("montauk_test_prod_") / fs::path(std::to_string(::getpid()));
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

// Wait for the published sequence to pass `above`, bounded by a deadline. A
// fixed sleep asserts how fast a loaded box schedules the producer, not whether
// it publishes.
static uint64_t wait_seq_above(montauk::app::SnapshotBuffers& b, uint64_t above) {
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
  while (b.seq() <= above && std::chrono::steady_clock::now() < deadline)
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  return b.seq();
}

TEST(producer_publishes_snapshots) {
  auto root = make_root_prod();
  TempRootGuard proc_root("MONTAUK_PROC_ROOT", root.string());
  // Producer constructs a real GpuCollector; without this it reaches live
  // NVML/nvidia-smi on any box with a GPU, making the test non-deterministic.
  TempRootGuard gpu_disable("MONTAUK_GPU_DISABLE_NATIVE", "1");
  montauk::app::SnapshotBuffers buffers; montauk::app::Producer producer(buffers);
  producer.start();
  auto seq1 = wait_seq_above(buffers, 0);
  ASSERT_TRUE(seq1 > 0);
  // mutate fixtures to let deltas occur
  std::ofstream(root / "proc/stat") << "cpu  150 0 150 1100 0 0 0 0\n"
                                        "cpu0 150 0 150 1100 0 0 0 0\n";
  std::ofstream(root / "proc/net/dev") <<
    "Inter-|   Receive                                                |  Transmit\n"
    " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"
    "eth0: 11000 0 0 0 0 0 0 0  22000 0 0 0 0 0 0 0\n";
  std::ofstream(root / "proc/diskstats") << "   8       0 sda 150 0 2000 0  260 0 2600 0  0  160 0\n";
  auto seq2 = wait_seq_above(buffers, seq1);
  ASSERT_TRUE(seq2 > seq1);
  producer.stop();
}

