#include "minitest.hpp"
#include "collectors/NetCollector.hpp"
#include <filesystem>
#include <fstream>
#include <thread>
#include <unistd.h>

namespace fs = std::filesystem;

static fs::path make_root_net() {
  auto root = fs::temp_directory_path() / fs::path("lsm_cpp_test_net_") / fs::path(std::to_string(::getpid()));
  fs::create_directories(root / "proc/net");
  return root;
}

TEST(net_collector_parses_and_deltas) {
  auto root = make_root_net();
  std::ofstream(root / "proc/net/dev") <<
    "Inter-|   Receive                                                |  Transmit\n"
    " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"
    "eth0: 1000 0 0 0 0 0 0 0  2000 0 0 0 0 0 0 0\n";
  setenv("LSM_PROC_ROOT", root.c_str(), 1);
  lsm::collectors::NetCollector c; lsm::model::NetSnapshot s{};
  ASSERT_TRUE(c.sample(s));
  ASSERT_TRUE(!s.interfaces.empty());
  std::this_thread::sleep_for(std::chrono::milliseconds(120));
  std::ofstream(root / "proc/net/dev") <<
    "Inter-|   Receive                                                |  Transmit\n"
    " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"
    "eth0: 11000 0 0 0 0 0 0 0  32000 0 0 0 0 0 0 0\n";
  ASSERT_TRUE(c.sample(s));
  ASSERT_TRUE(s.agg_rx_bps > 0.0 && s.agg_tx_bps > 0.0);
}
