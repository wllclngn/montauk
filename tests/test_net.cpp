// NetCollector: /proc/net/dev parsing and bps rate deltas.
#include "minitest.hpp"
#include "env_guard.hpp"
#include "collectors/NetCollector.hpp"
#include <filesystem>
#include <fstream>
#include <thread>
#include <unistd.h>

namespace fs = std::filesystem;

static fs::path make_root_net() {
  auto root = fs::temp_directory_path() / fs::path("montauk_test_net_") / fs::path(std::to_string(::getpid()));
  fs::create_directories(root / "proc/net");
  return root;
}

TEST(net_collector_parses_and_deltas) {
  auto root = make_root_net();
  std::ofstream(root / "proc/net/dev") <<
    "Inter-|   Receive                                                |  Transmit\n"
    " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"
    "eth0: 1000 0 0 0 0 0 0 0  2000 0 0 0 0 0 0 0\n";
  TempRootGuard proc_root("MONTAUK_PROC_ROOT", root.string());
  montauk::collectors::NetCollector c; montauk::model::NetSnapshot s{};
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

TEST(net_collector_counter_reset_no_spike) {
  auto root = make_root_net();
  std::ofstream(root / "proc/net/dev") <<
    "Inter-|   Receive                                                |  Transmit\n"
    " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"
    "eth0: 500000 0 0 0 0 0 0 0  600000 0 0 0 0 0 0 0\n";
  TempRootGuard proc_root("MONTAUK_PROC_ROOT", root.string());
  montauk::collectors::NetCollector c; montauk::model::NetSnapshot s{};
  ASSERT_TRUE(c.sample(s));
  std::this_thread::sleep_for(std::chrono::milliseconds(120));
  // Counters went BACKWARD (interface re-created / driver counter reset):
  // the delta must be dropped for the frame, not published as a huge spike.
  std::ofstream(root / "proc/net/dev") <<
    "Inter-|   Receive                                                |  Transmit\n"
    " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"
    "eth0: 1000 0 0 0 0 0 0 0  2000 0 0 0 0 0 0 0\n";
  ASSERT_TRUE(c.sample(s));
  ASSERT_TRUE(!s.interfaces.empty());
  ASSERT_TRUE(s.agg_rx_bps == 0.0 && s.agg_tx_bps == 0.0);
}
