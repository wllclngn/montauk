#include "minitest.hpp"
#include "app/Producer.hpp"
#include <filesystem>
#include <fstream>
#include <thread>
#include <atomic>
#include <unistd.h>

namespace fs = std::filesystem;

TEST(stress_producer_with_mutations) {
  auto root = fs::temp_directory_path() / fs::path("montauk_test_stress_") / fs::path(std::to_string(::getpid()));
  fs::create_directories(root / "proc/net");
  // seed files
  std::ofstream(root / "proc/meminfo") << "MemTotal:  1048576 kB\nMemAvailable:  524288 kB\n";
  std::ofstream(root / "proc/stat") << "cpu  100 0 100 1000 0 0 0 0\ncpu0 100 0 100 1000 0 0 0 0\n";
  std::ofstream(root / "proc/net/dev") <<
    "Inter-|   Receive                                                |  Transmit\n"
    " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"
    "eth0: 1000 0 0 0 0 0 0 0  2000 0 0 0 0 0 0 0\n";
  std::ofstream(root / "proc/diskstats") << "   8       0 sda 100 0 1000 0  200 0 2000 0  0  100 0\n";
  setenv("MONTAUK_PROC_ROOT", root.c_str(), 1);

  montauk::app::SnapshotBuffers buffers; montauk::app::Producer producer(buffers);
  producer.start();
  std::atomic<bool> run{true};
  std::thread mut([&]{
    uint64_t rx=2000, tx=4000, rd=150, wr=260, rdsec=2000, wrsec=2600; int iter=0;
    while (run.load()) {
      // bump cpu
      std::ofstream(root / "proc/stat") << "cpu  100 "<<iter<<" 100 " << (1100+iter) << " 0 0 0 0\ncpu0 100 "<<iter<<" 100 "<<(1100+iter)<<" 0 0 0 0\n";
      // bump net
      rx += 5000; tx += 6000;
      std::ofstream(root / "proc/net/dev") <<
        "Inter-|   Receive                                                |  Transmit\n"
        " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"
        "eth0: "<<rx<<" 0 0 0 0 0 0 0  "<<tx<<" 0 0 0 0 0 0 0\n";
      // bump disk
      rd += 10; wr += 10; rdsec += 100; wrsec += 110;
      std::ofstream(root / "proc/diskstats") << "   8       0 sda "<<rd<<" 0 "<<rdsec<<" 0  "<<wr<<" 0 "<<wrsec<<" 0  0  "<<(100+iter)<<" 0\n";
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
      iter++;
    }
  });

  std::this_thread::sleep_for(std::chrono::seconds(2));
  auto seq1 = buffers.seq();
  std::this_thread::sleep_for(std::chrono::seconds(2));
  auto seq2 = buffers.seq();
  run.store(false); mut.join();
  producer.stop();
  ASSERT_TRUE(seq2 > seq1);
}
