#include "minitest.hpp"
#include "collectors/FdinfoProcessCollector.hpp"
#include "util/Procfs.hpp"
#include <filesystem>
#include <fstream>
#include <thread>
#include <chrono>

using namespace std::chrono_literals;

namespace fs = std::filesystem;

// Simulate Intel XE-style fdinfo counters and validate per-PID GPU% via deltas.
TEST(fdinfo_intel_cycles_basic) {
  auto root = fs::temp_directory_path() / fs::path("lsm_cpp_test_gpu_") / fs::path(std::to_string(::getpid()));
  fs::create_directories(root / "proc/4242/fdinfo");
  auto fdpath = root / "proc/4242/fdinfo/3";
  // First snapshot: baseline counters
  {
    std::ofstream(fdpath) <<
      "drm-client-id:\t1\n"
      "drm-cycles-rcs:\t1000\n"
      "drm-total-cycles-rcs:\t10000\n";
  }
  setenv("LSM_PROC_ROOT", root.c_str(), 1);
  lsm::collectors::FdinfoProcessCollector fdi;
  std::unordered_map<int,int> pid_to_gpu; std::unordered_map<int,uint64_t> pid_to_mem; std::unordered_set<int> running;
  // First call establishes baseline; no utilization yet
  ASSERT_TRUE(fdi.sample(pid_to_gpu, pid_to_mem, running));
  ASSERT_TRUE(pid_to_gpu.empty());
  // Second snapshot: +1000 cycles on +10000 total cycles -> 10%
  std::this_thread::sleep_for(10ms);
  {
    std::ofstream(fdpath) <<
      "drm-client-id:\t1\n"
      "drm-cycles-rcs:\t2000\n"
      "drm-total-cycles-rcs:\t20000\n";
  }
  ASSERT_TRUE(fdi.sample(pid_to_gpu, pid_to_mem, running));
  ASSERT_TRUE(pid_to_gpu.find(4242) != pid_to_gpu.end());
  int util = pid_to_gpu[4242];
  ASSERT_TRUE(util >= 9 && util <= 11);
}

