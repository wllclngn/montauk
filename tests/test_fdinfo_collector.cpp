// FdinfoProcessCollector: per-PID GPU utilization from Intel XE fdinfo cycle
// counters.
#include "minitest.hpp"
#include "env_guard.hpp"
#include "collectors/FdinfoProcessCollector.hpp"
#include "util/Procfs.hpp"
#include <filesystem>
#include <fstream>
#include <thread>
#include <chrono>
#include <unistd.h>

using namespace std::chrono_literals;

namespace fs = std::filesystem;

// Simulate Intel XE-style fdinfo counters and validate per-PID GPU% via deltas.
TEST(fdinfo_intel_cycles_basic) {
  auto root = fs::temp_directory_path() / fs::path("montauk_test_gpu_") / fs::path(std::to_string(::getpid()));
  fs::create_directories(root / "proc/4242/fdinfo");
  auto fdpath = root / "proc/4242/fdinfo/3";
  // First snapshot: baseline counters
  {
    std::ofstream(fdpath) <<
      "drm-client-id:\t1\n"
      "drm-cycles-rcs:\t1000\n"
      "drm-total-cycles-rcs:\t10000\n";
  }
  TempRootGuard proc_root("MONTAUK_PROC_ROOT", root.string());
  montauk::collectors::FdinfoProcessCollector fdi;
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



// THE AMD ENGINE AND VRAM PATHS HAD NO COVERAGE. Only the Intel cycle path
// above was tested, so the rest of the fdinfo parser -- every AMD engine key,
// both VRAM spellings, and the malformed-value handling -- was exercised by
// nothing. Added when that parser was rewritten to drop its per-line
// allocations and its try/catch, because a rewrite of untested code is a
// rewrite whose behavior nobody can compare.
TEST(fdinfo_amd_engines_and_vram) {
  auto root = fs::temp_directory_path() / fs::path("montauk_test_gpu_amd_") /
              fs::path(std::to_string(::getpid()));
  fs::create_directories(root / "proc/4343/fdinfo");
  auto fdpath = root / "proc/4343/fdinfo/7";
  {
    std::ofstream(fdpath) <<
      "drm-client-id:\t2\n"
      "drm-engine-gfx:\t1000000\n"
      "drm-memory-vram:\t65536 KiB\n";
  }
  TempRootGuard proc_root("MONTAUK_PROC_ROOT", root.string());
  montauk::collectors::FdinfoProcessCollector fdi;
  std::unordered_map<int,int> pid_to_gpu; std::unordered_map<int,uint64_t> pid_to_mem;
  std::unordered_set<int> running;
  ASSERT_TRUE(fdi.sample(pid_to_gpu, pid_to_mem, running));
  // VRAM is a level, not a delta, so it reports on the very first sample.
  ASSERT_TRUE(pid_to_mem.find(4343) != pid_to_mem.end());
  ASSERT_EQ(pid_to_mem[4343], 65536u);
}

// A value that is not a number must leave its counter untouched rather than
// landing a garbage figure. The old parser got this from catching an exception
// out of stoull; the rewrite gets it from from_chars reporting no conversion,
// and the observable behavior has to be the same.
TEST(fdinfo_malformed_values_are_ignored) {
  auto root = fs::temp_directory_path() / fs::path("montauk_test_gpu_bad_") /
              fs::path(std::to_string(::getpid()));
  fs::create_directories(root / "proc/4444/fdinfo");
  auto fdpath = root / "proc/4444/fdinfo/2";
  {
    // CRLF line endings, a junk engine value, and a VRAM field with no digits.
    std::ofstream(fdpath) <<
      "drm-client-id:\t3\r\n"
      "drm-engine-gfx:\tnot-a-number\r\n"
      "drm-memory-vram:\tKiB\r\n"
      "a line with no colon\r\n";
  }
  TempRootGuard proc_root("MONTAUK_PROC_ROOT", root.string());
  montauk::collectors::FdinfoProcessCollector fdi;
  std::unordered_map<int,int> pid_to_gpu; std::unordered_map<int,uint64_t> pid_to_mem;
  std::unordered_set<int> running;
  // Must not crash, and must not invent a VRAM figure from an unparseable field.
  (void)fdi.sample(pid_to_gpu, pid_to_mem, running);
  ASSERT_TRUE(pid_to_mem.find(4444) == pid_to_mem.end() || pid_to_mem[4444] == 0u);
}
