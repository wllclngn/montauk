#include "minitest.hpp"
#include "collectors/CpuCollector.hpp"
#include <filesystem>
#include <fstream>
#include <unistd.h>

namespace fs = std::filesystem;

static fs::path make_root_cpu() {
  auto root = fs::temp_directory_path() / fs::path("montauk_test_cpu_") / fs::path(std::to_string(::getpid()));
  fs::create_directories(root / "proc");
  return root;
}

TEST(cpu_collector_delta_usage) {
  auto root = make_root_cpu();
  // First sample
  std::ofstream(root / "proc/stat") << "cpu  100 0 100 1000 0 0 0 0\n"
                                        "cpu0 100 0 100 1000 0 0 0 0\n";
  setenv("MONTAUK_PROC_ROOT", root.c_str(), 1);
  montauk::collectors::CpuCollector c; montauk::model::CpuSnapshot s{};
  ASSERT_TRUE(c.sample(s));
  // Second sample with more work and total
  std::ofstream(root / "proc/stat") << "cpu  150 0 150 1100 0 0 0 0\n"
                                        "cpu0 150 0 150 1100 0 0 0 0\n";
  ASSERT_TRUE(c.sample(s));
  ASSERT_TRUE(s.usage_pct > 40.0 && s.usage_pct < 60.0);
}

