#include "minitest.hpp"
#include "collectors/MemoryCollector.hpp"
#include <filesystem>
#include <fstream>
#include <cstdlib>
#include <unistd.h>

using namespace std;
namespace fs = std::filesystem;

static fs::path make_root() {
  auto root = fs::temp_directory_path() / fs::path("montauk_test_mem_") / fs::path(std::to_string(::getpid()));
  fs::create_directories(root / "proc");
  return root;
}

TEST(memory_collector_parses_meminfo) {
  auto root = make_root();
  // Minimal meminfo
  ofstream(root / "proc/meminfo") <<
    "MemTotal:       2097152 kB\n"
    "MemAvailable:   1048576 kB\n"
    "MemFree:         524288 kB\n"
    "Buffers:         131072 kB\n"
    "Cached:          262144 kB\n";
  setenv("MONTAUK_PROC_ROOT", root.c_str(), 1);
  montauk::collectors::MemoryCollector c; montauk::model::Memory m{}; 
  ASSERT_TRUE(c.sample(m));
  ASSERT_EQ(m.total_kb, 2097152u);
  ASSERT_EQ(m.used_kb, 1048576u);
  ASSERT_TRUE(m.used_pct > 49.0 && m.used_pct < 51.0);
}
