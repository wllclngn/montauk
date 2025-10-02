#include "minitest.hpp"
#include "collectors/GpuCollector.hpp"
#include <filesystem>
#include <fstream>
#include <unistd.h>

namespace fs = std::filesystem;

TEST(gpu_collector_nvidia_proc_fallback) {
  auto root = fs::temp_directory_path() / fs::path("montauk_test_gpu_") / fs::path(std::to_string(::getpid()));
  fs::create_directories(root / "proc/driver/nvidia/gpus/0000:01:00.0");
  std::ofstream(root / "proc/driver/nvidia/gpus/0000:01:00.0/fb_memory_usage") <<
      "Total                       : 4096 MiB\n"
      "Used                        : 1024 MiB\n";
  setenv("MONTAUK_PROC_ROOT", root.c_str(), 1);
  montauk::collectors::GpuCollector c; montauk::model::GpuVram v{};
  ASSERT_TRUE(c.sample(v));
  ASSERT_EQ(v.total_mb, 4096u);
  ASSERT_EQ(v.used_mb, 1024u);
}

TEST(gpu_collector_amd_sysfs_fallback) {
  namespace fs = std::filesystem;
  auto root = fs::temp_directory_path() / fs::path("montauk_test_gpu_amd_") / fs::path(std::to_string(::getpid()));
  fs::create_directories(root / "sys/class/drm/card0/device");
  std::ofstream(root / "sys/class/drm/card0/device/mem_info_vram_total") << (512ull * 1024ull * 1024ull);
  std::ofstream(root / "sys/class/drm/card0/device/mem_info_vram_used") << (128ull * 1024ull * 1024ull);
  setenv("MONTAUK_SYS_ROOT", root.c_str(), 1);
  montauk::collectors::GpuCollector c; montauk::model::GpuVram v{};
  ASSERT_TRUE(c.sample(v));
  ASSERT_EQ(v.total_mb, 512u);
  ASSERT_EQ(v.used_mb, 128u);
}
