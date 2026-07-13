// GpuCollector: NVIDIA /proc and AMD sysfs fallback parsers.
#include "minitest.hpp"
#include "env_guard.hpp"
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
  TempRootGuard proc_root("MONTAUK_PROC_ROOT", root.string());
  TempRootGuard gpu_disable("MONTAUK_GPU_DISABLE_NATIVE", "1");  // isolate the proc parser from a live NVML GPU
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
  TempRootGuard sys_root("MONTAUK_SYS_ROOT", root.string());
  TempRootGuard gpu_disable("MONTAUK_GPU_DISABLE_NATIVE", "1");  // isolate the sysfs parser from a live NVML GPU
  // Point the proc root at this sandbox (which has no proc/driver/nvidia) so the
  // NVIDIA proc reader finds nothing and the AMD sysfs reader is what answers.
  TempRootGuard proc_root("MONTAUK_PROC_ROOT", root.string());
  montauk::collectors::GpuCollector c; montauk::model::GpuVram v{};
  ASSERT_TRUE(c.sample(v));
  ASSERT_EQ(v.total_mb, 512u);
  ASSERT_EQ(v.used_mb, 128u);
}
