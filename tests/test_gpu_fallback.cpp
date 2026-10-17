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
  std::ofstream(root / "proc/driver/nvidia/gpus/0000:01:00.0/information") <<
      "Model: \t\t NVIDIA GeForce RTX 3080\nIRQ:   140\n";
  TempRootGuard proc_root("MONTAUK_PROC_ROOT", root.string());
  TempRootGuard gpu_disable("MONTAUK_GPU_DISABLE_NATIVE", "1");  // isolate the proc parser from a live NVML GPU
  montauk::collectors::GpuCollector c; montauk::model::GpuVram v{};
  ASSERT_TRUE(c.sample(v));
  ASSERT_EQ(v.total_mb, 4096u);
  ASSERT_EQ(v.used_mb, 1024u);
  ASSERT_EQ(v.devices.size(), 1u);
  ASSERT_EQ(v.devices[0].name, std::string("NVIDIA GeForce RTX 3080"));
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

// The rest of one card's pass: busy percent, hwmon power, and each labelled
// temperature with its threshold, read through the device's hwmon link.
TEST(gpu_collector_amd_sysfs_busy_power_temps) {
  auto root = fs::temp_directory_path() / fs::path("montauk_test_gpu_amd2_") / fs::path(std::to_string(::getpid()));
  const auto dev = root / "sys/class/drm/card0/device";
  const auto hw = dev / "hwmon/hwmon3";
  fs::create_directories(hw);
  fs::create_directories(root / "sys/class/drm/card0-DP-1");
  std::ofstream(dev / "mem_info_vram_total") << (1024ull * 1024ull * 1024ull);
  std::ofstream(dev / "mem_info_vram_used") << (256ull * 1024ull * 1024ull);
  std::ofstream(dev / "gpu_busy_percent") << "37\n";
  std::ofstream(dev / "uevent") << "DRIVER=amdgpu\nPCI_ID=1002:73BF\n";
  std::ofstream(hw / "power1_average") << "45500000\n";
  std::ofstream(hw / "temp1_input") << "51000\n";
  std::ofstream(hw / "temp1_label") << "edge\n";
  std::ofstream(hw / "temp1_crit") << "100000\n";
  std::ofstream(hw / "temp2_input") << "63000\n";
  std::ofstream(hw / "temp2_label") << "junction\n";
  std::ofstream(hw / "temp2_crit") << "110000\n";
  std::ofstream(hw / "temp3_input") << "58000\n";
  std::ofstream(hw / "temp3_label") << "mem\n";
  std::ofstream(hw / "temp3_emergency") << "105000\n";
  TempRootGuard sys_root("MONTAUK_SYS_ROOT", root.string());
  TempRootGuard gpu_disable("MONTAUK_GPU_DISABLE_NATIVE", "1");
  TempRootGuard proc_root("MONTAUK_PROC_ROOT", root.string());
  montauk::collectors::GpuCollector c; montauk::model::GpuVram v{};
  ASSERT_TRUE(c.sample(v));
  ASSERT_EQ(v.total_mb, 1024u);
  ASSERT_EQ(v.devices.size(), 1u);
  ASSERT_EQ(v.devices[0].name, std::string("amdgpu (1002:73BF)"));
  ASSERT_TRUE(v.has_util);
  ASSERT_EQ(v.gpu_util_pct, 37.0);
  ASSERT_TRUE(v.has_power);
  ASSERT_EQ(v.power_draw_w, 45.5);
  const auto& d = v.devices[0];
  ASSERT_TRUE(d.has_temp_edge && d.has_temp_hotspot && d.has_temp_mem);
  ASSERT_EQ(d.temp_edge_c, 51.0);
  ASSERT_EQ(d.temp_hotspot_c, 63.0);
  ASSERT_EQ(d.temp_mem_c, 58.0);
  ASSERT_TRUE(d.has_thr_edge && d.has_thr_hotspot && d.has_thr_mem);
  ASSERT_EQ(d.thr_edge_c, 100.0);
  ASSERT_EQ(d.thr_hotspot_c, 110.0);
  ASSERT_EQ(d.thr_mem_c, 105.0);
  fs::remove_all(root);
}
