// GpuCollector: nvidia-smi device-level fallback (injected mock binary).
#include "minitest.hpp"
#include "env_guard.hpp"
#include "collectors/GpuCollector.hpp"
#include <filesystem>
#include <fstream>
#include <unistd.h>
#include <sys/stat.h>

namespace fs = std::filesystem;

// Simulate nvidia-smi device-level output to test fallback
TEST(gpu_collector_nvidia_smi_device_fallback) {
  auto root = fs::temp_directory_path() / fs::path("montauk_test_smi_") / fs::path(std::to_string(::getpid()));
  fs::create_directories(root);
  auto script = root / "nvidia-smi";
  {
    std::ofstream out(script);
    out << "#!/bin/sh\n";
    out << "case \"$1\" in\n";
    out << "  --query-gpu=*) echo 'MockGPU, 4096, 1024, 12, 6, 55, P2, 75.0' ;;\n";
    out << "  *) exit 1 ;;\n";
    out << "esac\n";
  }
  ::chmod(script.c_str(), 0755);
  TempRootGuard smi_path("MONTAUK_NVIDIA_SMI_PATH", script.string());
  // Ensure device-level fallback is enabled and cache interval is small
  TempRootGuard smi_dev("MONTAUK_NVIDIA_SMI_DEV", "1");
  TempRootGuard smi_interval("MONTAUK_SMI_MIN_INTERVAL_MS", "0");
  // Skip native NVML so the injected nvidia-smi is what answers, not a live GPU.
  TempRootGuard gpu_disable("MONTAUK_GPU_DISABLE_NATIVE", "1");

  montauk::collectors::GpuCollector c; montauk::model::GpuVram v{};
  ASSERT_TRUE(c.sample(v));
  ASSERT_EQ(v.total_mb, 4096u);
  ASSERT_EQ(v.used_mb, 1024u);
  ASSERT_TRUE(v.has_util);
}
