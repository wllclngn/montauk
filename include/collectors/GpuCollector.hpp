#pragma once
#include "model/Snapshot.hpp"
#include <string>

namespace montauk::collectors {

class GpuCollector {
public:
  // Attempts NVML, then /proc and sysfs fallbacks. Returns true if any data was found.
  [[nodiscard]] bool sample(montauk::model::GpuVram& out) const;
};

// Where nvidia-smi is: MONTAUK_NVIDIA_SMI_PATH read live, then the configured
// path, then PATH and the usual install locations, each one that can run.
// Empty when there is none.
[[nodiscard]] std::string find_nvidia_smi_path();

} // namespace montauk::collectors

