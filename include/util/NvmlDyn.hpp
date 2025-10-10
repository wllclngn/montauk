#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include "model/Snapshot.hpp"

namespace montauk::util {

// Lightweight runtime NVML loader (dlopen/dlsym).
// Avoids build-time dependency on nvml.h and enables graceful degradation
// across driver/toolkit updates and varying library layouts.
class NvmlDyn {
public:
  // Singleton accessor
  static NvmlDyn& instance();

  // Attempt to load libnvidia-ml once (idempotent). Respects env:
  //   MONTAUK_DISABLE_NVML=1  -> do not load
  //   MONTAUK_NVML_PATH=/path/to/libnvidia-ml.so.1
  bool load_once();

  // True if library is loaded and core symbols are present.
  bool available() const;

  // Populate device-level GPU metrics via NVML. Returns true if any data found.
  bool read_devices(montauk::model::GpuVram& out);

private:
  NvmlDyn() = default;
  NvmlDyn(const NvmlDyn&) = delete;
  NvmlDyn& operator=(const NvmlDyn&) = delete;

  void* handle_{};
  bool loaded_{false};
  bool suppressed_{false};

  // Function pointers (subset used by GpuCollector)
  using nvmlReturn_t = int; // NVML_SUCCESS == 0
  using nvmlDevice_t = void*;
  struct nvmlMemory_t { unsigned long long total, free, used; };
  struct nvmlUtilization_t { unsigned int gpu, memory; };

  // Signatures
  nvmlReturn_t (*p_nvmlInit_v2)();
  nvmlReturn_t (*p_nvmlShutdown)();
  nvmlReturn_t (*p_nvmlDeviceGetCount_v2)(unsigned int* count);
  nvmlReturn_t (*p_nvmlDeviceGetHandleByIndex_v2)(unsigned int index, nvmlDevice_t* device);
  nvmlReturn_t (*p_nvmlDeviceGetName)(nvmlDevice_t device, char* name, unsigned int length);
  nvmlReturn_t (*p_nvmlDeviceGetMemoryInfo)(nvmlDevice_t device, nvmlMemory_t* mem);
  nvmlReturn_t (*p_nvmlDeviceGetTemperature)(nvmlDevice_t device, unsigned int sensorType, unsigned int* temp);
  nvmlReturn_t (*p_nvmlDeviceGetUtilizationRates)(nvmlDevice_t device, nvmlUtilization_t* utilization);
  nvmlReturn_t (*p_nvmlDeviceGetEncoderUtilization)(nvmlDevice_t device, unsigned int* utilization, unsigned int* samplingPeriodUs);
  nvmlReturn_t (*p_nvmlDeviceGetDecoderUtilization)(nvmlDevice_t device, unsigned int* utilization, unsigned int* samplingPeriodUs);
  nvmlReturn_t (*p_nvmlDeviceGetPowerUsage)(nvmlDevice_t device, unsigned int* milliwatts);
  nvmlReturn_t (*p_nvmlDeviceGetPowerManagementLimit)(nvmlDevice_t device, unsigned int* milliwatts);
  nvmlReturn_t (*p_nvmlDeviceGetPerformanceState)(nvmlDevice_t device, unsigned int* pstate);

  // Helpers
  static const char* getenv_compat(const char* name);
  bool dlsym_all();
};

} // namespace montauk::util

