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
  [[nodiscard]] bool load_once();

  // True if library is loaded and core symbols are present.
  [[nodiscard]] bool available() const;

  // Populate device-level GPU metrics via NVML. Returns true if any data found.
  [[nodiscard]] bool read_devices(montauk::model::GpuVram& out);

  // Resolve an arbitrary NVML symbol from the already-open handle, or nullptr.
  //
  // This exists so there is exactly ONE dlopen of libnvidia-ml in the process,
  // and one place that honours MONTAUK_DISABLE_NVML / MONTAUK_NVML_PATH.
  // GpuAttributor needs the per-process entry points, whose signatures use
  // nvml.h types this header deliberately does not include -- so it builds its
  // own typed table from this accessor rather than opening a second handle or
  // linking NVML back into DT_NEEDED.
  [[nodiscard]] void* sym(const char* name);

private:
  NvmlDyn() = default;
  ~NvmlDyn();
  NvmlDyn(const NvmlDyn&) = delete;
  NvmlDyn& operator=(const NvmlDyn&) = delete;

  void* handle_{};
  bool loaded_{false};
  bool suppressed_{false};
  // NVML is initialised once and held: An init/shutdown pair per sample costs
  // ~3 ms whenever nothing else holds a reference, and nothing while one is.
  bool inited_{false};
  // What a device does not change while montauk runs, read once per device
  // set: its name and its power-management limit.
  struct Fixed { std::string name; bool has_limit; double limit_w; };
  std::vector<Fixed> fixed_;

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
  nvmlReturn_t (*p_nvmlDeviceGetFanSpeed_v2)(nvmlDevice_t device, unsigned int fan, unsigned int* speed);

  // Helpers
  bool dlsym_all();

};

} // namespace montauk::util

