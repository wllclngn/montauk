#pragma once
#include "model/Snapshot.hpp"

namespace lsm::collectors {

class GpuCollector {
public:
  // Attempts NVML, then /proc and sysfs fallbacks. Returns true if any data was found.
  bool sample(lsm::model::GpuVram& out) const;
};

} // namespace lsm::collectors

