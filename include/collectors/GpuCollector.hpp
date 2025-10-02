#pragma once
#include "model/Snapshot.hpp"

namespace montauk::collectors {

class GpuCollector {
public:
  // Attempts NVML, then /proc and sysfs fallbacks. Returns true if any data was found.
  bool sample(montauk::model::GpuVram& out) const;
};

} // namespace montauk::collectors

