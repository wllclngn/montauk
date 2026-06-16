#pragma once

#include <string>
#include <vector>

namespace montauk::model {

// Per-idle-state residency aggregated across CPUs (POLL/C1/C2/C6/...), fraction
// of total cpu-time spent in that state over the interval.
struct CpuIdleState {
  std::string name;
  double residency_pct{0.0};
};

struct Thermal {
  bool   has_temp{false};
  double cpu_max_c{0.0};
  bool   has_warn{false};
  double warn_c{0.0};
  // Optional fan speed (RPM) from hwmon
  bool   has_fan{false};
  double fan_rpm{0.0};
  // Optional package power (W) from RAPL/powercap, energy delta per interval.
  bool   has_power{false};
  double power_watts{0.0};
  // Optional per-state idle residency (%) over the interval, across CPUs.
  std::vector<CpuIdleState> cstates;
};

} // namespace montauk::model
