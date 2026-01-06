#pragma once

namespace montauk::model {

struct Thermal {
  bool   has_temp{false};
  double cpu_max_c{0.0};
  bool   has_warn{false};
  double warn_c{0.0};
  // Optional fan speed (RPM) from hwmon
  bool   has_fan{false};
  double fan_rpm{0.0};
};

} // namespace montauk::model
