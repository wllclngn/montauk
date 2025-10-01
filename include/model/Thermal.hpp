#pragma once

namespace lsm::model {

struct Thermal {
  bool   has_temp{false};
  double cpu_max_c{0.0};
  bool   has_warn{false};
  double warn_c{0.0};
};

} // namespace lsm::model
