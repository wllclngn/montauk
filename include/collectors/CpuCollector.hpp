#pragma once
#include "model/Snapshot.hpp"

namespace montauk::collectors {

class CpuCollector {
public:
  CpuCollector() = default;
  bool sample(montauk::model::CpuSnapshot& out);
private:
  montauk::model::CpuTimes last_total_{};
  std::vector<montauk::model::CpuTimes> last_per_{};
  bool has_last_{false};
  std::string cpu_model_{};
};

} // namespace montauk::collectors
