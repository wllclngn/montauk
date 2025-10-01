#pragma once
#include "model/Snapshot.hpp"

namespace lsm::collectors {

class CpuCollector {
public:
  CpuCollector() = default;
  bool sample(lsm::model::CpuSnapshot& out);
private:
  lsm::model::CpuTimes last_total_{};
  std::vector<lsm::model::CpuTimes> last_per_{};
  bool has_last_{false};
  std::string cpu_model_{};
};

} // namespace lsm::collectors
