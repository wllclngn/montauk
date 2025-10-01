#pragma once
#include "model/Snapshot.hpp"

namespace lsm::collectors {

class ThermalCollector {
public:
  bool sample(lsm::model::Thermal& out);
};

} // namespace lsm::collectors

