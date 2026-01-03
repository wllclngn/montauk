#pragma once
#include "model/Snapshot.hpp"

namespace montauk::collectors {

class ThermalCollector {
public:
  bool sample(montauk::model::Thermal& out);
};

} // namespace montauk::collectors

