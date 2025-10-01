#pragma once
#include "model/Snapshot.hpp"

namespace lsm::collectors {

class MemoryCollector {
public:
  bool sample(lsm::model::Memory& out) const; // returns true on success
};

} // namespace lsm::collectors

