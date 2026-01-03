#pragma once
#include "model/Snapshot.hpp"

namespace montauk::collectors {

class MemoryCollector {
public:
  bool sample(montauk::model::Memory& out) const; // returns true on success
};

} // namespace montauk::collectors

