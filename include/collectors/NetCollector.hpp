#pragma once
#include "model/Snapshot.hpp"

namespace montauk::collectors {

class NetCollector {
public:
  [[nodiscard]] bool sample(montauk::model::NetSnapshot& out);
private:
  // keep previous by interface name for deltas
  std::vector<montauk::model::NetIf> last_{};
};

} // namespace montauk::collectors

