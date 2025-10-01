#pragma once
#include "model/Snapshot.hpp"

namespace lsm::collectors {

class NetCollector {
public:
  bool sample(lsm::model::NetSnapshot& out);
private:
  // keep previous by interface name for deltas
  std::vector<lsm::model::NetIf> last_{};
};

} // namespace lsm::collectors

