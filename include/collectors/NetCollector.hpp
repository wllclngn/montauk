#pragma once
#include "model/Snapshot.hpp"
#include <unordered_map>

namespace montauk::collectors {

class NetCollector {
public:
  [[nodiscard]] bool sample(montauk::model::NetSnapshot& out);
private:
  // keep previous by interface name for deltas
  std::unordered_map<std::string, montauk::model::NetIf> last_{};
};

} // namespace montauk::collectors

