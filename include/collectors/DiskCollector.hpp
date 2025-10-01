#pragma once
#include "model/Snapshot.hpp"
#include <unordered_map>

namespace lsm::collectors {

class DiskCollector {
public:
  bool sample(lsm::model::DiskSnapshot& out);
private:
  struct Prev { uint64_t rd{}, wr{}, rdsec{}, wrsec{}, tios{}, ms{}; double ts{}; };
  std::unordered_map<std::string, Prev> last_;
  static constexpr uint64_t kSectorSize = 512; // typical
};

} // namespace lsm::collectors

