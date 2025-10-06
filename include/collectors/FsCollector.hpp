#pragma once
#include "model/Fs.hpp"

namespace montauk::collectors {

class FsCollector {
public:
  // Sample filesystem usage across mounted filesystems (user-visible only)
  bool sample(montauk::model::FsSnapshot& out);
};

} // namespace montauk::collectors

