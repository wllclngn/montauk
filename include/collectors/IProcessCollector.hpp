#pragma once
#include "model/Snapshot.hpp"

namespace montauk::collectors {

// Minimal interface for process collectors so we can swap
// between traditional /proc scanning and event-driven netlink.
class IProcessCollector {
public:
  virtual ~IProcessCollector() = default;

  // Initialize collector. Return false if unavailable (permissions, platform).
  // Default: available (no-op)
  [[nodiscard]] virtual bool init() { return true; }

  // Sample current process state into out. Return true on success.
  [[nodiscard]] virtual bool sample(montauk::model::ProcessSnapshot& out) = 0;

  // Cleanup resources. Default: no-op
  virtual void shutdown() {}

  // Optional: human-friendly name for diagnostics
  [[nodiscard]] virtual const char* name() const = 0;
};

} // namespace montauk::collectors

