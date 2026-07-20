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

  // Sample current process state into out.
  //
  // Return-value convention for EVERY collector's sample(), process or not:
  // true means "this snapshot section was refreshed with data this cycle",
  // false means it was not (source unavailable, read failure, or the call
  // was a within-interval no-op). Producer tolerates false by carrying the
  // previous section forward.
  [[nodiscard]] virtual bool sample(montauk::model::ProcessSnapshot& out) = 0;

  // Cleanup resources. Default: no-op
  virtual void shutdown() {}

  // Optional: human-friendly name for diagnostics
  [[nodiscard]] virtual const char* name() const = 0;
};

} // namespace montauk::collectors

