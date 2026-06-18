#pragma once
#include "model/Snapshot.hpp"

#include <chrono>
#include <cstdint>
#include <map>
#include <string>

namespace montauk::collectors {

class ThermalCollector {
public:
  [[nodiscard]] bool sample(montauk::model::Thermal& out);

private:
  // RAPL/powercap package energy is a monotonic microjoule counter; power is
  // its delta over wall time between samples. State persists across snapshots.
  uint64_t prev_energy_uj_{0};
  std::chrono::steady_clock::time_point prev_energy_t_{};
  bool have_prev_energy_{false};
  // Wrap-safe cumulative energy (joules): each valid interval's energy summed.
  // Exposed as a monotonic counter so a window-integral is its delta.
  double energy_accum_j_{0.0};
  // Per-idle-state cumulative residency (microseconds, summed across CPUs);
  // residency percent is the delta over total cpu-time in the interval.
  std::map<std::string, uint64_t> prev_cstate_us_;
  std::chrono::steady_clock::time_point prev_cstate_t_{};
  bool have_prev_cstate_{false};
};

} // namespace montauk::collectors

