#pragma once
#include "model/Snapshot.hpp"

#include <chrono>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

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
  // The cpuidle states, found once: each state's time file and the index of
  // its name in cstate_names_, since a state's name never changes while it
  // exists. Found again when the CPU count changes or a read fails (hotplug).
  struct CstateFile { std::string time_path; size_t name_idx; };
  std::vector<CstateFile> cstate_files_;
  std::vector<std::string> cstate_names_;
  size_t cstate_cpu_entries_{0};
  int cstate_ncpu_{0};
  bool cstate_found_{false};
  void find_cstates(size_t cpu_entries);
  // The sensors, found once: Each hwmon temperature input with whether its chip
  // is a CPU package and the threshold its crit, max or emergency file gives
  // (thresholds do not move while the chip is there), each fan input, each
  // thermal zone and each RAPL package counter. Found again when the set of
  // hwmon chips changes or an input goes missing.
  struct TempInput { std::string path; bool cpu; bool has_thr; double thr_c; };
  std::vector<TempInput> temps_;
  std::vector<std::string> fans_, zones_, rapl_;
  size_t hwmon_entries_{0};
  bool sensors_found_{false};
  void find_sensors(size_t hwmon_entries);
};

} // namespace montauk::collectors

