#pragma once
#include "model/Process.hpp"

#include <cstdint>
#include <unordered_map>

namespace montauk::app {

// Cross-sectional anomaly enrichment over the live process population. Builds a
// per-process feature vector (CPU %, RSS, GPU %, fault delta, thread count) and
// fuses two sublimation learn-lane detectors (robust MAD, Mahalanobis) into a
// rank-averaged anomaly_score per process, plus the dominant feature axis. The
// fault delta is derived from prev_faults, the caller-owned per-pid cumulative
// fault count from the previous cycle (the Producer holds it across frames and
// this call refreshes it). Runs on the Producer thread before publish; writes
// back onto procs.processes. A near-empty population (< 8 processes) is unscored.
void enrich_anomalies(montauk::model::ProcessSnapshot& procs,
                      std::unordered_map<int32_t, uint64_t>& prev_faults);

}  // namespace montauk::app
