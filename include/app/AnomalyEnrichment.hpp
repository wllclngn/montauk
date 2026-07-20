#pragma once
#include "model/Process.hpp"

namespace montauk::app {

// Cross-sectional anomaly enrichment over the live process population. Builds a
// per-process feature vector (CPU %, RSS, GPU %) and fuses two sublimation
// learn-lane detectors (robust MAD, Mahalanobis) into a rank-averaged
// anomaly_score per process, plus the dominant feature axis. Runs
// on the Producer thread before publish; writes back onto procs.processes.
// A near-empty population (fewer than 8 processes) is left unscored.
void enrich_anomalies(montauk::model::ProcessSnapshot& procs);

}  // namespace montauk::app
