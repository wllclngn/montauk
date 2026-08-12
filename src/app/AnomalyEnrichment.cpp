#include "app/AnomalyEnrichment.hpp"

#include "sublimation_learn.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace montauk::app {

void enrich_anomalies(montauk::model::ProcessSnapshot& procs,
                      std::unordered_map<int32_t, uint64_t>& prev_faults,
                      std::unordered_map<int32_t, uint64_t>& prev_ctxsw) {
  auto& ps = procs.processes;
  const size_t n = ps.size();
  for (auto& p : ps) { p.anomaly_score = 0.0; p.anomaly_axis = -1;
                       p.fault_delta = 0.0; p.ctxsw_delta = 0.0; }
  auto refresh_faults = [&]() {
    prev_faults.clear();
    prev_faults.reserve(ps.size());
    for (const auto& p : ps) prev_faults[p.pid] = p.flt_raw;
    prev_ctxsw.clear();
    prev_ctxsw.reserve(ps.size());
    for (const auto& p : ps) prev_ctxsw[p.pid] = p.nvctx_raw;
  };
  if (n < 8) { refresh_faults(); return; }  // too few for a distribution

  // INVOLUNTARY switches, not the sum: a voluntary switch is a process
  // choosing to block, which cpu% already describes. Being PREEMPTED is the
  // axis nothing else here can see.
  constexpr size_t d = 6;  // cpu%, rss, gpu%, fault delta, thread count, ctxsw delta
  std::vector<double> x(n * d);
  for (size_t i = 0; i < n; ++i) {
    x[i * d + 0] = ps[i].cpu_pct;
    x[i * d + 1] = static_cast<double>(ps[i].rss_kb);
    x[i * d + 2] = ps[i].has_gpu_util ? ps[i].gpu_util_pct : 0.0;
    auto pf = prev_faults.find(ps[i].pid);
    x[i * d + 3] = (pf != prev_faults.end() && ps[i].flt_raw > pf->second)
                       ? static_cast<double>(ps[i].flt_raw - pf->second) : 0.0;
    x[i * d + 4] = static_cast<double>(ps[i].thread_count);
    auto pc = prev_ctxsw.find(ps[i].pid);
    x[i * d + 5] = (pc != prev_ctxsw.end() && ps[i].nvctx_raw > pc->second)
                       ? static_cast<double>(ps[i].nvctx_raw - pc->second) : 0.0;
    ps[i].fault_delta = x[i * d + 3];   // publish the stateful features for --json / vector
    ps[i].ctxsw_delta = x[i * d + 5];
  }

  // The fusion is the sublimation learn-lane primitive: the three spatial
  // detectors (MAD, Mahalanobis, Half-Space Trees) rank-averaged, plus the
  // dominant-axis attribution, computed ONCE in the core -- the same
  // sublimation_anomaly_fuse vector's montauk_anomalies calls. montauk owns the
  // feature matrix built above; sublimation owns the score. (EWMA stays out: it
  // is temporal, and belongs to the changepoint field, not this spatial fusion.)
  // FUSE ONLY THE AXES THAT CARRY SIGNAL. A column that is constant across the
  // whole population tells the detectors nothing, and worse, it is not free:
  // Mahalanobis inverts a covariance matrix that a constant column makes
  // singular. Which axes are live depends on the COLLECTOR -- the kernel-module
  // path has no fault or context-switch counters at all, so on any box where
  // the module is loaded (the auto-detect default) those two columns are zero
  // for every process. Fusing six axes when three are constants is how this
  // shipped ranking on a third of its advertised basis. Compact to the live
  // columns, fuse those, then map the dominant axis back to its original index
  // so the published axis still means what the feature table says.
  uint32_t live_mask = 0;
  std::vector<size_t> live;
  for (size_t j = 0; j < d; ++j) {
    const double first = x[j];
    for (size_t i = 1; i < n; ++i) {
      if (x[i * d + j] != first) { live.push_back(j); live_mask |= (1u << j); break; }
    }
  }
  procs.anomaly_axis_mask = live_mask;
  const size_t dl = live.size();
  if (dl == 0) { refresh_faults(); return; }   // nothing varies: no ranking to make

  std::vector<double> xl;
  const double* fuse_x = x.data();
  if (dl != d) {
    xl.resize(n * dl);
    for (size_t i = 0; i < n; ++i)
      for (size_t k = 0; k < dl; ++k) xl[i * dl + k] = x[i * d + live[k]];
    fuse_x = xl.data();
  }

  std::vector<double> scores(n);
  std::vector<int8_t> axes(n);
  if (sublimation_anomaly_fuse(fuse_x, n, dl, scores.data(), axes.data()) == 0) {
    for (size_t i = 0; i < n; ++i) {
      const int8_t a = axes[i];
      if (a >= 0 && (size_t)a < dl) axes[i] = (int8_t)live[(size_t)a];
    }
    for (size_t i = 0; i < n; ++i) {
      ps[i].anomaly_score = scores[i];
      ps[i].anomaly_axis = axes[i];
    }
  }  // on allocation failure the reset 0.0 / -1 above stands
  refresh_faults();
}

}  // namespace montauk::app
