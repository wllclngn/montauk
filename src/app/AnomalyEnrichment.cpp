#include "app/AnomalyEnrichment.hpp"

#include "sublimation_learn.h"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <numeric>
#include <vector>

namespace montauk::app {

namespace {
// Rank-normalize a score vector to [0,1] (0 = lowest, 1 = highest). Fusing the
// three detectors by rank average combines their wildly different scales cleanly,
// the same fusion the real-data validation used.
std::vector<double> rank_normalize(const std::vector<double>& v) {
  const size_t n = v.size();
  std::vector<size_t> idx(n);
  std::iota(idx.begin(), idx.end(), 0);
  std::sort(idx.begin(), idx.end(), [&](size_t a, size_t b) { return v[a] < v[b]; });
  std::vector<double> r(n);
  for (size_t rank = 0; rank < n; ++rank)
    r[idx[rank]] = (n > 1) ? static_cast<double>(rank) / static_cast<double>(n - 1) : 0.0;
  return r;
}
}  // namespace

void enrich_anomalies(montauk::model::ProcessSnapshot& procs,
                      std::unordered_map<int32_t, uint64_t>& prev_faults) {
  auto& ps = procs.processes;
  const size_t n = ps.size();
  for (auto& p : ps) { p.anomaly_score = 0.0; p.anomaly_axis = -1; }
  auto refresh_faults = [&]() {
    prev_faults.clear();
    prev_faults.reserve(ps.size());
    for (const auto& p : ps) prev_faults[p.pid] = p.flt_raw;
  };
  if (n < 8) { refresh_faults(); return; }  // too few for a distribution

  constexpr size_t d = 5;  // cpu%, rss, gpu%, fault delta, thread count
  std::vector<double> x(n * d);
  for (size_t i = 0; i < n; ++i) {
    x[i * d + 0] = ps[i].cpu_pct;
    x[i * d + 1] = static_cast<double>(ps[i].rss_kb);
    x[i * d + 2] = ps[i].has_gpu_util ? ps[i].gpu_util_pct : 0.0;
    auto pf = prev_faults.find(ps[i].pid);
    x[i * d + 3] = (pf != prev_faults.end() && ps[i].flt_raw > pf->second)
                       ? static_cast<double>(ps[i].flt_raw - pf->second) : 0.0;
    x[i * d + 4] = static_cast<double>(ps[i].thread_count);
  }

  // Two detectors: MAD catches a process extreme on any single axis (cpu, rss,
  // gpu, fault delta or thread count), Mahalanobis catches one whose
  // combination of axes is unusual. Half-Space Trees stays out of the live
  // per-frame ensemble (it rebuilt a deterministic forest every frame); its
  // return as a standing model over this wider feature set is tracked separately.
  std::vector<double> mad(n), maha(n);
  sublimation_mad_scores(x.data(), n, d, mad.data());
  if (sublimation_mahalanobis(x.data(), n, d, 1e-3, maha.data()) != 0)
    std::fill(maha.begin(), maha.end(), 0.0);  // degenerate covariance: drop it

  const auto rm = rank_normalize(mad);
  const auto rh = rank_normalize(maha);

  // Per-column standardization drives the dominant-axis attribution: the feature
  // with the largest absolute z-score is what makes a process anomalous.
  double mean[d] = {0, 0, 0, 0, 0}, sd[d] = {0, 0, 0, 0, 0};
  for (size_t i = 0; i < n; ++i)
    for (size_t j = 0; j < d; ++j) mean[j] += x[i * d + j];
  for (size_t j = 0; j < d; ++j) mean[j] /= static_cast<double>(n);
  for (size_t i = 0; i < n; ++i)
    for (size_t j = 0; j < d; ++j) { double e = x[i * d + j] - mean[j]; sd[j] += e * e; }
  for (size_t j = 0; j < d; ++j) sd[j] = std::sqrt(sd[j] / static_cast<double>(n));

  for (size_t i = 0; i < n; ++i) {
    ps[i].anomaly_score = (rm[i] + rh[i]) / 2.0;
    int axis = -1;
    double best = 0.0;
    for (size_t j = 0; j < d; ++j) {
      if (sd[j] <= 0.0) continue;
      double z = std::fabs((x[i * d + j] - mean[j]) / sd[j]);
      if (z > best) { best = z; axis = static_cast<int>(j); }
    }
    ps[i].anomaly_axis = static_cast<int8_t>(axis);
  }
  refresh_faults();
}

}  // namespace montauk::app
