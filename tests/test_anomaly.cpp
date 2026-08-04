// AnomalyEnrichment: cross-sectional anomaly scoring over the process population.
// A planted CPU or RSS outlier must rank as the top anomaly on the right axis; a
// too-small population is left unscored.
#include "minitest.hpp"
#include "app/AnomalyEnrichment.hpp"
#include "model/Process.hpp"

#include <cstdint>
#include <unordered_map>

using montauk::model::ProcessSnapshot;
using montauk::model::ProcSample;

static ProcessSnapshot make_pop(size_t n) {
  ProcessSnapshot ps;
  for (size_t i = 0; i < n; ++i) {
    ProcSample p;
    p.pid = static_cast<int32_t>(1000 + i);
    p.cpu_pct = 1.0 + static_cast<double>(i % 3);      // 1..3, a tight cluster
    p.rss_kb = 40000 + (i % 5) * 1000;                 // ~40 MB cluster
    ps.processes.push_back(p);
  }
  return ps;
}

static size_t top_scored(const ProcessSnapshot& ps) {
  size_t top = 0;
  for (size_t i = 1; i < ps.processes.size(); ++i)
    if (ps.processes[i].anomaly_score > ps.processes[top].anomaly_score) top = i;
  return top;
}

TEST(anomaly_flags_cpu_outlier) {
  auto ps = make_pop(30);
  ps.processes[7].cpu_pct = 99.0;                      // a CPU burner
  std::unordered_map<int32_t, uint64_t> pf, pc;
  montauk::app::enrich_anomalies(ps, pf, pc);
  ASSERT_EQ(top_scored(ps), static_cast<size_t>(7));
  ASSERT_EQ(static_cast<int>(ps.processes[7].anomaly_axis), 0);  // cpu
}

TEST(anomaly_flags_rss_outlier) {
  auto ps = make_pop(30);
  ps.processes[12].rss_kb = 8000000;                   // a ~8 GB memory hog
  std::unordered_map<int32_t, uint64_t> pf, pc;
  montauk::app::enrich_anomalies(ps, pf, pc);
  ASSERT_EQ(top_scored(ps), static_cast<size_t>(12));
  ASSERT_EQ(static_cast<int>(ps.processes[12].anomaly_axis), 1);  // rss
}

TEST(anomaly_skips_tiny_population) {
  auto ps = make_pop(5);                               // fewer than 8: unscored
  ps.processes[2].cpu_pct = 99.0;
  std::unordered_map<int32_t, uint64_t> pf, pc;
  montauk::app::enrich_anomalies(ps, pf, pc);
  for (const auto& p : ps.processes) {
    ASSERT_EQ(p.anomaly_score, 0.0);
    ASSERT_EQ(static_cast<int>(p.anomaly_axis), -1);
  }
}

// THE SIXTH AXIS. A process being PREEMPTED hard is invisible to the other five:
// cpu% says it ran, rss says nothing, gpu and faults are unrelated, and thread
// count is static. This is the case the axis was added for.
//
// Two calls on purpose -- the feature is a DELTA, so the first call only seeds
// the previous-counter map and can find nothing. A single-shot caller sees 0
// here, which is correct rather than broken.
TEST(anomaly_flags_involuntary_ctxsw_outlier) {
  auto ps = make_pop(30);
  std::unordered_map<int32_t, uint64_t> pf, pc;
  for (auto& p : ps.processes) p.nvctx_raw = 100;
  montauk::app::enrich_anomalies(ps, pf, pc);            // seeds pc
  for (const auto& p : ps.processes) ASSERT_EQ(p.ctxsw_delta, 0.0);

  for (auto& p : ps.processes) p.nvctx_raw = 110;        // everyone drifts
  ps.processes[19].nvctx_raw = 900000;                   // one is thrashed
  montauk::app::enrich_anomalies(ps, pf, pc);
  ASSERT_EQ(ps.processes[19].ctxsw_delta, 899900.0);
  ASSERT_EQ(top_scored(ps), static_cast<size_t>(19));
  ASSERT_EQ(static_cast<int>(ps.processes[19].anomaly_axis), 5);  // ctxsw
}

// VOLUNTARY switches are read but deliberately NOT fused: a process choosing to
// block is what cpu% already describes, so folding it in would double-count the
// axis the fusion already has. The raw counter is still published for a caller
// that wants the ratio.
TEST(anomaly_ignores_voluntary_ctxsw) {
  auto ps = make_pop(30);
  std::unordered_map<int32_t, uint64_t> pf, pc;
  for (auto& p : ps.processes) { p.nvctx_raw = 100; p.vctx_raw = 100; }
  montauk::app::enrich_anomalies(ps, pf, pc);
  for (auto& p : ps.processes) { p.nvctx_raw = 110; p.vctx_raw = 110; }
  ps.processes[3].vctx_raw = 900000;                     // voluntary only
  montauk::app::enrich_anomalies(ps, pf, pc);
  ASSERT_EQ(ps.processes[3].ctxsw_delta, 10.0);          // unmoved by voluntary
  ASSERT_EQ(static_cast<int>(ps.processes[3].anomaly_axis) == 5, false);
}
