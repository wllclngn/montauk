// AnomalyEnrichment: cross-sectional anomaly scoring over the process population.
// A planted CPU or RSS outlier must rank as the top anomaly on the right axis; a
// too-small population is left unscored.
#include "minitest.hpp"
#include "app/AnomalyEnrichment.hpp"
#include "model/Process.hpp"

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
  montauk::app::enrich_anomalies(ps);
  ASSERT_EQ(top_scored(ps), static_cast<size_t>(7));
  ASSERT_EQ(static_cast<int>(ps.processes[7].anomaly_axis), 0);  // cpu
}

TEST(anomaly_flags_rss_outlier) {
  auto ps = make_pop(30);
  ps.processes[12].rss_kb = 8000000;                   // a ~8 GB memory hog
  montauk::app::enrich_anomalies(ps);
  ASSERT_EQ(top_scored(ps), static_cast<size_t>(12));
  ASSERT_EQ(static_cast<int>(ps.processes[12].anomaly_axis), 1);  // rss
}

TEST(anomaly_skips_tiny_population) {
  auto ps = make_pop(5);                               // fewer than 8: unscored
  ps.processes[2].cpu_pct = 99.0;
  montauk::app::enrich_anomalies(ps);
  for (const auto& p : ps.processes) {
    ASSERT_EQ(p.anomaly_score, 0.0);
    ASSERT_EQ(static_cast<int>(p.anomaly_axis), -1);
  }
}
