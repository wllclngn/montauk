#include "minitest.hpp"
#include "app/Alerts.hpp"

TEST(alert_engine_cpu_mem) {
  lsm::model::Snapshot s{};
  s.cpu.usage_pct = 95.0;
  s.mem.used_kb = 900; s.mem.total_kb = 1000; s.mem.used_pct = 90.0;
  lsm::app::AlertEngine eng({.cpu_total_high_pct = 90.0, .mem_high_pct = 90.0, .top_proc_cpu_pct = 80.0, .sustain = std::chrono::seconds(0)});
  auto alerts = eng.evaluate(s);
  ASSERT_TRUE(!alerts.empty());
}
