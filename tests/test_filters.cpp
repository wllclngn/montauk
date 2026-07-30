// Process filter: filtering the process list by name/pid/user criteria.
#include "minitest.hpp"
#include "app/Filter.hpp"
#include "sublimation.h"   // searchsorted: the membership predicate ProcessTable uses

TEST(filters_basic) {
  montauk::model::ProcessSnapshot ps{};
  ps.processes.push_back({.pid=1,.total_time=0,.rss_kb=10000,.cpu_pct=5.0,.user_name="mod",.cmd="chrome --renderer",.exe_path="/usr/bin/chrome"});
  ps.processes.push_back({.pid=2,.total_time=0,.rss_kb=5000,.cpu_pct=1.0,.user_name="root",.cmd="sshd: root",.exe_path="/usr/sbin/sshd"});
  montauk::app::ProcessFilterSpec spec{};
  spec.name_contains = std::optional<std::string>("chrome");
  spec.cpu_min = std::optional<double>(2.0);
  montauk::app::ProcessFilter f(spec);
  auto idx = f.apply(ps);
  ASSERT_EQ(idx.size(), 1u);
  ASSERT_EQ(ps.processes[idx[0]].pid, 1);
}

TEST(filters_case_insensitive_substring) {
  montauk::model::ProcessSnapshot ps{};
  ps.processes.push_back({.pid=10,.total_time=0,.rss_kb=1000,.cpu_pct=2.0,.user_name="mod",.cmd="Firefox --new-tab",.exe_path="/usr/bin/firefox"});
  ps.processes.push_back({.pid=20,.total_time=0,.rss_kb=2000,.cpu_pct=1.0,.user_name="mod",.cmd="code --unity-launch",.exe_path="/usr/bin/code"});
  ps.processes.push_back({.pid=30,.total_time=0,.rss_kb=500,.cpu_pct=0.5,.user_name="root",.cmd="firefoxUpdater",.exe_path="/usr/bin/updater"});

  // "firefox" should match both PID 10 ("Firefox") and PID 30 ("firefoxUpdater") case-insensitively
  montauk::app::ProcessFilterSpec spec{};
  spec.name_contains = std::optional<std::string>("firefox");
  montauk::app::ProcessFilter f(spec);
  auto idx = f.apply(ps);
  ASSERT_EQ(idx.size(), 2u);
  ASSERT_EQ(ps.processes[idx[0]].pid, 10);
  ASSERT_EQ(ps.processes[idx[1]].pid, 30);

  // Empty query should match all
  montauk::app::ProcessFilterSpec empty_spec{};
  empty_spec.name_contains = std::optional<std::string>("");
  montauk::app::ProcessFilter f2(empty_spec);
  auto idx2 = f2.apply(ps);
  ASSERT_EQ(idx2.size(), 3u);
}

// apply() returning STRICTLY ASCENDING indices is load-bearing, not incidental:
// ProcessTable's filter step binary-searches this result with
// sublimation_searchsorted_u64 instead of building a hash set per frame. If
// apply() ever emitted out of order the membership test would silently drop
// rows, and no other test would notice -- so the invariant is asserted here,
// beside the function that has to hold it.
TEST(filters_apply_returns_ascending_indices) {
  montauk::model::ProcessSnapshot ps{};
  for (int i = 0; i < 64; ++i) {
    // Every third process matches, so the result is sparse rather than a
    // contiguous prefix -- a run of 0,1,2,... would pass even if unsorted.
    const bool hit = (i % 3) == 0;
    ps.processes.push_back({.pid = 1000 + i,
                            .total_time = 0,
                            .rss_kb = 100,
                            .cpu_pct = 1.0,
                            .user_name = "mod",
                            .cmd = hit ? "target-proc" : "other-proc",
                            .exe_path = "/usr/bin/x"});
  }
  montauk::app::ProcessFilterSpec spec{};
  spec.name_contains = std::optional<std::string>("target");
  montauk::app::ProcessFilter f(spec);
  auto idx = f.apply(ps);

  ASSERT_TRUE(idx.size() > 1u);
  for (size_t i = 1; i < idx.size(); ++i) ASSERT_TRUE(idx[i - 1] < idx[i]);

  // And the exact membership predicate ProcessTable runs: binary search plus an
  // equality check must agree with a linear scan for every index, hit or miss.
  for (size_t probe = 0; probe < ps.processes.size(); ++probe) {
    bool linear = false;
    for (size_t m : idx) if (m == probe) { linear = true; break; }
    size_t pos = sublimation_searchsorted_u64(
        reinterpret_cast<const uint64_t*>(idx.data()), idx.size(),
        static_cast<uint64_t>(probe), 0);
    const bool binary = pos < idx.size() && idx[pos] == probe;
    ASSERT_EQ(binary, linear);
  }
}
