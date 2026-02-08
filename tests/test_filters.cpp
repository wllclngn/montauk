#include "minitest.hpp"
#include "app/Filter.hpp"

TEST(process_filter_basic) {
  montauk::model::ProcessSnapshot ps{};
  ps.processes.push_back({.pid=1,.utime=0,.stime=0,.total_time=0,.rss_kb=10000,.cpu_pct=5.0,.user_name="mod",.cmd="chrome --renderer",.exe_path="/usr/bin/chrome"});
  ps.processes.push_back({.pid=2,.utime=0,.stime=0,.total_time=0,.rss_kb=5000,.cpu_pct=1.0,.user_name="root",.cmd="sshd: root",.exe_path="/usr/sbin/sshd"});
  montauk::app::ProcessFilterSpec spec{};
  spec.name_contains = std::optional<std::string>("chrome");
  spec.cpu_min = std::optional<double>(2.0);
  montauk::app::ProcessFilter f(spec);
  auto idx = f.apply(ps);
  ASSERT_EQ(idx.size(), 1u);
  ASSERT_EQ(ps.processes[idx[0]].pid, 1);
}

TEST(process_filter_case_insensitive_substring) {
  montauk::model::ProcessSnapshot ps{};
  ps.processes.push_back({.pid=10,.utime=0,.stime=0,.total_time=0,.rss_kb=1000,.cpu_pct=2.0,.user_name="mod",.cmd="Firefox --new-tab",.exe_path="/usr/bin/firefox"});
  ps.processes.push_back({.pid=20,.utime=0,.stime=0,.total_time=0,.rss_kb=2000,.cpu_pct=1.0,.user_name="mod",.cmd="code --unity-launch",.exe_path="/usr/bin/code"});
  ps.processes.push_back({.pid=30,.utime=0,.stime=0,.total_time=0,.rss_kb=500,.cpu_pct=0.5,.user_name="root",.cmd="firefoxUpdater",.exe_path="/usr/bin/updater"});

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
