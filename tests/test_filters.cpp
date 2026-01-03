#include "minitest.hpp"
#include "app/Filter.hpp"

TEST(process_filter_basic) {
  montauk::model::ProcessSnapshot ps{};
  ps.processes.push_back({.pid=1,.ppid=0,.utime=0,.stime=0,.total_time=0,.rss_kb=10000,.cpu_pct=5.0,.user_name="mod",.cmd="chrome --renderer",.exe_path="/usr/bin/chrome"});
  ps.processes.push_back({.pid=2,.ppid=0,.utime=0,.stime=0,.total_time=0,.rss_kb=5000,.cpu_pct=1.0,.user_name="root",.cmd="sshd: root",.exe_path="/usr/sbin/sshd"});
  montauk::app::ProcessFilterSpec spec{};
  spec.name_contains = std::optional<std::string>("chrome");
  spec.cpu_min = std::optional<double>(2.0);
  montauk::app::ProcessFilter f(spec);
  auto idx = f.apply(ps);
  ASSERT_EQ(idx.size(), 1u);
  ASSERT_EQ(ps.processes[idx[0]].pid, 1);
}
