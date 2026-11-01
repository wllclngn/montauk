// The snapshot's anomaly rows name a process by the kernel's name for it.
#include "minitest.hpp"
#include "app/MetricsServer.hpp"
#include "app/SnapshotBuffers.hpp"

#include <string>

namespace {
std::string row_name(const std::string& cmd, const std::string& comm) {
  montauk::app::SnapshotBuffers bufs;
  montauk::model::ProcSample p{};
  p.pid = 1;
  p.cmd = cmd;
  p.comm = comm;
  bufs.back().procs.processes.push_back(p);
  bufs.publish();
  const auto ms = montauk::app::read_metrics_snapshot(bufs);
  return std::string(ms.anomaly_features.at(0).comm.data());
}
}  // namespace

// A command line rewritten to another system's form, and a relative argv[0],
// both read as the comm; an absolute path reads as it did, its basename.
TEST(snapshot_names_by_comm) {
  ASSERT_EQ(row_name("S:\\steamapps\\common\\Hollow Knight\\hollow_knight.exe", "hollow_knight.e"),
            std::string("hollow_knight.e"));
  ASSERT_EQ(row_name("./steamwebhelper -nocrashdialog", "steamwebhelper"),
            std::string("steamwebhelper"));
  ASSERT_EQ(row_name("/usr/lib/firefox/firefox -contentproc", "firefox"), std::string("firefox"));
}

// A row with no comm keeps the command line's program, basename for an
// absolute path, a kernel thread's slashes intact.
TEST(snapshot_names_fall_back_without_comm) {
  ASSERT_EQ(row_name("/usr/bin/python3 -c x", ""), std::string("python3"));
  ASSERT_EQ(row_name("kworker/4:0H", ""), std::string("kworker/4:0H"));
}
