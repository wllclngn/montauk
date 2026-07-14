// snapshot_to_json/snapshot_to_prometheus/trace_to_prometheus/trace_to_json
// against a fixed fixture (fixtures/metrics_fixture.hpp), gated byte-identical
// against goldens captured before the renderer-unification refactor -- the
// oracle that proves the MetricsSink rewrite reproduces today's output
// exactly, plus permanent regression coverage afterward (the "Snapshot JSON
// test coverage" gap: snapshot_to_json/trace_to_prometheus/trace_to_json had
// no direct test or golden before this file).
//
// MONTAUK_UPDATE_GOLDEN=1 regenerates the goldens from current output,
// mirroring corpus_check.py's own --update convention for frozen fixtures.
#include "minitest.hpp"
#include "env_guard.hpp"
#include "fixtures/metrics_fixture.hpp"
#include "app/MetricsServer.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <unistd.h>

namespace {

bool update_mode() {
  const char* v = std::getenv("MONTAUK_UPDATE_GOLDEN");
  return v && v[0] == '1';
}

// render_system() (src/app/MetricsRender.cpp) reads kernel/scheduler live via
// read_kernel_version()/read_scheduler() rather than from MetricsSnapshot --
// they're system-identity facts, not per-frame collected fields, same as the
// live SystemPanel's own direct calls. Both route through
// util::read_file_string, which already honors MONTAUK_PROC_ROOT/
// MONTAUK_SYS_ROOT (the same redirection every collector test uses), so
// pointing both at a fixed fixture tree makes this test's kernel/scheduler
// values as hermetic as every other fixture field instead of leaking the
// live host's kernel/scheduler into a byte-identical golden compare.
struct SystemIdentityFixture {
  std::filesystem::path root;
  TempRootGuard proc_root;
  TempRootGuard sys_root;

  SystemIdentityFixture()
      : root(std::filesystem::temp_directory_path() /
             std::filesystem::path("montauk_test_json_snapshot_") /
             std::filesystem::path(std::to_string(::getpid()))),
        proc_root("MONTAUK_PROC_ROOT", root.string()),
        sys_root("MONTAUK_SYS_ROOT", root.string()) {
    std::filesystem::create_directories(root / "proc/sys/kernel");
    std::ofstream(root / "proc/sys/kernel/osrelease") << "7.1.3-arch1-2\n";
    std::filesystem::create_directories(root / "sys/kernel/sched_ext/root");
    std::ofstream(root / "sys/kernel/sched_ext/root/ops") << "pandemonium\n";
  }
};

std::string read_golden(const char* path) {
  std::ifstream f(path, std::ios::binary);
  std::ostringstream ss;
  ss << f.rdbuf();
  return ss.str();
}

void write_golden(const char* path, const std::string& text) {
  std::ofstream f(path, std::ios::binary);
  f << text;
}

void assert_matches_golden(const char* path, const std::string& got) {
  if (update_mode()) {
    write_golden(path, got);
  }
  std::string golden = read_golden(path);
  ASSERT_EQ(got, golden);
}

}  // namespace

TEST(json_snapshot_matches_prometheus_golden) {
  SystemIdentityFixture id;
  auto s = make_fixture_snapshot();
  assert_matches_golden("tests/fixtures/synthetic_snapshot.prom.golden",
                        montauk::app::snapshot_to_prometheus(s));
}

TEST(json_snapshot_matches_json_golden) {
  SystemIdentityFixture id;
  auto s = make_fixture_snapshot();
  assert_matches_golden("tests/fixtures/synthetic_snapshot.json.golden",
                        montauk::app::snapshot_to_json(s));
}

TEST(trace_snapshot_matches_prometheus_golden) {
  auto t = make_fixture_trace();
  assert_matches_golden("tests/fixtures/synthetic_trace.prom.golden",
                        montauk::app::trace_to_prometheus(t));
}

TEST(trace_snapshot_matches_json_golden) {
  auto t = make_fixture_trace();
  assert_matches_golden("tests/fixtures/synthetic_trace.json.golden",
                        montauk::app::trace_to_json(t));
}
