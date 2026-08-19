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
#include "util/fmt_double.h"
#include "util/json.h"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <sstream>
#include <vector>
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

// THE TWO FACES MUST FORMAT ONE DOUBLE ONE WAY.
//
// The JSON face used snprintf("%.12g") while the Prometheus face used
// std::to_chars, so one computed double rendered as two different strings --
// 1/3 as 0.333333333333 in JSON and 0.3333333333333333 in Prometheus. The
// byte-identical goldens could not catch it: each face was frozen against
// itself, so both were "correct" and neither was ever compared to the other.
//
// Both now call montauk_fmt_double, so the property to hold down is that the
// shared formatter is shortest round-trip and that the JSON face actually uses
// it. The Prometheus face is pinned by its own golden above, and calls the same
// function.
//
// An earlier version of this test scraped numeric literals out of the rendered
// text with a hand-rolled scanner. That scanner had an infinite loop on a date
// like 2026-08-17 and hung the suite. A test for a simple property should not
// need a parser -- this one asserts the property at the source instead.
TEST(shared_double_formatter_is_shortest_round_trip) {
  static const double vals[] = {
    1.0 / 3.0, 2.0 / 3.0, 0.1, 0.2, 0.3, 1.5, 100.0, 0.0, -0.0,
    3.141592653589793, 123456789.12345679, 1e30, 1e-30, 1e308, 5e-324, -2.5,
  };
  for (double v : vals) {
    char buf[40];
    int n = montauk_fmt_double(buf, sizeof buf, v);
    ASSERT_TRUE(n > 0);
    std::string got(buf, (size_t)n);
    // Shortest ROUND-TRIP: the text must read back as the identical double.
    // %.12g fails this on 1/3, which is the defect that started this.
    ASSERT_EQ(strtod(got.c_str(), nullptr), v);
    // And it must be canonical -- reformatting its own output is a fixed point,
    // so no caller can produce two spellings of one value.
    char again[40];
    int n2 = montauk_fmt_double(again, sizeof again, strtod(got.c_str(), nullptr));
    ASSERT_EQ(std::string(again, (size_t)n2), got);
  }
}

TEST(json_face_uses_the_shared_double_formatter) {
  static const double vals[] = {1.0 / 3.0, 0.1, 123456789.12345679, 1e30, -2.5};
  for (double v : vals) {
    montauk_sink sink;
    montauk_sink_init(&sink, -1);
    montauk_json j;
    montauk_json_init(&j, &sink);
    montauk_json_num(&j, v);

    char buf[40];
    int n = montauk_fmt_double(buf, sizeof buf, v);
    ASSERT_EQ(std::string(sink.data, sink.len), std::string(buf, (size_t)n));
    montauk_sink_free(&sink);
  }
}
