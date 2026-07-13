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
#include "fixtures/metrics_fixture.hpp"
#include "app/MetricsServer.hpp"

#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>

namespace {

bool update_mode() {
  const char* v = std::getenv("MONTAUK_UPDATE_GOLDEN");
  return v && v[0] == '1';
}

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
  auto s = make_fixture_snapshot();
  assert_matches_golden("tests/fixtures/synthetic_snapshot.prom.golden",
                        montauk::app::snapshot_to_prometheus(s));
}

TEST(json_snapshot_matches_json_golden) {
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
