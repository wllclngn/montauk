#include "minitest.hpp"
#include "app/MetricsServer.hpp"
#include <string>

TEST(prometheus_serializer_cpu_gauge) {
  montauk::app::MetricsSnapshot snap{};
  snap.cpu.usage_pct = 42.5;
  snap.cpu.physical_cores = 8;
  snap.cpu.logical_threads = 16;
  std::string out = montauk::app::snapshot_to_prometheus(snap);
  ASSERT_TRUE(out.find("# TYPE montauk_cpu_usage_percent gauge") != std::string::npos);
  ASSERT_TRUE(out.find("montauk_cpu_usage_percent 42") != std::string::npos);
  ASSERT_TRUE(out.find("montauk_cpu_physical_cores 8") != std::string::npos);
  ASSERT_TRUE(out.find("montauk_cpu_logical_threads 16") != std::string::npos);
}

TEST(prometheus_serializer_memory_bytes) {
  montauk::app::MetricsSnapshot snap{};
  snap.mem.total_kb = 16000000;     // ~16 GB
  snap.mem.used_kb = 8000000;
  snap.mem.available_kb = 8000000;
  snap.mem.used_pct = 50.0;
  std::string out = montauk::app::snapshot_to_prometheus(snap);
  // 16000000 * 1024 = 16384000000
  ASSERT_TRUE(out.find("montauk_memory_total_bytes 16384000000") != std::string::npos);
  ASSERT_TRUE(out.find("montauk_memory_used_bytes 8192000000") != std::string::npos);
}

TEST(prometheus_serializer_per_core_labels) {
  montauk::app::MetricsSnapshot snap{};
  snap.cpu.per_core_pct = {10.0, 20.0, 30.0, 40.0};
  std::string out = montauk::app::snapshot_to_prometheus(snap);
  ASSERT_TRUE(out.find("# TYPE montauk_cpu_core_usage_percent gauge") != std::string::npos);
  ASSERT_TRUE(out.find("{core=\"0\"}") != std::string::npos);
  ASSERT_TRUE(out.find("{core=\"3\"}") != std::string::npos);
}

TEST(prometheus_serializer_process_top_n) {
  montauk::app::MetricsSnapshot snap{};
  constexpr int N = 20;
  for (int i = 0; i < N; ++i) {
    snap.top_procs[i].pid = 1000 + i;
    snap.top_procs[i].cpu_pct = static_cast<double>(N - i);
    snap.top_procs[i].rss_kb = 100000;
    snap.top_procs[i].cmd = "proc" + std::to_string(i);
  }
  snap.top_procs_count = N;
  std::string out = montauk::app::snapshot_to_prometheus(snap);
  // Count montauk_process_cpu_percent lines (excluding HELP/TYPE)
  int count = 0;
  size_t pos = 0;
  while ((pos = out.find("montauk_process_cpu_percent{", pos)) != std::string::npos) {
    ++count; ++pos;
  }
  ASSERT_EQ(count, N);
}

TEST(prometheus_serializer_empty) {
  montauk::app::MetricsSnapshot snap{};
  std::string out = montauk::app::snapshot_to_prometheus(snap);
  ASSERT_TRUE(!out.empty());
  ASSERT_TRUE(out.find("montauk_cpu_usage_percent") != std::string::npos);
  ASSERT_TRUE(out.find("montauk_processes_total") != std::string::npos);
}
