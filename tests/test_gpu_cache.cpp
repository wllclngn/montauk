#include "minitest.hpp"
#include "app/Producer.hpp"
#include "app/SnapshotBuffers.hpp"
#include <chrono>

using namespace std::chrono;

TEST(gpu_cache_persists_between_samples) {
  montauk::app::SnapshotBuffers bufs;
  montauk::app::Producer prod(bufs);

  montauk::model::ProcessSnapshot procs{};
  montauk::model::ProcSample p{}; p.pid = 4242; p.cmd = "gpuwork"; p.has_gpu_util = false; p.gpu_util_pct = 0.0;
  procs.processes.push_back(p);

  auto t0 = steady_clock::now();
  // First: fresh sample (25%) should be applied
  prod.test_apply_gpu_samples({{4242, 25}}, procs, t0);
  ASSERT_TRUE(procs.processes[0].has_gpu_util);
  ASSERT_TRUE((int)(procs.processes[0].gpu_util_pct + 0.5) == 25);

  // Simulate next cycle with no new samples, within TTL => value should persist
  procs.processes[0].has_gpu_util = false; procs.processes[0].gpu_util_pct = 0.0;
  auto t1 = t0 + milliseconds(1500);
  prod.test_apply_gpu_samples({}, procs, t1);
  ASSERT_TRUE(procs.processes[0].has_gpu_util);
  ASSERT_TRUE((int)(procs.processes[0].gpu_util_pct + 0.5) == 25);

  // After TTL expires, no new sample => should not set has_gpu_util (renderer shows 0)
  procs.processes[0].has_gpu_util = false; procs.processes[0].gpu_util_pct = 0.0;
  auto t2 = t0 + milliseconds(2500);
  prod.test_apply_gpu_samples({}, procs, t2);
  ASSERT_TRUE(!procs.processes[0].has_gpu_util);
}
