// ThermalCollector: hwmon/thermal_zone temperature reading, with sysfs root
// redirection.
#include "minitest.hpp"
#include "env_guard.hpp"
#include "collectors/ThermalCollector.hpp"
#include <chrono>
#include <filesystem>
#include <fstream>
#include <thread>
#include <unistd.h>
#include "util/Procfs.hpp"

namespace fs = std::filesystem;

TEST(thermal_collector_reads_hwmon_with_sys_root) {
  auto root = fs::temp_directory_path() / fs::path("montauk_test_thermal_") / fs::path(std::to_string(::getpid()));
  fs::create_directories(root / "sys/class/hwmon/hwmon0");
  std::ofstream(root / "sys/class/hwmon/hwmon0/temp1_input") << 56000 << "\n"; // 56.000 C
  // also provide thermal_zone fallback
  fs::create_directories(root / "sys/class/thermal/thermal_zone0");
  std::ofstream(root / "sys/class/thermal/thermal_zone0/temp") << 56000 << "\n";
  TempRootGuard sys_root("MONTAUK_SYS_ROOT", root.string());
  // Sanity: mapped paths exist
  ASSERT_TRUE(std::filesystem::exists(montauk::util::map_sys_path("/sys/class/hwmon")));
  ASSERT_TRUE(std::filesystem::exists(montauk::util::map_sys_path("/sys/class/thermal")));
  montauk::collectors::ThermalCollector t;
  montauk::model::Thermal th{};
  ASSERT_TRUE(t.sample(th));
  ASSERT_TRUE(th.has_temp);
  ASSERT_TRUE(th.cpu_max_c > 55.0 && th.cpu_max_c < 57.0);
}

// C-state residency: the states are found once and only their times read
// after, so a residency is the time delta over cpu-time, aggregated by name,
// and a state that disappears (a CPU offlined) drops the baseline and is found
// again rather than read as a stale path or a delta across the change.
TEST(thermal_collector_cstate_residency_and_rediscovery) {
  auto root = fs::temp_directory_path() / fs::path("montauk_test_cstate_") / fs::path(std::to_string(::getpid()));
  auto state = [&](int cpu, int st, const char* name, long us) {
    auto d = root / ("sys/devices/system/cpu/cpu" + std::to_string(cpu)) / "cpuidle" / ("state" + std::to_string(st));
    fs::create_directories(d);
    std::ofstream(d / "name") << name << "\n";
    std::ofstream(d / "time") << us << "\n";
  };
  for (int cpu = 0; cpu < 2; cpu++) { state(cpu, 0, "POLL", 0); state(cpu, 1, "C1", 0); }
  TempRootGuard sys_root("MONTAUK_SYS_ROOT", root.string());
  montauk::collectors::ThermalCollector t;
  montauk::model::Thermal th{};
  (void)t.sample(th);
  ASSERT_TRUE(th.cstates.empty());   // the first sample is the baseline
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  for (int cpu = 0; cpu < 2; cpu++) state(cpu, 1, "C1", 50000);
  (void)t.sample(th);
  double c1 = -1.0;
  for (const auto& c : th.cstates) if (c.name == "C1") c1 = c.residency_pct;
  // 100,000 us of C1 over at least 0.1 s on two CPUs: at most 50%.
  ASSERT_TRUE(c1 > 30.0 && c1 <= 50.0);

  fs::remove_all(root / "sys/devices/system/cpu/cpu1/cpuidle/state1");
  (void)t.sample(th);
  ASSERT_TRUE(th.cstates.empty());   // the change is seen, not read across
  (void)t.sample(th);
  ASSERT_TRUE(th.cstates.empty());   // found again: a fresh baseline
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  state(0, 1, "C1", 150000);
  (void)t.sample(th);
  c1 = -1.0;
  for (const auto& c : th.cstates) if (c.name == "C1") c1 = c.residency_pct;
  ASSERT_TRUE(c1 > 30.0 && c1 <= 50.0);
  fs::remove_all(root);
}
