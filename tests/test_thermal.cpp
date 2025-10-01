#include "minitest.hpp"
#include "collectors/ThermalCollector.hpp"
#include <filesystem>
#include <fstream>
#include <unistd.h>
#include "util/Procfs.hpp"

namespace fs = std::filesystem;

TEST(thermal_collector_reads_hwmon_with_sys_root) {
  auto root = fs::temp_directory_path() / fs::path("lsm_cpp_test_thermal_") / fs::path(std::to_string(::getpid()));
  fs::create_directories(root / "sys/class/hwmon/hwmon0");
  std::ofstream(root / "sys/class/hwmon/hwmon0/temp1_input") << 56000 << "\n"; // 56.000 C
  // also provide thermal_zone fallback
  fs::create_directories(root / "sys/class/thermal/thermal_zone0");
  std::ofstream(root / "sys/class/thermal/thermal_zone0/temp") << 56000 << "\n";
  setenv("LSM_SYS_ROOT", root.c_str(), 1);
  // Sanity: mapped paths exist
  ASSERT_TRUE(std::filesystem::exists(lsm::util::map_sys_path("/sys/class/hwmon")));
  ASSERT_TRUE(std::filesystem::exists(lsm::util::map_sys_path("/sys/class/thermal")));
  lsm::collectors::ThermalCollector t;
  lsm::model::Thermal th{};
  ASSERT_TRUE(t.sample(th));
  ASSERT_TRUE(th.has_temp);
  ASSERT_TRUE(th.cpu_max_c > 55.0 && th.cpu_max_c < 57.0);
}
