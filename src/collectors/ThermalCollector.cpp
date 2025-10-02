#include "collectors/ThermalCollector.hpp"
#include <filesystem>
#include <fstream>
#include <string>
#include "util/Procfs.hpp"

namespace fs = std::filesystem;

namespace montauk::collectors {

static bool read_number_file(const fs::path& p, long& out) {
  std::ifstream f(p);
  if (!f) return false;
  f >> out; return f.good();
}

// Read from hwmon first; fallback to thermal_zone
bool ThermalCollector::sample(montauk::model::Thermal& out) {
  out.has_temp = false; out.cpu_max_c = 0.0; out.has_warn = false; out.warn_c = 0.0;
  // hwmon: /sys/class/hwmon/hwmon*/temp*_input (millidegrees C)
  try {
    fs::path hw(montauk::util::map_sys_path("/sys/class/hwmon"));
    if (fs::exists(hw)) {
      double min_warn_c = 0.0; bool have_any_warn = false;
      for (auto& e : fs::recursive_directory_iterator(hw)) {
        auto name = e.path().filename().string();
        if (name.rfind("temp",0)==0 && name.find("_input")!=std::string::npos) {
          long mdeg = 0; if (!read_number_file(e.path(), mdeg)) continue;
          double c = mdeg / 1000.0;
          if (!out.has_temp || c > out.cpu_max_c) { out.has_temp = true; out.cpu_max_c = c; }
          // Try to discover a warning threshold for this sensor
          auto base = name.substr(0, name.find("_input"));
          for (const char* suff : {"_crit", "_max", "_emergency"}) {
            long thr = 0;
            if (read_number_file(e.path().parent_path() / (base + suff), thr)) {
              double tc = thr / 1000.0;
              if (!have_any_warn || tc < min_warn_c) { min_warn_c = tc; have_any_warn = true; }
              break;
            }
          }
        }
      }
      if (have_any_warn) { out.has_warn = true; out.warn_c = min_warn_c; }
    }
    if (!out.has_temp) {
      fs::path tz(montauk::util::map_sys_path("/sys/class/thermal"));
      if (fs::exists(tz)) {
        for (auto& z : fs::directory_iterator(tz)) {
          if (z.path().filename().string().rfind("thermal_zone",0)!=0) continue;
          long mdeg=0; if (!read_number_file(z.path()/"temp", mdeg)) continue;
          double c = mdeg / 1000.0;
          if (!out.has_temp || c > out.cpu_max_c) { out.has_temp = true; out.cpu_max_c = c; }
        }
      }
    }
  } catch (...) {
    // ignore
  }
  return out.has_temp;
}

} // namespace montauk::collectors
