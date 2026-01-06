#include "collectors/ThermalCollector.hpp"
#include <filesystem>
#include <fstream>
#include <string>
#include <cerrno>
#include "util/Procfs.hpp"
#include "util/Churn.hpp"

namespace fs = std::filesystem;

namespace montauk::collectors {

enum class ReadResult {
  Success,
  FileNotFound,
  ParseError,
  PermissionDenied
};

static ReadResult read_number_file(const fs::path& p, long& out) {
  std::ifstream f(p);
  if (!f) {
    if (errno == ENOENT) {
      return ReadResult::FileNotFound;
    } else if (errno == EACCES) {
      return ReadResult::PermissionDenied;
    }
    return ReadResult::FileNotFound;
  }
  
  f >> out;
  if (!f.good()) {
    return ReadResult::ParseError;
  }
  
  return ReadResult::Success;
}

// Read from hwmon first; fallback to thermal_zone
bool ThermalCollector::sample(montauk::model::Thermal& out) {
  out.has_temp = false; out.cpu_max_c = 0.0; out.has_warn = false; out.warn_c = 0.0;
  out.has_fan = false; out.fan_rpm = 0.0;

  try {
    fs::path hw(montauk::util::map_sys_path("/sys/class/hwmon"));
    if (fs::exists(hw)) {
      double min_warn_c = 0.0; bool have_any_warn = false;

      for (auto& e : fs::recursive_directory_iterator(hw,
           fs::directory_options::skip_permission_denied)) {
        try {
          auto name = e.path().filename().string();
          // Fan speed (RPM)
          if (name.rfind("fan",0)==0 && name.find("_input")!=std::string::npos) {
            long rpm = 0;
            ReadResult res = read_number_file(e.path(), rpm);
            if (res == ReadResult::Success && rpm > 0) {
              if (!out.has_fan || rpm > out.fan_rpm) {
                out.has_fan = true;
                out.fan_rpm = (double)rpm;
              }
            }
          }
          // Temperature
          if (name.rfind("temp",0)==0 && name.find("_input")!=std::string::npos) {
            long mdeg = 0; 
            ReadResult res = read_number_file(e.path(), mdeg);
            if (res != ReadResult::Success) {
              if (res != ReadResult::FileNotFound) {
                montauk::util::note_churn(montauk::util::ChurnKind::Sysfs);
              }
              continue;
            }
            
            double c = mdeg / 1000.0;
            if (!out.has_temp || c > out.cpu_max_c) { 
              out.has_temp = true; 
              out.cpu_max_c = c; 
            }
            
            auto base = name.substr(0, name.find("_input"));
            for (const char* suff : {"_crit", "_max", "_emergency"}) {
              long thr = 0;
              ReadResult thr_res = read_number_file(e.path().parent_path() / (base + suff), thr);
              if (thr_res == ReadResult::Success) {
                double tc = thr / 1000.0;
                if (!have_any_warn || tc < min_warn_c) { 
                  min_warn_c = tc; 
                  have_any_warn = true; 
                }
                break;
              } else if (thr_res != ReadResult::FileNotFound) {
                montauk::util::note_churn(montauk::util::ChurnKind::Sysfs);
              }
            }
          }
        } catch (const fs::filesystem_error&) {
          montauk::util::note_churn(montauk::util::ChurnKind::Sysfs);
          continue;
        }
      }
      
      if (have_any_warn) { 
        out.has_warn = true; 
        out.warn_c = min_warn_c; 
      }
    }
  } catch (const fs::filesystem_error&) {
    montauk::util::note_churn(montauk::util::ChurnKind::Sysfs);
  }
  
  if (!out.has_temp) {
    try {
      fs::path tz(montauk::util::map_sys_path("/sys/class/thermal"));
      if (fs::exists(tz)) {
        for (auto& z : fs::directory_iterator(tz)) {
          try {
            if (z.path().filename().string().rfind("thermal_zone",0)!=0) 
              continue;
            
            long mdeg=0; 
            ReadResult res = read_number_file(z.path()/"temp", mdeg);
            if (res != ReadResult::Success) {
              if (res != ReadResult::FileNotFound) {
                montauk::util::note_churn(montauk::util::ChurnKind::Sysfs);
              }
              continue;
            }
            
            double c = mdeg / 1000.0;
            if (!out.has_temp || c > out.cpu_max_c) { 
              out.has_temp = true; 
              out.cpu_max_c = c; 
            }
          } catch (const fs::filesystem_error&) {
            montauk::util::note_churn(montauk::util::ChurnKind::Sysfs);
            continue;
          }
        }
      }
    } catch (const fs::filesystem_error&) {
      montauk::util::note_churn(montauk::util::ChurnKind::Sysfs);
    }
  }
  
  return out.has_temp;
}

} // namespace montauk::collectors
