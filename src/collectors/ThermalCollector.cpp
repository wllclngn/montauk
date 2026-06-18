#include "collectors/ThermalCollector.hpp"
#include <filesystem>
#include <fstream>
#include <string>
#include <cerrno>
#include <chrono>
#include <cstdint>
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

  // /sys/class/hwmon/hwmonN are symlinks to the underlying device, and
  // recursive_directory_iterator does NOT descend symlinked directories -- so
  // it never saw any temp*_input and we fell back to thermal_zone (acpitz,
  // ~17C, not the CPU). Iterate each chip explicitly and read its files through
  // the link. Prefer a CPU-package chip (k10temp/coretemp/zenpower) for the
  // reported temp; a blind global max lands on whatever board/ACPI sensor reads
  // hottest. Fall back to the hottest hwmon sensor, then thermal_zone below.
  try {
    fs::path hw(montauk::util::map_sys_path("/sys/class/hwmon"));
    if (fs::exists(hw)) {
      double min_warn_c = 0.0; bool have_any_warn = false;
      double cpu_c = 0.0; bool have_cpu = false;  // hottest CPU-package sensor
      double any_c = 0.0; bool have_any = false;  // hottest hwmon sensor
      auto trim = [](std::string s) {
        while (!s.empty() && (s.back()=='\n'||s.back()=='\r'||s.back()==' '))
          s.pop_back();
        return s;
      };

      for (auto& chip : fs::directory_iterator(hw,
           fs::directory_options::skip_permission_denied)) {
        try {
          std::string chip_name;
          auto n = montauk::util::read_file_string((chip.path()/"name").string());
          if (n) chip_name = trim(*n);
          bool is_cpu = chip_name=="k10temp" || chip_name=="coretemp" ||
                        chip_name=="zenpower";

          for (auto& f : fs::directory_iterator(chip.path(),
               fs::directory_options::skip_permission_denied)) {
            auto name = f.path().filename().string();
            // Fan speed (RPM)
            if (name.rfind("fan",0)==0 && name.find("_input")!=std::string::npos) {
              long rpm = 0;
              if (read_number_file(f.path(), rpm) == ReadResult::Success && rpm > 0) {
                if (!out.has_fan || rpm > out.fan_rpm) {
                  out.has_fan = true;
                  out.fan_rpm = (double)rpm;
                }
              }
            }
            // Temperature
            if (name.rfind("temp",0)==0 && name.find("_input")!=std::string::npos) {
              long mdeg = 0;
              ReadResult res = read_number_file(f.path(), mdeg);
              if (res != ReadResult::Success) {
                if (res != ReadResult::FileNotFound) {
                  montauk::util::note_churn(montauk::util::ChurnKind::Sysfs);
                }
                continue;
              }

              double c = mdeg / 1000.0;
              if (c > any_c) { any_c = c; have_any = true; }
              if (is_cpu && c > cpu_c) { cpu_c = c; have_cpu = true; }

              auto base = name.substr(0, name.find("_input"));
              for (const char* suff : {"_crit", "_max", "_emergency"}) {
                long thr = 0;
                ReadResult thr_res = read_number_file(chip.path() / (base + suff), thr);
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
          }
        } catch (const fs::filesystem_error&) {
          montauk::util::note_churn(montauk::util::ChurnKind::Sysfs);
          continue;
        }
      }

      if (have_cpu)      { out.has_temp = true; out.cpu_max_c = cpu_c; }
      else if (have_any) { out.has_temp = true; out.cpu_max_c = any_c; }
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

  // RAPL / powercap package power: sum the top-level intel-rapl:N package
  // energy_uj counters (skip subzones intel-rapl:N:M to avoid double-count),
  // delta over wall time. Counter is monotonic microjoules; a wrap (now<prev)
  // is dropped for one interval.
  out.has_power = false;
  out.power_watts = 0.0;
  try {
    fs::path pc(montauk::util::map_sys_path("/sys/class/powercap"));
    if (fs::exists(pc)) {
      uint64_t energy_uj = 0;
      bool any = false;
      for (auto& e : fs::directory_iterator(pc,
           fs::directory_options::skip_permission_denied)) {
        std::string name = e.path().filename().string();
        if (name.rfind("intel-rapl:", 0) != 0) continue;     // package domains
        if (name.find(':', 11) != std::string::npos) continue;  // skip subzones
        std::ifstream f(e.path() / "energy_uj");
        uint64_t v = 0;
        if (f >> v) { energy_uj += v; any = true; }
      }
      if (any) {
        auto now = std::chrono::steady_clock::now();
        if (have_prev_energy_ && energy_uj >= prev_energy_uj_) {
          double dt = std::chrono::duration<double>(now - prev_energy_t_).count();
          if (dt > 0.0) {
            double interval_j = static_cast<double>(energy_uj - prev_energy_uj_) / 1e6;
            out.power_watts = interval_j / dt;
            out.has_power = true;
            // Integrate the (wrap-handled) interval energy. A counter wrap shows
            // as energy_uj < prev and is skipped, losing at most one interval per
            // wrap -- the same blind spot the instantaneous power already has.
            energy_accum_j_ += interval_j;
          }
        }
        prev_energy_uj_ = energy_uj;
        prev_energy_t_ = now;
        have_prev_energy_ = true;
        out.has_energy = true;
        out.energy_joules_total = energy_accum_j_;
      }
    }
  } catch (const fs::filesystem_error&) {
    montauk::util::note_churn(montauk::util::ChurnKind::Sysfs);
  }

  // C-state residency: sum each idle state's cumulative time (us) across all
  // cpuN/cpuidle/stateM, delta over wall time gives the fraction of total
  // cpu-time spent idle in that state. State names (POLL/C1/C2/C6/...) are
  // aggregated by name so the report is per-state, not per-(cpu,state).
  out.cstates.clear();
  try {
    fs::path cpubase(montauk::util::map_sys_path("/sys/devices/system/cpu"));
    if (fs::exists(cpubase)) {
      std::map<std::string, uint64_t> cur_us;
      int ncpu = 0;
      for (auto& cpu : fs::directory_iterator(cpubase,
           fs::directory_options::skip_permission_denied)) {
        std::string cname = cpu.path().filename().string();
        if (cname.rfind("cpu", 0) != 0 || cname.size() < 4) continue;
        if (cname[3] < '0' || cname[3] > '9') continue;  // cpu<N> only
        fs::path idle = cpu.path() / "cpuidle";
        if (!fs::exists(idle)) continue;
        ++ncpu;
        for (auto& st : fs::directory_iterator(idle,
             fs::directory_options::skip_permission_denied)) {
          if (st.path().filename().string().rfind("state", 0) != 0) continue;
          auto nm = montauk::util::read_file_string((st.path() / "name").string());
          long us = 0;
          if (read_number_file(st.path() / "time", us) != ReadResult::Success) continue;
          if (!nm) continue;
          std::string name = *nm;
          while (!name.empty() && (name.back() == '\n' || name.back() == ' ' ||
                                   name.back() == '\r')) name.pop_back();
          if (name.empty()) continue;
          cur_us[name] += (uint64_t)us;
        }
      }
      if (ncpu > 0 && !cur_us.empty()) {
        auto now = std::chrono::steady_clock::now();
        if (have_prev_cstate_) {
          double dt = std::chrono::duration<double>(now - prev_cstate_t_).count();
          double total_us = dt * 1e6 * (double)ncpu;
          if (total_us > 0.0) {
            for (const auto& [name, us] : cur_us) {
              auto it = prev_cstate_us_.find(name);
              if (it == prev_cstate_us_.end() || us < it->second) continue;
              double pct = (double)(us - it->second) / total_us * 100.0;
              if (pct < 0.0) pct = 0.0;
              if (pct > 100.0) pct = 100.0;
              out.cstates.push_back({name, pct});
            }
          }
        }
        prev_cstate_us_ = std::move(cur_us);
        prev_cstate_t_ = now;
        have_prev_cstate_ = true;
      }
    }
  } catch (const fs::filesystem_error&) {
    montauk::util::note_churn(montauk::util::ChurnKind::Sysfs);
  }

  return out.has_temp || out.has_power || !out.cstates.empty();
}

} // namespace montauk::collectors
