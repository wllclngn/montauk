#include "collectors/ThermalCollector.hpp"
#include <string>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include "util/Procfs.hpp"
#include "util/Churn.hpp"

namespace montauk::collectors {

using montauk::util::read_number;

// A failed read of an input found earlier: gone (the device unbound, so the
// sensors are found again) or churn.
static bool gone_or_churn() {
  if (errno == ENOENT) return true;
  montauk::util::note_churn(montauk::util::ChurnKind::Sysfs);
  return false;
}

void ThermalCollector::find_sensors(size_t hwmon_entries) {
  temps_.clear(); fans_.clear(); zones_.clear(); rapl_.clear();
  hwmon_entries_ = hwmon_entries;
  sensors_found_ = true;
  // /sys/class/hwmon/hwmonN are symlinks to the underlying device; each chip
  // is read through its link. A CPU-package chip (k10temp/coretemp/zenpower)
  // gives the reported temperature where there is one: A blind maximum lands
  // on whatever board or ACPI sensor reads hottest.
  for (const auto& chip : montauk::util::list_dir("/sys/class/hwmon")) {
    const std::string dir = "/sys/class/hwmon/" + chip;
    auto files = montauk::util::read_dir(dir);
    if (!files) continue;
    std::string name;
    if (auto n = montauk::util::read_line(dir + "/name")) name = *n;
    const bool cpu = name == "k10temp" || name == "coretemp" || name == "zenpower";
    for (const auto& f : *files) {
      const bool input = f.find("_input") != std::string::npos;
      if (input && f.rfind("fan", 0) == 0) fans_.push_back(dir + "/" + f);
      if (!input || f.rfind("temp", 0) != 0) continue;
      TempInput ti{dir + "/" + f, cpu, false, 0.0};
      const std::string base = f.substr(0, f.find("_input"));
      for (const char* suff : {"_crit", "_max", "_emergency"}) {
        long long thr = 0;
        if (read_number(dir + "/" + base + suff, thr)) {
          ti.has_thr = true;
          ti.thr_c = (double)thr / 1000.0;
          break;
        }
        if (errno != ENOENT) montauk::util::note_churn(montauk::util::ChurnKind::Sysfs);
      }
      temps_.push_back(std::move(ti));
    }
  }
  for (const auto& z : montauk::util::list_dir("/sys/class/thermal"))
    if (z.rfind("thermal_zone", 0) == 0) zones_.push_back("/sys/class/thermal/" + z + "/temp");
  // RAPL package domains only: intel-rapl:N, never a subzone intel-rapl:N:M,
  // which would count its package twice.
  for (const auto& e : montauk::util::list_dir("/sys/class/powercap"))
    if (e.rfind("intel-rapl:", 0) == 0 && e.find(':', 11) == std::string::npos)
      rapl_.push_back("/sys/class/powercap/" + e + "/energy_uj");
}

static bool is_cpu_entry(const std::string& n) {
  return n.size() > 3 && n.rfind("cpu", 0) == 0 && n[3] >= '0' && n[3] <= '9';
}

void ThermalCollector::find_cstates(size_t cpu_entries) {
  cstate_files_.clear(); cstate_names_.clear(); cstate_ncpu_ = 0;
  cstate_cpu_entries_ = cpu_entries;
  cstate_found_ = true;
  for (const auto& cpu : montauk::util::list_dir("/sys/devices/system/cpu")) {
    if (!is_cpu_entry(cpu)) continue;
    const std::string idle = "/sys/devices/system/cpu/" + cpu + "/cpuidle";
    auto states = montauk::util::read_dir(idle);
    if (!states) continue;
    ++cstate_ncpu_;
    for (const auto& st : *states) {
      if (st.rfind("state", 0) != 0) continue;
      auto nm = montauk::util::read_line(idle + "/" + st + "/name");
      if (!nm || nm->empty()) continue;
      const std::string& name = *nm;
      size_t idx = 0;
      while (idx < cstate_names_.size() && cstate_names_[idx] != name) idx++;
      if (idx == cstate_names_.size()) cstate_names_.push_back(name);
      cstate_files_.push_back({idle + "/" + st + "/time", idx});
    }
  }
}

// Read from hwmon first; fallback to thermal_zone. The sensors are found once
// (find_sensors) and only their inputs read here: The walk this replaced listed
// every chip and reopened every threshold through a stream on every sample.
bool ThermalCollector::sample(montauk::model::Thermal& out) {
  out.has_temp = false; out.cpu_max_c = 0.0; out.has_warn = false; out.warn_c = 0.0;
  out.has_fan = false; out.fan_rpm = 0.0;
  const size_t hwmon_entries = montauk::util::list_dir("/sys/class/hwmon").size();
  if (!sensors_found_ || hwmon_entries != hwmon_entries_) find_sensors(hwmon_entries);
  bool gone = false;

  double min_warn_c = 0.0; bool have_any_warn = false;
  double cpu_c = 0.0; bool have_cpu = false;  // hottest CPU-package sensor
  double any_c = 0.0; bool have_any = false;  // hottest hwmon sensor
  for (const TempInput& ti : temps_) {
    long long mdeg = 0;
    if (!read_number(ti.path, mdeg)) { gone |= gone_or_churn(); continue; }
    const double c = (double)mdeg / 1000.0;
    if (c > any_c) { any_c = c; have_any = true; }
    if (ti.cpu && c > cpu_c) { cpu_c = c; have_cpu = true; }
    if (ti.has_thr && (!have_any_warn || ti.thr_c < min_warn_c)) { min_warn_c = ti.thr_c; have_any_warn = true; }
  }
  if (have_cpu)      { out.has_temp = true; out.cpu_max_c = cpu_c; }
  else if (have_any) { out.has_temp = true; out.cpu_max_c = any_c; }
  if (have_any_warn) { out.has_warn = true; out.warn_c = min_warn_c; }
  for (const std::string& f : fans_) {
    long long rpm = 0;
    if (!read_number(f, rpm)) { gone |= errno == ENOENT; continue; }
    if (rpm > 0 && (!out.has_fan || (double)rpm > out.fan_rpm)) { out.has_fan = true; out.fan_rpm = (double)rpm; }
  }

  if (!out.has_temp) {
    for (const std::string& z : zones_) {
      long long mdeg = 0;
      if (!read_number(z, mdeg)) { gone |= gone_or_churn(); continue; }
      const double c = (double)mdeg / 1000.0;
      if (!out.has_temp || c > out.cpu_max_c) { out.has_temp = true; out.cpu_max_c = c; }
    }
  }

  // RAPL / powercap package power: the package energy_uj counters summed, a
  // delta over wall time. The counter is monotonic microjoules; a wrap
  // (now < prev) is dropped for one interval.
  out.has_power = false;
  out.power_watts = 0.0;
  uint64_t energy_uj = 0;
  bool any = false;
  for (const std::string& r : rapl_) {
    unsigned long long v = 0;
    if (read_number(r, v)) { energy_uj += v; any = true; }
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
  // A sensor that went away (a device unbound) is found again next sample.
  if (gone) sensors_found_ = false;

  // C-state residency: sum each idle state's cumulative time (us) across all
  // cpuN/cpuidle/stateM, delta over wall time gives the fraction of total
  // cpu-time spent idle in that state. State names (POLL/C1/C2/C6/...) are
  // aggregated by name so the report is per-state, not per-(cpu,state). The
  // states are found once (find_cstates) and only their times read here: The
  // whole walk reopened every state's name through a stream for every CPU on
  // every sample.
  out.cstates.clear();
  size_t cpu_entries = 0;
  for (const auto& cpu : montauk::util::list_dir("/sys/devices/system/cpu"))
    if (is_cpu_entry(cpu)) cpu_entries++;
  if (!cstate_found_ || cpu_entries != cstate_cpu_entries_) find_cstates(cpu_entries);
  if (cstate_ncpu_ > 0 && !cstate_files_.empty()) {
    std::vector<uint64_t> sums(cstate_names_.size(), 0);
    bool complete = true;
    for (const auto& f : cstate_files_) {
      unsigned long long us = 0;
      if (!read_number(f.time_path, us)) { complete = false; break; }
      sums[f.name_idx] += us;
    }
    if (!complete) {
      // A state went away (a CPU offlined): find them again next sample, and
      // drop the baseline rather than take a delta across the change.
      cstate_found_ = false;
      have_prev_cstate_ = false;
    } else {
      std::map<std::string, uint64_t> cur_us;
      for (size_t i = 0; i < sums.size(); i++) cur_us[cstate_names_[i]] = sums[i];
      auto now = std::chrono::steady_clock::now();
      if (have_prev_cstate_) {
        double dt = std::chrono::duration<double>(now - prev_cstate_t_).count();
        double total_us = dt * 1e6 * (double)cstate_ncpu_;
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

  return out.has_temp || out.has_power || !out.cstates.empty();
}

} // namespace montauk::collectors
