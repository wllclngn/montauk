#include "collectors/CpuCollector.hpp"
#include "util/Procfs.hpp"
#include <string>
#include <sstream>
#include <map>
#include <chrono>

#include <string_view>

namespace montauk::collectors {

static void parse_cpu_line(const std::string_view& line, montauk::model::CpuTimes& out) {
  // line starts with 'cpu' or 'cpuN'
  size_t pos = 0; // skip label
  // find first space after label
  pos = line.find(' ');
  if (pos == std::string::npos) return;
  std::string_view rest = line.substr(pos + 1);
  // read 8 numbers
  uint64_t vals[8]{}; int i = 0;
  size_t start = 0;
  while (i < 8 && start < rest.size()) {
    // skip spaces
    while (start < rest.size() && (rest[start] == ' ' || rest[start] == '\t')) ++start;
    size_t end = start;
    while (end < rest.size() && rest[end] >= '0' && rest[end] <= '9') ++end;
    if (end > start) {
      vals[i++] = std::strtoull(std::string(rest.substr(start, end - start)).c_str(), nullptr, 10);
    }
    start = end + 1;
  }
  out.user = vals[0]; out.nice = vals[1]; out.system = vals[2]; out.idle = vals[3];
  out.iowait = vals[4]; out.irq = vals[5]; out.softirq = vals[6]; out.steal = vals[7];
}

bool CpuCollector::sample(montauk::model::CpuSnapshot& out) {
  // Load CPU model once
  if (cpu_model_.empty()) {
    auto txt_opt = montauk::util::read_file_string("/proc/cpuinfo");
    if (txt_opt) {
      std::istringstream ss(*txt_opt);
      std::string line;
      std::string model;
      // For physical cores per socket
      std::string cur_phys;
      int cur_cpu_cores = -1;
      std::map<std::string,int> socket_cores;
      int logical_count_cpuinfo = 0;
      while (std::getline(ss, line)) {
        // common on x86
        if (line.rfind("model name", 0) == 0) {
          auto pos = line.find(':');
          if (pos != std::string::npos) { model = line.substr(pos + 1); }
          // don't break; we want to parse full file
        }
        // arm variations
        if (line.rfind("Hardware", 0) == 0 || line.rfind("Processor", 0) == 0) {
          auto pos = line.find(':');
          if (pos != std::string::npos) { model = line.substr(pos + 1); }
        }
        if (line.rfind("physical id", 0) == 0) {
          auto pos = line.find(':'); if (pos!=std::string::npos) cur_phys = line.substr(pos+1);
        }
        if (line.rfind("cpu cores", 0) == 0) {
          auto pos = line.find(':'); if (pos!=std::string::npos) {
            try { cur_cpu_cores = std::stoi(line.substr(pos+1)); } catch(...) { cur_cpu_cores=-1; }
          }
        }
        if (line.rfind("processor", 0) == 0) {
          // counts logical entries
          logical_count_cpuinfo++;
        }
        if (line.empty()) {
          if (!cur_phys.empty() && cur_cpu_cores > 0) {
            socket_cores.emplace(cur_phys, cur_cpu_cores);
          }
          cur_phys.clear(); cur_cpu_cores = -1;
        }
      }
      // trim spaces
      auto trim = [](std::string s){ while(!s.empty() && (s.front()==' '||s.front()=='\t')) s.erase(s.begin()); while(!s.empty() && (s.back()==' '||s.back()=='\t'||s.back()=='\r')) s.pop_back(); return s; };
      cpu_model_ = trim(model);
      // compute physical cores (best effort)
      int phys_total = 0;
      for (const auto& kv : socket_cores) { phys_total += kv.second; }
      // store as a side-effect in model string? we'll attach to snapshot later using members below
      // We cannot set out here; keep in member variables? Simpler: reuse socket_cores later? Not persisted; so pass via snapshot below using computed values from per_core size.
      // We'll stash phys_total in a static for this run
      static int g_phys_cache = 0; if (g_phys_cache==0) g_phys_cache = phys_total;
      // Use g_phys_cache in snapshot below
      (void)g_phys_cache;
    }
  }
  auto txt_opt = montauk::util::read_file_string("/proc/stat");
  if (!txt_opt) return false;
  const std::string& txt = *txt_opt;
  montauk::model::CpuTimes agg{}; std::vector<montauk::model::CpuTimes> per;
  uint64_t ctxt = 0, intr = 0;
  size_t start = 0; bool after_cpu = false;
  while (start < txt.size()) {
    size_t end = txt.find('\n', start); if (end == std::string::npos) end = txt.size();
    std::string_view line(txt.data() + start, end - start);
    if (line.starts_with("cpu ")) { parse_cpu_line(line, agg); after_cpu = true; }
    else if (after_cpu && line.starts_with("cpu")) { montauk::model::CpuTimes t{}; parse_cpu_line(line, t); per.push_back(t); }
    else if (line.starts_with("ctxt ")) {
      size_t pos = line.find(' ');
      if (pos != std::string::npos) {
        ctxt = std::strtoull(std::string(line.substr(pos + 1)).c_str(), nullptr, 10);
      }
    }
    else if (line.starts_with("intr ")) {
      size_t pos = line.find(' ');
      if (pos != std::string::npos) {
        // First number after "intr" is total interrupts
        std::string_view rest = line.substr(pos + 1);
        size_t space_pos = rest.find(' ');
        if (space_pos != std::string::npos) {
          intr = std::strtoull(std::string(rest.substr(0, space_pos)).c_str(), nullptr, 10);
        } else {
          intr = std::strtoull(std::string(rest).c_str(), nullptr, 10);
        }
      }
    }
    start = end + 1;
  }
  
  // Calculate rates for ctxt and intr
  auto now = std::chrono::steady_clock::now();
  double ctxt_per_sec = 0.0, intr_per_sec = 0.0;
  if (has_last_ && last_sample_time_.time_since_epoch().count() != 0) {
    auto dt = std::chrono::duration<double>(now - last_sample_time_).count();
    if (dt > 0.0) {
      if (ctxt >= last_ctxt_) ctxt_per_sec = (double)(ctxt - last_ctxt_) / dt;
      if (intr >= last_intr_) intr_per_sec = (double)(intr - last_intr_) / dt;
    }
  }
  last_ctxt_ = ctxt;
  last_intr_ = intr;
  last_sample_time_ = now;
  
  // compute deltas
  double usage = 0.0; std::vector<double> per_pct(per.size(), 0.0);
  double pct_user = 0.0, pct_sys = 0.0, pct_iow = 0.0, pct_irq = 0.0, pct_steal = 0.0;
  if (has_last_) {
    auto td = agg.total() - last_total_.total();
    auto wd = agg.work()  - last_total_.work();
    usage = (td > 0) ? (100.0 * static_cast<double>(wd) / static_cast<double>(td)) : 0.0;
    if (td > 0) {
      double inv = 100.0 / static_cast<double>(td);
      pct_user  = inv * ( (double)(agg.user   - last_total_.user) + (double)(agg.nice - last_total_.nice) );
      pct_sys   = inv * ( (double)(agg.system - last_total_.system) );
      pct_iow   = inv * ( (double)(agg.iowait - last_total_.iowait) );
      pct_irq   = inv * ( (double)(agg.irq    - last_total_.irq) + (double)(agg.softirq - last_total_.softirq) );
      pct_steal = inv * ( (double)(agg.steal  - last_total_.steal) );
    }
    for (size_t i = 0; i < per.size(); ++i) {
      if (i < last_per_.size()) {
        auto tdi = per[i].total() - last_per_[i].total();
        auto wdi = per[i].work()  - last_per_[i].work();
        per_pct[i] = (tdi > 0) ? (100.0 * static_cast<double>(wdi) / static_cast<double>(tdi)) : 0.0;
      }
    }
  }
  last_total_ = agg; last_per_ = per; has_last_ = true;
  out.total_times = agg; out.per_core = std::move(per); out.usage_pct = usage; out.per_core_pct = std::move(per_pct);
  out.pct_user = pct_user; out.pct_system = pct_sys; out.pct_iowait = pct_iow; out.pct_irq = pct_irq; out.pct_steal = pct_steal;
  out.ctxt_per_sec = ctxt_per_sec;
  out.intr_per_sec = intr_per_sec;
  if (!cpu_model_.empty()) out.model = cpu_model_;
  // Set logical threads from per-core count
  out.logical_threads = (int)out.per_core_pct.size(); if (out.logical_threads<=0) out.logical_threads = 1;
  // best-effort physical core count
  {
    static int g_phys_cache = 0; // filled during first cpuinfo parse
    if (g_phys_cache > 0) out.physical_cores = g_phys_cache;
    else out.physical_cores = 0; // unknown
  }
  return true;
}

} // namespace montauk::collectors
