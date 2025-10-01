#include "collectors/GpuCollector.hpp"
#include "util/Procfs.hpp"

#include <filesystem>
#include <cstdio>
#include <regex>
#include <string_view>
#include <fstream>
#include <sstream>
#include <unordered_set>

namespace fs = std::filesystem;

namespace lsm::collectors {

static std::string trim(std::string s) {
  auto issp = [](unsigned char c){ return c==' '||c=='\t'||c=='\r'||c=='\n'; };
  while (!s.empty() && issp(s.front())) s.erase(s.begin());
  while (!s.empty() && issp(s.back())) s.pop_back();
  return s;
}

static bool read_nvidia_proc(lsm::model::GpuVram& out) {
  fs::path root(lsm::util::map_proc_path("/proc/driver/nvidia/gpus"));
  if (!fs::exists(root)) return false;
  bool any = false;
  uint64_t total_mb_sum = 0, used_mb_sum = 0;
  std::vector<std::string> model_names;
  for (auto& entry : fs::directory_iterator(root)) {
    if (!entry.is_directory()) continue;
    auto p = entry.path() / "fb_memory_usage";
    auto txt = lsm::util::read_file_string(p.string());
    if (!txt) continue;
    uint64_t total_mb = 0, used_mb = 0;
    for (const auto& line : {std::string("Total"), std::string("Used")}) {
      size_t pos = txt->find(line);
      if (pos == std::string::npos) continue;
      size_t colon = txt->find(':', pos);
      if (colon == std::string::npos) continue;
      size_t end = txt->find('\n', colon + 1);
      std::string_view val(txt->data() + colon + 1, (end == std::string::npos ? txt->size() : end) - (colon + 1));
      // Extract integer before optional MiB
      std::string s(val);
      std::smatch m; std::regex r(R"((\d+))");
      if (std::regex_search(s, m, r)) {
        uint64_t v = std::stoull(m[1].str());
        if (line == "Total") total_mb = v;
        else used_mb = v;
      }
    }
    // Try to read a friendly model name
    std::string friendly = entry.path().filename().string();
    try {
      auto inf = entry.path() / "information";
      std::ifstream in(inf);
      if (in) {
        std::string line;
        while (std::getline(in, line)) {
          if (line.rfind("Model:", 0) == 0) {
            auto pos = line.find(':');
            if (pos != std::string::npos) {
              friendly = trim(line.substr(pos + 1));
            }
            break;
          }
        }
      }
    } catch (...) { /* ignore */ }

    if (total_mb > 0) {
      any = true;
      total_mb_sum += total_mb;
      used_mb_sum  += used_mb;
      out.devices.push_back(lsm::model::GpuVramDevice{ friendly, total_mb, used_mb });
      model_names.push_back(friendly);
    }
  }
  if (any) {
    out.total_mb = total_mb_sum;
    out.used_mb  = used_mb_sum;
    out.used_pct = out.total_mb ? (100.0 * static_cast<double>(out.used_mb) / static_cast<double>(out.total_mb)) : 0.0;
    // Aggregate a concise name
    if (!model_names.empty()) {
      std::unordered_set<std::string> uniq(model_names.begin(), model_names.end());
      if (uniq.size() == 1) {
        out.name = *uniq.begin();
        if (model_names.size() > 1) out.name += " x" + std::to_string(model_names.size());
      } else {
        out.name = model_names[0] + " +" + std::to_string(model_names.size()-1) + " more";
      }
    }
  }
  return any;
}

static bool read_amd_sysfs(lsm::model::GpuVram& out) {
  fs::path drm(lsm::util::map_sys_path("/sys/class/drm"));
  if (!fs::exists(drm)) return false;
  bool any = false;
  uint64_t total_mb_sum = 0, used_mb_sum = 0;
  std::vector<std::string> names;
  for (auto& entry : fs::directory_iterator(drm)) {
    auto name = entry.path().filename().string();
    if (!entry.is_directory()) continue;
    if (!name.starts_with("card")) continue;
    auto dev = entry.path() / "device";
    auto tot = dev / "mem_info_vram_total";
    auto usd = dev / "mem_info_vram_used";
    if (!fs::exists(tot) || !fs::exists(usd)) continue;
    auto s_tot = lsm::util::read_file_string(tot.string());
    auto s_usd = lsm::util::read_file_string(usd.string());
    if (!s_tot || !s_usd) continue;
    uint64_t t = 0, u = 0;
    try {
      t = std::stoull(*s_tot);
      u = std::stoull(*s_usd);
    } catch (...) { continue; }
    // Values are bytes; convert to MiB
    uint64_t t_mb = t / (1024ull * 1024ull);
    uint64_t u_mb = u / (1024ull * 1024ull);
    if (t_mb == 0) continue;
    any = true;
    total_mb_sum += t_mb; used_mb_sum += u_mb;
    // Try build a friendly string from uevent (DRIVER + PCI ID)
    std::string friendly = name;
    try {
      std::ifstream ue(dev / "uevent");
      std::string line; std::string driver; std::string pciid;
      while (std::getline(ue, line)) {
        if (line.rfind("DRIVER=",0)==0) driver = trim(line.substr(7));
        else if (line.rfind("PCI_ID=",0)==0) pciid = trim(line.substr(7));
      }
      if (!driver.empty() || !pciid.empty()) {
        friendly.clear();
        if (!driver.empty()) friendly += driver;
        if (!pciid.empty()) friendly += (friendly.empty()?"":" ") + std::string("(") + pciid + ")";
      }
    } catch(...) { /* ignore */ }
    if (friendly.empty()) friendly = name;
    lsm::model::GpuVramDevice rec{ friendly, t_mb, u_mb };
    // Read temps via hwmon if exposed
    try {
      fs::path hwmons = dev / "hwmon";
      if (fs::exists(hwmons)) {
        for (auto& hm : fs::directory_iterator(hwmons)) {
          for (auto& file : fs::directory_iterator(hm.path())) {
            auto fn = file.path().filename().string();
            if (fn.rfind("temp",0)==0 && fn.find("_input")!=std::string::npos) {
              // Determine label
              auto base = fn.substr(0, fn.find("_input"));
              std::string label;
              try {
                std::ifstream lf(hm.path() / (base + "_label"));
                if (lf) std::getline(lf, label);
              } catch(...) {}
              long mdeg=0; std::ifstream inf(file.path()); if (!inf) continue; inf >> mdeg; if (!inf) continue;
              double c = mdeg / 1000.0;
              // Try thresholds for this sensor (crit/max/emergency)
              double warn_tc = 0.0; bool have_warn = false;
              for (const char* suff : {"_crit", "_max", "_emergency"}) {
                long thr = 0; std::ifstream tf(hm.path() / (base + suff));
                if (tf) { tf >> thr; if (tf) { warn_tc = thr / 1000.0; have_warn = true; break; } }
              }
              std::string lab = label; for (auto& ch : lab) ch = std::tolower((unsigned char)ch);
              if (lab.find("edge")!=std::string::npos || (label.empty() && !rec.has_temp_edge)) { rec.has_temp_edge = true; rec.temp_edge_c = c; }
              else if (lab.find("junction")!=std::string::npos || lab.find("hotspot")!=std::string::npos) { rec.has_temp_hotspot = true; rec.temp_hotspot_c = c; }
              else if (lab.find("mem")!=std::string::npos || lab.find("hbm")!=std::string::npos) { rec.has_temp_mem = true; rec.temp_mem_c = c; }
              else if (!rec.has_temp_edge) { rec.has_temp_edge = true; rec.temp_edge_c = c; } // fallback first temp as edge
              if (have_warn) {
                if (lab.find("edge")!=std::string::npos || label.empty()) { rec.has_thr_edge = true; rec.thr_edge_c = warn_tc; }
                else if (lab.find("junction")!=std::string::npos || lab.find("hotspot")!=std::string::npos) { rec.has_thr_hotspot = true; rec.thr_hotspot_c = warn_tc; }
                else if (lab.find("mem")!=std::string::npos || lab.find("hbm")!=std::string::npos) { rec.has_thr_mem = true; rec.thr_mem_c = warn_tc; }
              }
            }
          }
        }
      }
    } catch(...) { /* ignore */ }
    out.devices.push_back(std::move(rec));
    names.push_back(friendly);
  }
  if (any) {
    out.total_mb = total_mb_sum;
    out.used_mb  = used_mb_sum;
    out.used_pct = out.total_mb ? (100.0 * static_cast<double>(out.used_mb) / static_cast<double>(out.total_mb)) : 0.0;
    // Aggregate a concise name
    if (!names.empty()) {
      std::unordered_set<std::string> uniq(names.begin(), names.end());
      if (uniq.size() == 1) {
        out.name = *uniq.begin();
        if (names.size() > 1) out.name += " x" + std::to_string(names.size());
      } else {
        out.name = names[0] + " +" + std::to_string(names.size()-1) + " more";
      }
    }
  }
  return any;
}

#ifdef LSM_HAVE_NVML
#include <nvml.h>
static bool read_nvml(lsm::model::GpuVram& out) {
  if (nvmlInit_v2() != NVML_SUCCESS) {
    if (const char* v = std::getenv("LSM_LOG_NVML"); v && (v[0]=='1'||v[0]=='t'||v[0]=='T'||v[0]=='y'||v[0]=='Y')) {
      ::fprintf(stderr, "NVML: init failed in collector (device-level metrics disabled)\n");
    }
    return false;
  }
  unsigned int n = 0; if (nvmlDeviceGetCount_v2(&n) != NVML_SUCCESS) { nvmlShutdown(); return false; }
  bool any = false; uint64_t total_mb_sum = 0, used_mb_sum = 0;
  std::vector<std::string> model_names;
  double total_power_w = 0.0; bool have_power = false;
  // Utilization aggregates (average across devices)
  double sum_gpu_util = 0.0; unsigned util_count = 0;
  double sum_mem_util = 0.0; unsigned mem_util_count = 0;
  double sum_enc_util = 0.0; unsigned enc_util_count = 0;
  double sum_dec_util = 0.0; unsigned dec_util_count = 0;
  for (unsigned int i = 0; i < n; ++i) {
    nvmlDevice_t dev{}; if (nvmlDeviceGetHandleByIndex_v2(i, &dev) != NVML_SUCCESS) continue;
    nvmlMemory_t mem{}; if (nvmlDeviceGetMemoryInfo(dev, &mem) != NVML_SUCCESS) continue;
    uint64_t t_mb = mem.total / (1024ull * 1024ull);
    uint64_t u_mb = mem.used  / (1024ull * 1024ull);
    if (t_mb == 0) continue;
    any = true; total_mb_sum += t_mb; used_mb_sum += u_mb;
    char name[96]; name[0] = '\0';
    lsm::model::GpuVramDevice rec{};
    if (nvmlDeviceGetName(dev, name, sizeof(name)) == NVML_SUCCESS) {
      rec.name = name; model_names.emplace_back(name);
    } else {
      rec.name = "GPU";
    }
    rec.total_mb = t_mb; rec.used_mb = u_mb;
    // Temps (edge and memory if available)
    unsigned int tc = 0;
    if (nvmlDeviceGetTemperature(dev, NVML_TEMPERATURE_GPU, &tc) == NVML_SUCCESS) { rec.has_temp_edge = true; rec.temp_edge_c = (double)tc; }
#ifdef NVML_TEMPERATURE_MEMORY
    if (nvmlDeviceGetTemperature(dev, NVML_TEMPERATURE_MEMORY, &tc) == NVML_SUCCESS) { rec.has_temp_mem = true; rec.temp_mem_c = (double)tc; }
#endif
    // Thresholds: slowdown (treat as warning)
    unsigned int tw = 0;
    if (nvmlDeviceGetTemperatureThreshold(dev, NVML_TEMPERATURE_THRESHOLD_SLOWDOWN, &tw) == NVML_SUCCESS) {
      rec.has_thr_edge = true; rec.thr_edge_c = (double)tw;
    }
#ifdef NVML_TEMPERATURE_THRESHOLD_MEM_MAX
    if (nvmlDeviceGetTemperatureThreshold(dev, NVML_TEMPERATURE_THRESHOLD_MEM_MAX, &tw) == NVML_SUCCESS) {
      rec.has_thr_mem = true; rec.thr_mem_c = (double)tw;
    }
#endif
    // Optional power (milliwatts -> watts)
    unsigned int mw = 0;
    if (nvmlDeviceGetPowerUsage(dev, &mw) == NVML_SUCCESS && mw > 0) {
      total_power_w += static_cast<double>(mw) / 1000.0;
      have_power = true;
    }
    out.devices.push_back(std::move(rec));
    // Utilization (core + memory)
    nvmlUtilization_t ur{};
    if (nvmlDeviceGetUtilizationRates(dev, &ur) == NVML_SUCCESS) {
      sum_gpu_util += ur.gpu; util_count++;
      sum_mem_util += ur.memory; mem_util_count++;
    }
    // Encoder/Decoder utilization (optional)
    unsigned int enc_util = 0, dec_util = 0; unsigned int samp_us = 0;
    if (nvmlDeviceGetEncoderUtilization(dev, &enc_util, &samp_us) == NVML_SUCCESS) { sum_enc_util += enc_util; enc_util_count++; }
    if (nvmlDeviceGetDecoderUtilization(dev, &dec_util, &samp_us) == NVML_SUCCESS) { sum_dec_util += dec_util; dec_util_count++; }
  }
  nvmlShutdown();
  if (any) {
    out.total_mb = total_mb_sum;
    out.used_mb  = used_mb_sum;
    out.used_pct = out.total_mb ? (100.0 * static_cast<double>(out.used_mb) / static_cast<double>(out.total_mb)) : 0.0;
    if (!model_names.empty()) {
      std::unordered_set<std::string> uniq(model_names.begin(), model_names.end());
      if (uniq.size() == 1) {
        out.name = *uniq.begin();
        if (model_names.size() > 1) out.name += " x" + std::to_string(model_names.size());
      } else {
        out.name = model_names[0] + " +" + std::to_string(model_names.size()-1) + " more";
      }
    }
    if (have_power) {
      out.has_power = true;
      out.power_draw_w = total_power_w;
    }
    if (util_count > 0) { out.has_util = true; out.gpu_util_pct = sum_gpu_util / util_count; }
    if (mem_util_count > 0) { out.has_mem_util = true; out.mem_util_pct = sum_mem_util / mem_util_count; }
    if (enc_util_count > 0 || dec_util_count > 0) {
      out.has_encdec = true;
      if (enc_util_count > 0) out.enc_util_pct = sum_enc_util / enc_util_count;
      if (dec_util_count > 0) out.dec_util_pct = sum_dec_util / dec_util_count;
    }
  }
  return any;
}
#else
static bool read_nvml(lsm::model::GpuVram&) { return false; }
#endif

bool GpuCollector::sample(lsm::model::GpuVram& out) const {
  out = {};
  if (read_nvml(out)) return true;
  bool ok = false;
  ok = read_nvidia_proc(out) || ok;
  ok = read_amd_sysfs(out)   || ok;
  // AMD core busy percent
  try {
    fs::path drm(lsm::util::map_sys_path("/sys/class/drm"));
    if (fs::exists(drm)) {
      double sum_busy = 0.0; unsigned cnt = 0;
      for (auto& entry : fs::directory_iterator(drm)) {
        if (!entry.is_directory()) continue;
        if (!entry.path().filename().string().starts_with("card")) continue;
        auto busy = entry.path() / "device" / "gpu_busy_percent";
        std::ifstream f(busy);
        if (!f) continue;
        double v = 0.0; f >> v; if (!f) continue;
        sum_busy += v; cnt++;
      }
      if (cnt > 0) { out.has_util = true; out.gpu_util_pct = sum_busy / cnt; }
    }
  } catch (...) { /* ignore */ }
  // Power via hwmon (all vendors): sum power1_average/input if present
  try {
    fs::path drm(lsm::util::map_sys_path("/sys/class/drm"));
    if (fs::exists(drm)) {
      double total_w = 0.0; bool have = false;
      for (auto& entry : fs::directory_iterator(drm)) {
        if (!entry.is_directory()) continue;
        if (!entry.path().filename().string().starts_with("card")) continue;
        fs::path hwmons = entry.path() / "device" / "hwmon";
        if (!fs::exists(hwmons)) continue;
        for (auto& hm : fs::directory_iterator(hwmons)) {
          auto pavg = hm.path() / "power1_average";
          auto pinp = hm.path() / "power1_input";
          for (auto p : {pavg, pinp}) {
            std::ifstream f(p);
            if (!f) continue;
            long long microw = 0; f >> microw; if (!f) continue;
            if (microw > 0) { total_w += static_cast<double>(microw) / 1'000'000.0; have = true; break; }
          }
        }
      }
      if (have) { out.has_power = true; out.power_draw_w = total_w; }
    }
  } catch (...) { /* ignore */ }
  return ok;
}

} // namespace lsm::collectors
