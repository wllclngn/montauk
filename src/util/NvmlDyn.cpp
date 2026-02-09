#include "util/NvmlDyn.hpp"
#include <cstdio>
#include <cstdlib>
#include <dlfcn.h>
#include <string>
#include <unordered_set>
#include <vector>
#include "ui/Config.hpp"

namespace montauk::util {

static const int NVML_SUCCESS = 0;
static const unsigned int NVML_TEMPERATURE_GPU = 0; // core sensor

NvmlDyn& NvmlDyn::instance() {
  static NvmlDyn inst;
  return inst;
}


bool NvmlDyn::load_once() {
  if (loaded_) return handle_ != nullptr;
  loaded_ = true;
  const auto& nvcfg = montauk::ui::config().nvidia;
  if (nvcfg.disable_nvml) { suppressed_ = true; return false; }

  std::vector<std::string> candidates;

  if (!nvcfg.nvml_path.empty()) {
    const char* p = nvcfg.nvml_path.c_str();
    std::string path = p;
    
    static const std::vector<std::string> allowed_prefixes = {
      "/usr/lib", "/usr/lib64", "/usr/local/lib", "/usr/local/lib64",
      "/opt/nvidia", "/opt/cuda"
    };
    
    bool valid = false;
    for (const auto& prefix : allowed_prefixes) {
      if (path.rfind(prefix, 0) == 0) {
        valid = true;
        break;
      }
    }
    
    if (valid) {
      candidates.emplace_back(path);
    } else {
      std::fprintf(stderr, "Warning: MONTAUK_NVML_PATH rejected (invalid prefix): %s\n", p);
    }
  }
  
  candidates.emplace_back("libnvidia-ml.so.1");
  candidates.emplace_back("libnvidia-ml.so");
  
  for (const auto& lib : candidates) {
    handle_ = ::dlopen(lib.c_str(), RTLD_LAZY | RTLD_LOCAL);
    if (handle_) break;
  }
  if (!handle_) return false;
  if (!dlsym_all()) {
    ::dlclose(handle_); handle_ = nullptr; return false;
  }
  return true;
}

bool NvmlDyn::dlsym_all() {
  auto L = [&](const char* sym){ return ::dlsym(handle_, sym); };
  p_nvmlInit_v2 = (nvmlReturn_t (*)())L("nvmlInit_v2");
  p_nvmlShutdown = (nvmlReturn_t (*)())L("nvmlShutdown");
  p_nvmlDeviceGetCount_v2 = (nvmlReturn_t (*)(unsigned int*))L("nvmlDeviceGetCount_v2");
  p_nvmlDeviceGetHandleByIndex_v2 = (nvmlReturn_t (*)(unsigned int, nvmlDevice_t*))L("nvmlDeviceGetHandleByIndex_v2");
  p_nvmlDeviceGetName = (nvmlReturn_t (*)(nvmlDevice_t, char*, unsigned int))L("nvmlDeviceGetName");
  p_nvmlDeviceGetMemoryInfo = (nvmlReturn_t (*)(nvmlDevice_t, nvmlMemory_t*))L("nvmlDeviceGetMemoryInfo");
  p_nvmlDeviceGetTemperature = (nvmlReturn_t (*)(nvmlDevice_t, unsigned int, unsigned int*))L("nvmlDeviceGetTemperature");
  p_nvmlDeviceGetUtilizationRates = (nvmlReturn_t (*)(nvmlDevice_t, nvmlUtilization_t*))L("nvmlDeviceGetUtilizationRates");
  p_nvmlDeviceGetEncoderUtilization = (nvmlReturn_t (*)(nvmlDevice_t, unsigned int*, unsigned int*))L("nvmlDeviceGetEncoderUtilization");
  p_nvmlDeviceGetDecoderUtilization = (nvmlReturn_t (*)(nvmlDevice_t, unsigned int*, unsigned int*))L("nvmlDeviceGetDecoderUtilization");
  p_nvmlDeviceGetPowerUsage = (nvmlReturn_t (*)(nvmlDevice_t, unsigned int*))L("nvmlDeviceGetPowerUsage");
  p_nvmlDeviceGetPowerManagementLimit = (nvmlReturn_t (*)(nvmlDevice_t, unsigned int*))L("nvmlDeviceGetPowerManagementLimit");
  p_nvmlDeviceGetPerformanceState = (nvmlReturn_t (*)(nvmlDevice_t, unsigned int*))L("nvmlDeviceGetPerformanceState");
  p_nvmlDeviceGetFanSpeed_v2 = (nvmlReturn_t (*)(nvmlDevice_t, unsigned int, unsigned int*))L("nvmlDeviceGetFanSpeed_v2");
  // Core must-haves
  return p_nvmlInit_v2 && p_nvmlShutdown && p_nvmlDeviceGetCount_v2 && p_nvmlDeviceGetHandleByIndex_v2 && p_nvmlDeviceGetMemoryInfo;
}

bool NvmlDyn::available() const { return handle_ != nullptr && !suppressed_; }

bool NvmlDyn::read_devices(montauk::model::GpuVram& out) {
  out = {};
  if (!load_once() || !available()) return false;
  
  NvmlGuard guard;
  if (!guard.ok()) return false;
  
  unsigned int n = 0;
  if (p_nvmlDeviceGetCount_v2(&n) != NVML_SUCCESS) return false;

  bool any = false; uint64_t total_mb_sum = 0, used_mb_sum = 0;
  double total_power_w = 0.0; bool have_power = false;
  double total_plimit_w = 0.0; bool have_plimit = false;
  int first_pstate = -1; bool have_pstate = false;
  double sum_gpu_util = 0.0; unsigned util_count = 0;
  double sum_mem_util = 0.0; unsigned mem_util_count = 0;
  double sum_enc_util = 0.0; unsigned enc_util_count = 0;
  double sum_dec_util = 0.0; unsigned dec_util_count = 0;
  std::vector<std::string> model_names;

  for (unsigned int i = 0; i < n; ++i) {
    nvmlDevice_t dev{};
    if (p_nvmlDeviceGetHandleByIndex_v2(i, &dev) != NVML_SUCCESS) continue;
    nvmlMemory_t mem{};
    if (p_nvmlDeviceGetMemoryInfo(dev, &mem) != NVML_SUCCESS) continue;
    uint64_t t_mb = mem.total / (1024ull * 1024ull);
    uint64_t u_mb = mem.used  / (1024ull * 1024ull);
    if (t_mb == 0) continue;
    any = true; total_mb_sum += t_mb; used_mb_sum += u_mb;

    montauk::model::GpuVramDevice rec{};
    if (p_nvmlDeviceGetName) {
      char name[96]; name[0] = '\0';
      if (p_nvmlDeviceGetName(dev, name, sizeof(name)) == NVML_SUCCESS && name[0]) {
        rec.name = name; model_names.emplace_back(name);
      }
    }
    if (rec.name.empty()) rec.name = "GPU";
    rec.total_mb = t_mb; rec.used_mb = u_mb;

    // Temperature (edge)
    if (p_nvmlDeviceGetTemperature) {
      unsigned int tc = 0;
      if (p_nvmlDeviceGetTemperature(dev, NVML_TEMPERATURE_GPU, &tc) == NVML_SUCCESS) {
        rec.has_temp_edge = true; rec.temp_edge_c = (double)tc;
      }
    }

    // Fan speed (percent, first fan)
    if (p_nvmlDeviceGetFanSpeed_v2) {
      unsigned int pct = 0;
      if (p_nvmlDeviceGetFanSpeed_v2(dev, 0, &pct) == NVML_SUCCESS) {
        rec.has_fan = true; rec.fan_speed_pct = (double)pct;
      }
    }

    // Power usage and limit (optional)
    if (p_nvmlDeviceGetPowerUsage) {
      unsigned int mw = 0; if (p_nvmlDeviceGetPowerUsage(dev, &mw) == NVML_SUCCESS && mw > 0) { total_power_w += (double)mw / 1000.0; have_power = true; }
    }
    if (p_nvmlDeviceGetPowerManagementLimit) {
      unsigned int lim_mw = 0; if (p_nvmlDeviceGetPowerManagementLimit(dev, &lim_mw) == NVML_SUCCESS && lim_mw > 0) { total_plimit_w += (double)lim_mw / 1000.0; have_plimit = true; }
    }

    // Pstate (first device)
    if (!have_pstate && p_nvmlDeviceGetPerformanceState) {
      unsigned int pst = 0; if (p_nvmlDeviceGetPerformanceState(dev, &pst) == NVML_SUCCESS) { first_pstate = (int)pst; have_pstate = true; }
    }

    // Utilization
    if (p_nvmlDeviceGetUtilizationRates) {
      nvmlUtilization_t ur{}; if (p_nvmlDeviceGetUtilizationRates(dev, &ur) == NVML_SUCCESS) { sum_gpu_util += ur.gpu; util_count++; sum_mem_util += ur.memory; mem_util_count++; }
    }
    // Enc/Dec
    if (p_nvmlDeviceGetEncoderUtilization) { unsigned int u=0, us=0; if (p_nvmlDeviceGetEncoderUtilization(dev, &u, &us)==NVML_SUCCESS) { sum_enc_util += u; enc_util_count++; } }
    if (p_nvmlDeviceGetDecoderUtilization) { unsigned int u=0, us=0; if (p_nvmlDeviceGetDecoderUtilization(dev, &u, &us)==NVML_SUCCESS) { sum_dec_util += u; dec_util_count++; } }

    out.devices.push_back(std::move(rec));
  }

  if (!any) return false;
  out.total_mb = total_mb_sum;
  out.used_mb  = used_mb_sum;
  out.used_pct = out.total_mb ? (100.0 * (double)out.used_mb / (double)out.total_mb) : 0.0;
  if (!model_names.empty()) {
    std::unordered_set<std::string> uniq(model_names.begin(), model_names.end());
    if (uniq.size() == 1) {
      out.name = *uniq.begin(); if (model_names.size() > 1) out.name += " x" + std::to_string(model_names.size());
    } else {
      out.name = model_names[0] + " +" + std::to_string(model_names.size()-1) + " more";
    }
  }
  if (have_power) { out.has_power = true; out.power_draw_w = total_power_w; }
  if (have_plimit) { out.has_power_limit = true; out.power_limit_w = total_plimit_w; }
  if (have_pstate) { out.has_pstate = true; out.pstate = first_pstate; }
  if (util_count > 0) { out.has_util = true; out.gpu_util_pct = sum_gpu_util / util_count; }
  if (mem_util_count > 0) { out.has_mem_util = true; out.mem_util_pct = sum_mem_util / mem_util_count; }
  if (enc_util_count > 0 || dec_util_count > 0) {
    out.has_encdec = true;
    if (enc_util_count > 0) out.enc_util_pct = sum_enc_util / enc_util_count;
    if (dec_util_count > 0) out.dec_util_pct = sum_dec_util / dec_util_count;
  }
  return true;
}

} // namespace montauk::util

