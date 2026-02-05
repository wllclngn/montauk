#include "app/GpuAttributor.hpp"
#include <algorithm>
#include <cstdio>
#include <filesystem>
#include "ui/Config.hpp"

#ifdef MONTAUK_HAVE_NVML
#include <nvml.h>
#endif

using namespace std::chrono;

namespace montauk::app {

GpuAttributor::GpuAttributor() {}
GpuAttributor::~GpuAttributor() {
#ifdef MONTAUK_HAVE_NVML
  nvml_shutdown_if_needed();
#endif
}

static int as_int_pct(double v) { if (v < 0) v = 0; if (v > 100) v = 100; return (int)(v + 0.5); }

void GpuAttributor::enrich(montauk::model::Snapshot& s) {
  auto now_tp = steady_clock::now();
  std::unordered_map<int,int> pid_to_gpu; // per-PID util percent
  std::unordered_set<int> running_pids;
  std::unordered_map<int, uint64_t> pid_to_gpu_mem_kb;
#ifdef MONTAUK_HAVE_NVML
  // NVML path (NVIDIA)
  ensure_nvml_init();
  const bool log_nvml = []{
    const char* v = montauk::ui::getenv_compat("MONTAUK_LOG_NVML");
    return v && (v[0]=='1'||v[0]=='t'||v[0]=='T'||v[0]=='y'||v[0]=='Y');
  }();
  if (nvml_ok_) {
    unsigned int ndev=0; if (nvmlDeviceGetCount_v2(&ndev)==NVML_SUCCESS) {
      if (nvml_last_proc_ts_per_dev_.size() != ndev) nvml_last_proc_ts_per_dev_.assign(ndev, 0ull);
      bool mig_enabled_global = false;
      std::unordered_set<int> nvml_running;
      for (unsigned int di=0; di<ndev; ++di) {
        nvmlDevice_t dev{}; if (nvmlDeviceGetHandleByIndex_v2(di, &dev) != NVML_SUCCESS) continue;
        unsigned currentMode = 0, pendingMode = 0;
        if (nvmlDeviceGetMigMode(dev, &currentMode, &pendingMode) == NVML_SUCCESS) { if (currentMode == 1) mig_enabled_global = true; }
        // graphics
        unsigned int gcount = 0; auto grv = nvmlDeviceGetGraphicsRunningProcesses(dev, &gcount, nullptr);
        if (grv == NVML_ERROR_INSUFFICIENT_SIZE && gcount > 0) {
          std::vector<nvmlProcessInfo_t> gbuf(gcount);
          grv = nvmlDeviceGetGraphicsRunningProcesses(dev, &gcount, gbuf.data());
          if (grv == NVML_SUCCESS) {
            for (unsigned int i=0;i<gcount;i++) {
              int pid = (int)gbuf[i].pid; nvml_running.insert(pid);
              unsigned long long bytes = gbuf[i].usedGpuMemory;
              if (bytes > 0 && bytes < (1ull<<62)) { uint64_t kb = (uint64_t)(bytes/1024ull); auto it=pid_to_gpu_mem_kb.find(pid); if (it==pid_to_gpu_mem_kb.end()||kb>it->second) pid_to_gpu_mem_kb[pid]=kb; }
            }
          }
        }
        // compute
        unsigned int ccount = 0; auto crv = nvmlDeviceGetComputeRunningProcesses(dev, &ccount, nullptr);
        if (crv == NVML_ERROR_INSUFFICIENT_SIZE && ccount > 0) {
          std::vector<nvmlProcessInfo_t> cbuf(ccount);
          crv = nvmlDeviceGetComputeRunningProcesses(dev, &ccount, cbuf.data());
          if (crv == NVML_SUCCESS) {
            for (unsigned int i=0;i<ccount;i++) {
              int pid = (int)cbuf[i].pid; nvml_running.insert(pid);
              unsigned long long bytes = cbuf[i].usedGpuMemory;
              if (bytes > 0 && bytes < (1ull<<62)) { uint64_t kb = (uint64_t)(bytes/1024ull); auto it=pid_to_gpu_mem_kb.find(pid); if (it==pid_to_gpu_mem_kb.end()||kb>it->second) pid_to_gpu_mem_kb[pid]=kb; }
            }
          }
        }
        if (!mig_enabled_global) {
          unsigned long long& last_ts = nvml_last_proc_ts_per_dev_[di];
          unsigned long long query_ts = (last_ts > 200000ull) ? (last_ts - 200000ull) : 0ull;
          unsigned int count = 0; auto ret = nvmlDeviceGetProcessUtilization(dev, nullptr, &count, query_ts);
          if (ret == NVML_ERROR_INSUFFICIENT_SIZE && count > 0) {
            std::vector<nvmlProcessUtilizationSample_t> buf(count);
            ret = nvmlDeviceGetProcessUtilization(dev, buf.data(), &count, query_ts);
            if (ret == NVML_SUCCESS) {
              unsigned long long newest = last_ts;
              for (unsigned int i=0;i<count;i++) {
                const auto& sm = buf[i];
                if (sm.smUtil <= 100 && sm.encUtil <= 100 && sm.decUtil <= 100 && sm.timeStamp > last_ts) {
                  int pid = (int)sm.pid; int util = std::max({(int)sm.smUtil, (int)sm.encUtil, (int)sm.decUtil});
                  auto it = pid_to_gpu.find(pid); if (it==pid_to_gpu.end() || util > it->second) pid_to_gpu[pid] = util;
                  if (sm.timeStamp > newest) newest = sm.timeStamp;
                }
              }
              if (newest > last_ts) {
                last_ts = newest;
              }
              last_nvml_sample_tp_ = now_tp;
            } else if (log_nvml) {
              ::fprintf(stderr, "NVML: GetProcessUtilization failed on device %u (ret=%d)\n", di, (int)ret);
            }
          } else if (log_nvml) {
            ::fprintf(stderr, "NVML: no process samples on device %u (ret=%d, count=%u, last_ts=%llu)\n", di, (int)ret, count, (unsigned long long)last_ts);
          }
        }
      }
      running_pids.insert(nvml_running.begin(), nvml_running.end());
      s.nvml.mig_enabled = mig_enabled_global;
      // Populate diagnostics
      s.nvml.available = true; s.nvml.devices = (int)ndev; s.nvml.running_pids = (int)running_pids.size(); s.nvml.sampled_pids = (int)pid_to_gpu.size();
      if (last_nvml_sample_tp_.time_since_epoch().count() > 0) {
        auto age = std::chrono::duration_cast<std::chrono::milliseconds>(now_tp - last_nvml_sample_tp_).count(); if (age < 0) age = 0; s.nvml.sample_age_ms = (uint64_t)age;
      } else { s.nvml.sample_age_ms = 0; }
      // Version info (cache once per process) and attach to snapshot
#ifdef MONTAUK_HAVE_NVML
      if (!nvml_versions_cached_) {
        nvml_versions_cached_ = true;
        // Driver version
        char vbuf[128];
        if (nvmlSystemGetDriverVersion(vbuf, sizeof(vbuf)) == NVML_SUCCESS) {
          cached_driver_version_ = vbuf;
        }
        // NVML version
        if (nvmlSystemGetNVMLVersion(vbuf, sizeof(vbuf)) == NVML_SUCCESS) {
          cached_nvml_version_ = vbuf;
        }
        // CUDA version via nvidia-smi (as headers may not expose CUDA driver query across versions)
        FILE* fpv = ::popen("nvidia-smi --query-gpu=cuda_version --format=csv,noheader 2>/dev/null", "r");
        if (fpv) {
          char lbuf[64] = {0};
          if (std::fgets(lbuf, sizeof(lbuf), fpv)) {
            std::string cuda_str(lbuf);
            while (!cuda_str.empty() && (cuda_str.back()=='\n' || cuda_str.back()=='\r' || cuda_str.back()==' ' || cuda_str.back()=='\t')) cuda_str.pop_back();
            cached_cuda_version_ = cuda_str;
          }
          ::pclose(fpv);
        }
      }
      s.nvml.driver_version = cached_driver_version_;
      s.nvml.nvml_version = cached_nvml_version_;
      s.nvml.cuda_version = cached_cuda_version_;
#endif
    } else {
      s.nvml.available = false;
    }
  } else {
    s.nvml.available = false;
  }
#endif

  // Detect MIG mode via nvidia-smi when NVML path did not set it
  if (!s.nvml.mig_enabled) {
    auto find_smi = [&](){
      if (const char* p = montauk::ui::getenv_compat("MONTAUK_NVIDIA_SMI_PATH")) return std::string(p);
      if (const char* path = std::getenv("PATH")) {
        std::string p(path); size_t start=0; while (start<=p.size()) { size_t end=p.find(':',start); std::string dir=p.substr(start,end==std::string::npos?std::string::npos:end-start); if(!dir.empty()){ std::string cand=dir+"/nvidia-smi"; std::error_code ec; if(std::filesystem::exists(cand,ec)) return cand; } if(end==std::string::npos) break; start=end+1; }
      }
      const char* candidates[]={"/usr/bin/nvidia-smi","/usr/local/bin/nvidia-smi","/opt/nvidia/sbin/nvidia-smi","/bin/nvidia-smi"};
      for (const char* c: candidates) { std::error_code ec; if (std::filesystem::exists(c,ec)) return std::string(c); }
      return std::string();
    };
    std::string smi = find_smi();
    if (!smi.empty()) {
      std::string cmd = smi + " --query-gpu=mig.mode.current --format=csv,noheader 2>/dev/null";
      FILE* fp = ::popen(cmd.c_str(), "r");
      if (fp) {
        char lbuf[128]={0};
        if (std::fgets(lbuf, sizeof(lbuf), fp)) {
          std::string line(lbuf);
          auto trim = [](std::string str){ while(!str.empty() && (str.back()=='\n'||str.back()=='\r'||str.back()==' '||str.back()=='\t')) str.pop_back(); while(!str.empty() && (str.front()==' '||str.front()=='\t')) str.erase(str.begin()); return str; };
          line = trim(line);
          if (!line.empty() && (line[0]=='E' || line[0]=='e')) { // "Enabled"
            s.nvml.mig_enabled = true;
          }
        }
        ::pclose(fp);
      }
    }
  }

  // Populate version strings via nvidia-smi when NVML did not fill them
  if (s.nvml.driver_version.empty() || s.nvml.cuda_version.empty()) {
    auto find_smi = [&](){
      if (const char* p = montauk::ui::getenv_compat("MONTAUK_NVIDIA_SMI_PATH")) return std::string(p);
      if (const char* path = std::getenv("PATH")) {
        std::string p(path); size_t start=0; while (start<=p.size()) { size_t end=p.find(':',start); std::string dir=p.substr(start,end==std::string::npos?std::string::npos:end-start); if(!dir.empty()){ std::string cand=dir+"/nvidia-smi"; std::error_code ec; if(std::filesystem::exists(cand,ec)) return cand; } if(end==std::string::npos) break; start=end+1; }
      }
      const char* candidates[]={"/usr/bin/nvidia-smi","/usr/local/bin/nvidia-smi","/opt/nvidia/sbin/nvidia-smi","/bin/nvidia-smi"};
      for (const char* c: candidates) { std::error_code ec; if (std::filesystem::exists(c,ec)) return std::string(c); }
      return std::string();
    };
    std::string smi = find_smi();
    if (!smi.empty()) {
      std::string cmd = smi + " --query-gpu=driver_version,cuda_version --format=csv,noheader 2>/dev/null";
      FILE* fp = ::popen(cmd.c_str(), "r");
      if (fp) {
        char lbuf[128]={0};
        if (std::fgets(lbuf, sizeof(lbuf), fp)) {
          std::string line(lbuf);
          // Split by comma
          size_t comma = line.find(',');
          auto trim = [](std::string str){ while(!str.empty() && (str.back()=='\n'||str.back()=='\r'||str.back()==' '||str.back()=='\t')) str.pop_back(); while(!str.empty() && (str.front()==' '||str.front()=='\t')) str.erase(str.begin()); return str; };
          if (comma != std::string::npos) {
            auto drv = trim(line.substr(0, comma));
            auto cud = trim(line.substr(comma+1));
            if (s.nvml.driver_version.empty()) s.nvml.driver_version = drv;
            if (s.nvml.cuda_version.empty())   s.nvml.cuda_version   = cud;
          }
        }
        ::pclose(fp);
      }
    }
  }

  // If NVML gave nothing or is unavailable, try fdinfo for AMD/Intel
  if (pid_to_gpu.empty()) {
    std::unordered_map<int,int> map2; std::unordered_map<int,uint64_t> mem2; std::unordered_set<int> run2;
    if (fdinfo_.sample(map2, mem2, run2)) {
      pid_to_gpu.swap(map2); pid_to_gpu_mem_kb.insert(mem2.begin(), mem2.end()); running_pids.insert(run2.begin(), run2.end());
    }
  }

  // Optional NVIDIA PMON fallback (off by default): parse `nvidia-smi pmon` for per-process sm/enc/dec
  // Default-on PMON unless explicitly disabled (MONTAUK_NVIDIA_PMON=0 or montauk_NVIDIA_PMON=0)
  auto env_true = [](const char* name, bool defv=true){
    const char* v = montauk::ui::getenv_compat(name);
    if (!v) return defv;
    return !(v[0]=='0'||v[0]=='f'||v[0]=='F');
  };
  if (pid_to_gpu.empty() && env_true("MONTAUK_NVIDIA_PMON", true) && !s.nvml.mig_enabled) {
    // Find nvidia-smi
    std::string smi;
    if (const char* ep = montauk::ui::getenv_compat("MONTAUK_NVIDIA_SMI_PATH")) smi = ep; else {
      if (const char* path = std::getenv("PATH")) {
        std::string pathstr(path); size_t start=0; while (start<=pathstr.size()) { size_t end=pathstr.find(':',start); std::string dir=pathstr.substr(start,end==std::string::npos?std::string::npos:end-start); if(!dir.empty()){ std::string cand=dir+"/nvidia-smi"; std::error_code ec; if(std::filesystem::exists(cand,ec)) { smi=cand; break; } } if(end==std::string::npos) break; start=end+1; }
      }
      if (smi.empty()) { const char* candidates[]={"/usr/bin/nvidia-smi","/usr/local/bin/nvidia-smi","/opt/nvidia/sbin/nvidia-smi","/bin/nvidia-smi"}; for (const char* c: candidates){ std::error_code ec; if(std::filesystem::exists(c,ec)){ smi=c; break; } } }
    }
    std::string cmd = (!smi.empty()? smi : std::string("nvidia-smi")) + " pmon -c 1 -s u 2>/dev/null";
    FILE* fp = ::popen(cmd.c_str(), "r");
    if (fp) {
      char buf[512];
      // Format lines: "# gpu pid type sm mem enc dec command"
      while (std::fgets(buf, sizeof(buf), fp)) {
        if (buf[0] == '#') continue;
        // tokenization by spaces
        int gpu=-1, pid=-1, sm=-1, mem=-1, enc=-1, dec=-1;
        char type[32] = {0};
        // try a tolerant sscanf; some fields may be "-"
        // Read fields we care about; command skipped
        int matched = std::sscanf(buf, "%d %d %31s %d %d %d %d", &gpu, &pid, type, &sm, &mem, &enc, &dec);
        if (matched >= 4 && pid > 0) {
          auto fix = [](int v){ return (v<0||v>100)?0:v; };
          int util = std::max({fix(sm), fix(enc), fix(dec)});
          if (util > 0) {
            auto it = pid_to_gpu.find(pid);
            if (it == pid_to_gpu.end() || util > it->second) pid_to_gpu[pid] = util;
            running_pids.insert(pid);
          }
        }
      }
      ::pclose(fp);
    }
  }

  // Supplemental presence detection for NVIDIA decode-only workloads:
  // If running_pids is still empty but device-level util shows activity,
  // infer candidates by scanning /proc/<pid>/fd symlinks for GPU devices.
  if (running_pids.empty()) {
    int dev_util_hint = (int)std::max({ (double)as_int_pct(s.vram.gpu_util_pct), (double)as_int_pct(s.vram.enc_util_pct), (double)as_int_pct(s.vram.dec_util_pct) });
    if (dev_util_hint > 0) {
      for (const auto& p : s.procs.processes) {
        try {
          std::filesystem::path fddir(std::string("/proc/") + std::to_string(p.pid) + "/fd");
          if (!std::filesystem::exists(fddir)) continue;
          for (auto& de : std::filesystem::directory_iterator(fddir)) {
            std::error_code ec; auto target = std::filesystem::read_symlink(de.path(), ec);
            if (ec) continue;
            auto tstr = target.string();
            if (tstr.rfind("/dev/nvidia", 0) == 0 || tstr.find("nvidia-uvm") != std::string::npos || tstr.find("/dev/dri/renderD") == 0) {
              running_pids.insert(p.pid); break;
            }
          }
        } catch (...) { /* ignore per-pid errors */ }
      }
    }
  }

  // Heuristics for per-process GMEM when vendor APIs don't expose it
  auto choose_gpu_pid = [&]() -> int {
    int gpu_proc_pid = -1; int matches = 0; int chrome_gpu_pid = -1;
    for (const auto& p : s.procs.processes) {
      const std::string& c = p.cmd;
      bool is_gpu_proc = (c.find("--type=gpu-process") != std::string::npos);
      bool is_x = (c.find("/usr/lib/Xorg") != std::string::npos) || (c.find("Xorg") != std::string::npos) || (c.find("Xwayland") != std::string::npos);
      if (is_gpu_proc || is_x) {
        matches++; gpu_proc_pid = p.pid;
        if (c.find("chrome") != std::string::npos || c.find("helium") != std::string::npos) chrome_gpu_pid = p.pid;
      }
    }
    if (matches == 1) return gpu_proc_pid;
    if (chrome_gpu_pid > 0) return chrome_gpu_pid;
    return -1;
  };

  // Optional NVIDIA memory query via nvidia-smi (compute contexts)
  if (pid_to_gpu_mem_kb.empty() && env_true("MONTAUK_NVIDIA_MEM", true) && !s.nvml.mig_enabled) {
    std::string smi;
    if (const char* ep = montauk::ui::getenv_compat("MONTAUK_NVIDIA_SMI_PATH")) smi = ep; else {
      if (const char* path = std::getenv("PATH")) {
        std::string pathstr(path); size_t start=0; while (start<=pathstr.size()) { size_t end=pathstr.find(':',start); std::string dir=pathstr.substr(start,end==std::string::npos?std::string::npos:end-start); if(!dir.empty()){ std::string cand=dir+"/nvidia-smi"; std::error_code ec; if(std::filesystem::exists(cand,ec)) { smi=cand; break; } } if(end==std::string::npos) break; start=end+1; }
      }
      if (smi.empty()) { const char* candidates[]={"/usr/bin/nvidia-smi","/usr/local/bin/nvidia-smi","/opt/nvidia/sbin/nvidia-smi","/bin/nvidia-smi"}; for (const char* c: candidates){ std::error_code ec; if(std::filesystem::exists(c,ec)){ smi=c; break; } } }
    }
    std::string cmd = (!smi.empty()? smi : std::string("nvidia-smi")) + " --query-compute-apps=pid,used_memory --format=csv,noheader,nounits 2>/dev/null";
    FILE* fp = ::popen(cmd.c_str(), "r");
    if (fp) {
      char line[256];
      while (std::fgets(line, sizeof(line), fp)) {
        // Expect: "<pid>, <memMiB>"
        int pid = 0; long mem_mb = 0; if (std::sscanf(line, "%d , %ld", &pid, &mem_mb) == 2) {
          if (pid > 0 && mem_mb > 0) pid_to_gpu_mem_kb[pid] = (uint64_t)mem_mb * 1024ull;
        }
      }
      ::pclose(fp);
    }
  }

  // If still no per-process GMEM, distribute heuristically from device VRAM used
  if (pid_to_gpu_mem_kb.empty() && !s.nvml.mig_enabled) {
    uint64_t total_kb = s.vram.used_mb * 1024ull;
    if (total_kb > 0) {
      if (!pid_to_gpu.empty()) {
        // Proportional to GPU% shares (best-effort)
        int sum = 0; for (auto& kv : pid_to_gpu) sum += std::max(0, kv.second);
        if (sum > 0) {
          for (auto& kv : pid_to_gpu) {
            uint64_t share = (uint64_t)((long double)total_kb * (long double)kv.second / (long double)sum);
            if (share < 1024ull) share = 1024ull; // at least 1 MiB if non-zero util
            pid_to_gpu_mem_kb[kv.first] = share;
          }
        }
      }
      if (pid_to_gpu_mem_kb.empty()) {
        // Single running PID gets all; else pick a clear GPU process
        if (running_pids.size() == 1) {
          pid_to_gpu_mem_kb[*running_pids.begin()] = total_kb;
        } else {
          int chosen = choose_gpu_pid(); if (chosen > 0) pid_to_gpu_mem_kb[chosen] = total_kb;
        }
      }
    }
  }

  // Residual assignment: if device VRAM used exceeds summed per-PID GMEM, attribute the remainder
  if (!s.nvml.mig_enabled) {
    uint64_t dev_used_kb = s.vram.used_mb * 1024ull;
    if (dev_used_kb > 0) {
      uint64_t known = 0; for (auto& kv : pid_to_gpu_mem_kb) known += kv.second;
      if (known < dev_used_kb) {
        uint64_t residual = dev_used_kb - known;
        int chosen = choose_gpu_pid();
        if (chosen < 0 && running_pids.size() == 1) chosen = *running_pids.begin();
        if (chosen < 0 && !pid_to_gpu.empty()) {
          // pick max GPU% pid
          int bestp = -1, bestu = -1; for (auto& kv : pid_to_gpu) { if (kv.second > bestu) { bestu = kv.second; bestp = kv.first; } }
          chosen = bestp;
        }
        if (chosen > 0) {
          pid_to_gpu_mem_kb[chosen] += residual;
        }
      }
    }
  }

  // Fallbacks: if no per-process samples but exactly one running PID, attribute device-level util to it
  if (pid_to_gpu.empty() && running_pids.size() == 1 && !s.nvml.mig_enabled) {
    int only_pid = *running_pids.begin();
    int dev_util = (int)std::max({ (double)as_int_pct(s.vram.gpu_util_pct), (double)as_int_pct(s.vram.enc_util_pct), (double)as_int_pct(s.vram.dec_util_pct) });
    if (dev_util > 0) pid_to_gpu[only_pid] = dev_util;
  }
  // Heuristic: If still empty but device shows activity, attribute to a single clear GPU process
  if (pid_to_gpu.empty() && !s.nvml.mig_enabled) {
    int dev_util = (int)std::max({ (double)as_int_pct(s.vram.gpu_util_pct), (double)as_int_pct(s.vram.enc_util_pct), (double)as_int_pct(s.vram.dec_util_pct) });
    if (dev_util > 0) {
      int gpu_proc_pid = -1; int matches = 0; int chrome_gpu_pid = -1;
      for (const auto& p : s.procs.processes) {
        const std::string& c = p.cmd;
        bool is_gpu_proc = (c.find("--type=gpu-process") != std::string::npos);
        bool is_x = (c.find("/usr/lib/Xorg") != std::string::npos) || (c.find("Xorg") != std::string::npos) || (c.find("Xwayland") != std::string::npos);
        if (is_gpu_proc || is_x) {
          matches++; gpu_proc_pid = p.pid;
          if (c.find("chrome") != std::string::npos || c.find("helium") != std::string::npos) chrome_gpu_pid = p.pid;
        }
      }
      int chosen = -1;
      if (matches == 1) chosen = gpu_proc_pid;
      else if (chrome_gpu_pid > 0) chosen = chrome_gpu_pid; // prefer Chrome/Helium GPU process if present
      if (chosen > 0) { pid_to_gpu[chosen] = dev_util; running_pids.insert(chosen); }
    }
  }
  // Fallback: distribute device util proportionally to GPU memory among running pids
  if (pid_to_gpu.empty() && !running_pids.empty() && !s.nvml.mig_enabled) {
    int dev_util = (int)std::max({ (double)as_int_pct(s.vram.gpu_util_pct), (double)as_int_pct(s.vram.enc_util_pct), (double)as_int_pct(s.vram.dec_util_pct) });
    if (dev_util > 0) {
      uint64_t total_mem = 0; for (int pid : running_pids) { auto it = pid_to_gpu_mem_kb.find(pid); if (it!=pid_to_gpu_mem_kb.end() && it->second>0) total_mem += it->second; }
      if (total_mem > 0) {
        for (int pid : running_pids) {
          auto it = pid_to_gpu_mem_kb.find(pid);
          if (it != pid_to_gpu_mem_kb.end() && it->second > 0) {
            int share = (int)(( (long double)dev_util * (long double)it->second ) / (long double)total_mem);
            if (share < 1) share = 1;
            pid_to_gpu[pid] = share;
          }
        }
      } else {
        int n = (int)running_pids.size(); int base = std::max(1, dev_util / std::max(1,n)); for (int pid : running_pids) pid_to_gpu[pid] = base;
      }
    }
  }

  // Update smoothing state
  for (const auto& kv : pid_to_gpu) {
    int pid = kv.first; int util = kv.second;
    auto& st = gpu_smooth_[pid]; st.ema = (st.last_sample.time_since_epoch().count() == 0) ? (double)util : (0.5 * st.ema + 0.5 * (double)util); st.last_sample = now_tp;
  }
  for (int pid : running_pids) { auto& st = gpu_smooth_[pid]; st.last_running = now_tp; }

  // Write back to processes
  const auto hold = std::chrono::milliseconds(3000);
  const auto decay = std::chrono::milliseconds(3000);
  const auto exit_decay = std::chrono::milliseconds(500);
  for (auto& p : s.procs.processes) {
    auto itraw = pid_to_gpu.find(p.pid); p.has_gpu_util_raw = (itraw != pid_to_gpu.end()); p.gpu_util_pct_raw = p.has_gpu_util_raw ? (double)itraw->second : 0.0;
    double disp = 0.0; auto itst = gpu_smooth_.find(p.pid);
    if (itst != gpu_smooth_.end() && itst->second.last_sample.time_since_epoch().count() > 0) {
      auto age = now_tp - itst->second.last_sample; bool running = running_pids.count(p.pid) > 0;
      if (running) disp = itst->second.ema;
      else if (age <= hold) disp = itst->second.ema;
      else { auto over = age - hold; auto dwin = (itst->second.last_running.time_since_epoch().count() > 0 ? decay : exit_decay); double t = (double)std::chrono::duration_cast<std::chrono::milliseconds>(over).count() / (double)std::chrono::duration_cast<std::chrono::milliseconds>(dwin).count();
             if (t < 1.0) disp = itst->second.ema * (1.0 - t); else disp = 0.0; }
    }
    if (disp < 0.0) disp = 0.0;
    if (disp > 100.0) disp = 100.0;
    p.has_gpu_util = (disp > 0.0);
    p.gpu_util_pct = disp;
  }
  for (auto& p : s.procs.processes) { auto mit = pid_to_gpu_mem_kb.find(p.pid); if (mit != pid_to_gpu_mem_kb.end()) { p.has_gpu_mem = true; p.gpu_mem_kb = mit->second; } }
  // Prune smoothing state
  for (auto it = gpu_smooth_.begin(); it != gpu_smooth_.end(); ) { auto age = now_tp - it->second.last_sample; if (age > std::chrono::seconds(30)) it = gpu_smooth_.erase(it); else ++it; }
}

#ifdef MONTAUK_HAVE_NVML
void GpuAttributor::ensure_nvml_init() {
  if (!nvml_inited_) { nvml_inited_ = true; nvml_ok_ = (nvmlInit_v2() == NVML_SUCCESS); }
}
void GpuAttributor::nvml_shutdown_if_needed() { if (nvml_inited_ && nvml_ok_) { nvmlShutdown(); nvml_ok_ = false; } }
#endif

} // namespace montauk::app
