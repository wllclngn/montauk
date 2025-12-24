#include "ui/Panels.hpp"
#include "ui/Config.hpp"
#include "ui/Terminal.hpp"
#include "ui/Formatting.hpp"
#include "ui/Renderer.hpp"
#include "util/Retro.hpp"
#include "app/Security.hpp"
#include "util/Churn.hpp"
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace montauk::ui {

std::vector<std::string> render_gpu_panel(const montauk::model::Snapshot& /*s*/, int /*width*/) {
  return {};
}

std::vector<std::string> render_memory_panel(const montauk::model::Snapshot& /*s*/, int /*width*/) {
  return {};
}

std::vector<std::string> render_disk_panel(const montauk::model::Snapshot& /*s*/, int /*width*/) {
  return {};
}

std::vector<std::string> render_network_panel(const montauk::model::Snapshot& /*s*/, int /*width*/) {
  return {};
}

std::vector<std::string> render_system_panel(const montauk::model::Snapshot& /*s*/, int /*width*/, int /*target_rows*/) {
  return {};
}

std::vector<std::string> render_right_column(const montauk::model::Snapshot& s, int width, int target_rows) {
  std::vector<std::string> out;
  int iw = std::max(3, width - 2);
  auto box_add = [&](const std::string& title, const std::vector<std::string>& lines, int min_h=0){
    auto b = make_box(title, lines, width, min_h); out.insert(out.end(), b.begin(), b.end());
  };
  bool show_disk = g_ui.show_disk, show_net = g_ui.show_net,
       show_thermal = g_ui.show_thermal, show_gpumon = g_ui.show_gpumon;
  // In SYSTEM focus, hide other panels; when leaving focus, restore default panels
  if (g_ui.system_focus) {
    show_disk=false; show_net=false; show_gpumon=false;
  } else {
    show_disk=true; show_net=true; show_gpumon=true;
  }
  // Shared helper for one-line retro bars (label width 8, bar-only)
  auto bar_line8 = [&](const std::string& key, const char* label8, double pct_raw){
    const int label_w = 8;
    int barw = std::max(10, iw - (label_w + 3));
    double bar_pct = montauk::ui::smooth_value(key, pct_raw);
    std::string bar = montauk::util::retro_bar(bar_pct, barw);
    std::ostringstream os; os << trunc_pad(label8, label_w) << " " << bar;
    return os.str();
  };

  // PROCESSOR (CPU) — first on right (hidden in SYSTEM focus)
  if (!g_ui.system_focus) {
    std::vector<std::string> lines;
    lines.push_back(bar_line8("cpu.total", "CPU", s.cpu.usage_pct));
    box_add("PROCESSOR", lines, 1);
  }
  // (DISK I/O and NETWORK moved below GPU MONITOR)
  // GPU Info removed (details live in SYSTEM)
  // VRAM panel removed; VRAM appears as a row in GPU MONITOR and details in SYSTEM
  // THERMALS moved into SYSTEM box (removed)
  // GPU — fixed size with gentle spacing between rows
  if (show_gpumon) {
    std::vector<std::string> lines;
    auto gpu_line = [&](const std::string& key, const char* label8, double pct_raw){
      const int label_w = 8;
      // Bar only (percent shown in SYSTEM)
      // label + space + '[' + bar + ']' must fit
      int barw = std::max(10, iw - (label_w + 3));
      double bar_pct = montauk::ui::smooth_value(key, pct_raw);
      std::string bar = montauk::util::retro_bar(bar_pct, barw);
      std::ostringstream os; os << trunc_pad(label8, label_w) << " " << bar;
      return os.str();
    };
    auto add_row = [&](const std::string& row){ if (!row.empty()) lines.push_back(row); if (!lines.empty()) lines.push_back(""); };
    // Order: GPU → VRAM → MEM → ENC → DEC
    if (s.vram.has_util)    { add_row(gpu_line("gpu.util", "GPU", s.vram.gpu_util_pct)); }
    if (s.vram.total_mb > 0) { add_row(gpu_line("gpu.vram_used", "VRAM", s.vram.used_pct)); }
    if (s.vram.has_mem_util){ add_row(gpu_line("gpu.mem_util", "MEM", s.vram.mem_util_pct)); }
    if (s.vram.has_encdec) {
      add_row(gpu_line("gpu.enc", "ENC", s.vram.enc_util_pct));
      add_row(gpu_line("gpu.dec", "DEC", s.vram.dec_util_pct));
    }
    // POWER removed from GPU MONITOR (shown in SYSTEM)
    // Remove the trailing spacer if present
    if (!lines.empty() && lines.back().empty()) lines.pop_back();
    box_add("GPU", lines, (int)lines.size());
  }
  // MEMORY (after GPU) — hidden in SYSTEM focus
  if (!g_ui.system_focus) {
    std::vector<std::string> lines;
    lines.push_back(bar_line8("mem.used", "MEMORY", s.mem.used_pct));
    box_add("MEMORY", lines, 1);
  }
  // DISK I/O (after MEMORY)
  if (show_disk) {
    std::vector<std::string> lines;
    {
      std::ostringstream rs; rs << "R:" << (int)(s.disk.total_read_bps/1000000) << "MB/s  W:" << (int)(s.disk.total_write_bps/1000000) << "MB/s";
      lines.push_back(lr_align(iw, "", rs.str()));
    }
    size_t lim = std::min<size_t>(s.disk.devices.size(), 3);
    for (size_t i=0;i<lim;i++) {
      const auto& d = s.disk.devices[i];
      std::ostringstream r; r << (int)(d.util_pct+0.5) << "%";
      lines.push_back(lr_align(iw, d.name, r.str()));
    }
    box_add("DISK I/O", lines, 3);
  }
  // NETWORK (after DISK I/O)
  if (show_net) {
    std::vector<std::string> lines;
    {
      std::ostringstream rs; rs << "↓" << (int)(s.net.agg_rx_bps/1024) << "KB/s  ↑" << (int)(s.net.agg_tx_bps/1024) << "KB/s";
      lines.push_back(lr_align(iw, "", rs.str()));
    }
    size_t lim = std::min<size_t>(s.net.interfaces.size(), 3);
    for (size_t i=0;i<lim;i++) {
      const auto& n = s.net.interfaces[i];
      std::ostringstream rr; rr << "↓" << (int)(n.rx_bps/1024) << "KB/s  ↑" << (int)(n.tx_bps/1024) << "KB/s";
      lines.push_back(lr_align(iw, n.name, rr.str()));
    }
    box_add("NETWORK", lines, 3);
  }
  // SYSTEM box — last, elastic to fill all remaining space to match PROCESS MONITOR height
  {
    int remaining = std::max(0, target_rows - (int)out.size());
    // Always create SYSTEM box, minimum 1 line of content
    int inner_min = std::max(1, remaining - 2);
    std::vector<std::string> sys; std::vector<int> sys_sev; // 0 none, 1 caution, 2 warning
    auto push = [&](const std::string& s, int sev=0){ sys.push_back(s); sys_sev.push_back(sev); };
    
    // Hostname/Date/Time/Uptime/Kernel (show in SYSTEM focus only)
    if (g_ui.system_focus) {
      std::string hostname = read_hostname();
      push(lr_align(iw, "HOSTNAME", hostname), 0);
      
      std::string kernel = read_kernel_version();
      push(lr_align(iw, "KERNEL", kernel), 0);
      
      bool prefer12 = [](){
        const char* v = getenv_compat("MONTAUK_TIME_FORMAT");
        if (v && *v) { std::string s=v; for (auto& c: s) c=std::tolower((unsigned char)c); if (s.find("12")!=std::string::npos) return true; if (s.find("24")!=std::string::npos) return false; }
        return prefer_12h_clock_from_locale();
      }();
      std::string dates = format_date_now_locale();
      std::string times = format_time_now(prefer12);
      push(lr_align(iw, "DATE", dates), 0);
      push(lr_align(iw, "TIME", times), 0);
      
      std::string uptime = read_uptime_formatted();
      push(lr_align(iw, "UPTIME", uptime), 0);
      
      push("", 0);
    }

    // === CPU SECTION ===
    if (!s.cpu.model.empty()) {
      push(lr_align(iw, "CPU", s.cpu.model), 0);
    }
    int ncpu = (int)std::max<size_t>(1, s.cpu.per_core_pct.size());
    double topc = 0.0; for (double v : s.cpu.per_core_pct) if (v > topc) topc = v;
    {
      std::ostringstream rr; rr << "COUNT:" << ncpu << "  TOP: " << (int)(topc+0.5) << "%  AVG: " << (int)(s.cpu.usage_pct+0.5) << "%";
      push(lr_align(iw, "THREADS", rr.str()), 0);
    }
    // CPU freq/governor/turbo
    if (g_ui.system_focus) {
      auto fi = read_cpu_freq_info();
      std::ostringstream rr; rr.setf(std::ios::fixed);
      rr << "CURRENT:";
      if (fi.has_cur) { rr << std::setprecision(1) << fi.cur_ghz << "GHz  "; } else { rr << "N/A  "; }
      rr << "MAX:";
      if (fi.has_max) { rr << std::setprecision(1) << fi.max_ghz << "GHz "; } else { rr << "N/A "; }
      if (!fi.governor.empty()) rr << "GOV:" << fi.governor << "  ";
      if (!fi.turbo.empty()) rr << "TURBO:" << fi.turbo;
      push(lr_align(iw, "FREQ", rr.str()), 0);
    }
    // CPU UTIL breakdown
    if (g_ui.system_focus) {
      std::ostringstream rr; rr.setf(std::ios::fixed);
      auto pcti = [](double v){ int x = (int)(v+0.5); if (x<0) x=0; return x; };
      rr << "USR:" << pcti(s.cpu.pct_user) << "%  "
         << "SYS:" << pcti(s.cpu.pct_system) << "%  "
         << "IOWAIT:" << pcti(s.cpu.pct_iowait) << "%  "
         << "IRQ:" << pcti(s.cpu.pct_irq) << "%  "
         << "STEAL:" << pcti(s.cpu.pct_steal) << "%";
      push(lr_align(iw, "UTIL", rr.str()), 0);
    }
    // LOAD AVG
    if (g_ui.system_focus) {
      double a1=0,a5=0,a15=0; read_loadavg(a1,a5,a15);
      std::ostringstream rr; rr.setf(std::ios::fixed);
      rr << std::setprecision(2) << a1 << "  " << a5 << "  " << a15;
      push(lr_align(iw, "LOAD AVG", rr.str()), 0);
    }
    // CTXT/INTR (context switches and interrupts per second)
    if (g_ui.system_focus) {
      std::ostringstream rr;
      auto format_rate = [](double rate) -> std::string {
        if (rate >= 1000.0) {
          std::ostringstream os; os.setf(std::ios::fixed);
          os << std::setprecision(0) << rate;
          std::string s = os.str();
          // Add thousand separators
          int insertPosition = (int)s.length() - 3;
          while (insertPosition > 0) {
            s.insert(insertPosition, ",");
            insertPosition -= 3;
          }
          return s;
        } else {
          std::ostringstream os; os.setf(std::ios::fixed);
          os << std::setprecision(0) << rate;
          return os.str();
        }
      };
      rr << format_rate(s.cpu.ctxt_per_sec) << "/s  " << format_rate(s.cpu.intr_per_sec) << "/s";
      push(lr_align(iw, "CTXT/INTR", rr.str()), 0);
    }
    push("", 0);
    
    // === GPU SECTION ===
    if (!s.vram.name.empty()) push(lr_align(iw, "GPU", s.vram.name), 0);
    if (s.vram.has_util || s.vram.total_mb > 0) {
      std::ostringstream rr;
      if (s.vram.has_util) {
        rr << "G:" << (int)(s.vram.gpu_util_pct+0.5) << "% ";
      }
      if (s.vram.total_mb > 0) {
        rr << "VRAM:" << std::fixed << std::setprecision(1) << s.vram.used_pct << "% ";
      }
      if (s.vram.has_util) {
        rr << "M:" << (int)(s.vram.mem_util_pct+0.5) << "%";
        if (s.vram.has_encdec) rr << "  E:" << (int)(s.vram.enc_util_pct+0.5) << "%  D:" << (int)(s.vram.dec_util_pct+0.5) << "%";
      }
      push(lr_align(iw, "UTIL", rr.str()), 0);
    }
    if (s.nvml.available) {
      auto pid_status = [&](){
        if (s.nvml.sampled_pids > 0) return std::string("nvml");
        int dev_util = (int)(s.vram.gpu_util_pct + 0.5);
        if (dev_util > 0 && s.nvml.running_pids > 0) return std::string("share");
        return std::string("none");
      }();
      std::ostringstream rr; rr << (s.nvml.available? "OK" : "OFF")
                                << " DEV:" << s.nvml.devices
                                << " RUN:" << s.nvml.running_pids
                                << " SAMP:" << s.nvml.sampled_pids
                                << " AGE:" << s.nvml.sample_age_ms << "ms"
                                << " MIG:" << (s.nvml.mig_enabled? "on":"off")
                                << " PID:" << pid_status;
      push(lr_align(iw, "NVML", rr.str()), 0);
    }
    if (s.vram.has_power) { 
      std::ostringstream rr; rr << (int)(s.vram.power_draw_w+0.5) << "W"; 
      push(lr_align(iw, "POWER", rr.str()), 0); 
    }
    if (g_ui.system_focus) {
      if (s.vram.has_power_limit) {
        int utilp = 0;
        if (s.vram.has_power && s.vram.power_limit_w > 0.0) {
          utilp = (int)((s.vram.power_draw_w / s.vram.power_limit_w) * 100.0 + 0.5);
          if (utilp < 0) utilp = 0;
          if (utilp > 100) utilp = 100;
        }
        std::ostringstream rr; 
        rr << "[" << utilp << "% UTIL] " << (int)(s.vram.power_limit_w+0.5) << "W";
        push(lr_align(iw, "PLIMIT", rr.str()), 0);
      }
      if (s.vram.has_pstate) {
        std::ostringstream rr; rr << "P" << std::max(0, s.vram.pstate);
        push(lr_align(iw, "PSTATE", rr.str()), 0);
      }
    }
    push("", 0);
    
    // === MEMORY SECTION ===
    double mem_used_gb = s.mem.used_kb/1048576.0, mem_tot_gb = s.mem.total_kb/1048576.0;
    double mem_avail_gb = s.mem.available_kb/1048576.0;
    {
      std::ostringstream rr;
      if (g_ui.system_focus && s.mem.available_kb > 0) {
        rr << "AVAILABLE:" << std::fixed << std::setprecision(0) << mem_avail_gb << "GB  ";
      }
      rr << std::fixed << std::setprecision(1) << s.mem.used_pct << "% ["
         << std::setprecision(2) << mem_used_gb << "GB/" << mem_tot_gb << "GB]";
      push(lr_align(iw, "MEM", rr.str()), 0);
    }
    if (g_ui.system_focus) {
      std::ostringstream rr;
      rr << std::fixed << std::setprecision(1) << (s.mem.cached_kb/1048576.0) << "GB / " 
         << std::setprecision(1) << (s.mem.buffers_kb/1048576.0) << "GB";
      push(lr_align(iw, "CACHE/BUF", rr.str()), 0);
    }
    // No SWAP line in SYSTEM focus per design preference
    push("", 0);
    
    // === DISK I/O / FILESYSTEMS SECTION ===
    if (!s.fs.mounts.empty()) {
      push("DISK I/O:", 0);
      // Aggregate read/write throughput (SYSTEM focus only)
      if (g_ui.system_focus) {
        std::ostringstream os; 
        os << (int)(s.disk.total_read_bps/1000000) << "MB/s/" << (int)(s.disk.total_write_bps/1000000) << "MB/s";
        push(lr_align(iw, "READ/WRITE", os.str()), 0);
      }
      auto human_bytes = [](uint64_t b){
        const double kb = 1024.0, mb = kb*1024.0, gb = mb*1024.0, tb = gb*1024.0;
        std::ostringstream os; os.setf(std::ios::fixed); os<<std::setprecision(1);
        if (b >= (uint64_t)tb) { os<< (b/tb) << "T"; }
        else if (b >= (uint64_t)gb) { os<< (b/gb) << "G"; }
        else if (b >= (uint64_t)mb) { os<< (b/mb) << "M"; }
        else { os<< (int)(b/kb+0.5) << "K"; }
        return os.str();
      };
      size_t lim = std::min<size_t>(s.fs.mounts.size(), 3);
      for (size_t i=0;i<lim;i++) {
        const auto& m = s.fs.mounts[i];
        std::ostringstream right; right << (int)(m.used_pct+0.5) << "% ["
                                        << human_bytes(m.used_bytes) << "/" << human_bytes(m.total_bytes) << "]";
        std::string left = m.device.empty() ? m.fstype : m.device;
        push(lr_align(iw, left, right.str()), 0);
      }
      push("", 0);
    }
    // === NETWORK SECTION (inside SYSTEM focus) ===
    if (g_ui.system_focus) {
      push("NETWORK", 0);
      {
        std::ostringstream rs; rs << "\xE2\x86\x93" << (int)(s.net.agg_rx_bps/1024) << "KB/s  \xE2\x86\x91" << (int)(s.net.agg_tx_bps/1024) << "KB/s";
        push(lr_align(iw, "DOWN/UP", rs.str()), 0);
      }
      size_t lim = std::min<size_t>(s.net.interfaces.size(), 2);
      for (size_t i=0;i<lim;i++) {
        const auto& n = s.net.interfaces[i];
        std::ostringstream rr; rr << "\xE2\x86\x93" << (int)(n.rx_bps/1024) << "KB/s  \xE2\x86\x91" << (int)(n.tx_bps/1024) << "KB/s";
        push(lr_align(iw, n.name, rr.str()), 0);
      }
      push("", 0);
    }
    
    // === TEMPERATURE SECTION ===
    if (show_thermal) {
      auto thr_from = [&](bool has_thr, double thr_c, const char* env_warn, const char* env_warn_fallback){
        int def_warn = getenv_int(env_warn_fallback, 90);
        int warn = has_thr ? (int)(thr_c + 0.5) : getenv_int(env_warn, def_warn);
        int caution = getenv_int((std::string(env_warn).substr(0, std::string(env_warn).find_last_of('_')) + "_CAUTION_C").c_str(),
                                 getenv_int("MONTAUK_GPU_TEMP_CAUTION_C", std::max(0, warn - getenv_int("MONTAUK_TEMP_CAUTION_DELTA_C", 10))));
        return std::pair<int,int>{caution,warn};
      };
      // CPU temp
      if (s.thermal.has_temp) {
        int warn = s.thermal.has_warn ? (int)(s.thermal.warn_c + 0.5) : getenv_int("MONTAUK_CPU_TEMP_WARNING_C", 90);
        int caution = getenv_int("MONTAUK_CPU_TEMP_CAUTION_C", std::max(0, warn - getenv_int("MONTAUK_TEMP_CAUTION_DELTA_C", 10)));
        int val = (int)(s.thermal.cpu_max_c + 0.5);
        int sev = (val>=warn)?2:((val>=caution)?1:0);
        std::ostringstream rr; rr << val << "°C";
        push(lr_align(iw, "CPU TEMP", rr.str()), sev);
      }
      // GPU temps
      for (size_t i=0;i<s.vram.devices.size(); ++i) {
        const auto& d = s.vram.devices[i];
        if (!(d.has_temp_edge || d.has_temp_hotspot || d.has_temp_mem)) continue;
        std::ostringstream rr;
        bool first=false;
        int dev_sev = 0;
        if (d.has_temp_edge) { auto [cau,warn] = thr_from(d.has_thr_edge, d.thr_edge_c, "MONTAUK_GPU_TEMP_EDGE_WARNING_C", "MONTAUK_GPU_TEMP_WARNING_C"); int v=(int)(d.temp_edge_c+0.5); dev_sev=std::max(dev_sev,(v>=warn)?2:((v>=cau)?1:0)); rr << "E:" << v << "°C"; first=true; }
        if (d.has_temp_hotspot) { auto [cau,warn] = thr_from(d.has_thr_hotspot, d.thr_hotspot_c, "MONTAUK_GPU_TEMP_HOT_WARNING_C", "MONTAUK_GPU_TEMP_WARNING_C"); int v=(int)(d.temp_hotspot_c+0.5); dev_sev=std::max(dev_sev,(v>=warn)?2:((v>=cau)?1:0)); rr << (first?"  ":"") << "H:" << v << "°C"; first=true; }
        if (d.has_temp_mem) { auto [cau,warn] = thr_from(d.has_thr_mem, d.thr_mem_c, "MONTAUK_GPU_TEMP_MEM_WARNING_C", "MONTAUK_GPU_TEMP_WARNING_C"); int v=(int)(d.temp_mem_c+0.5); dev_sev=std::max(dev_sev,(v>=warn)?2:((v>=cau)?1:0)); rr << (first?"  ":"") << "M:" << v << "°C"; }
        {
          std::string label = (s.vram.devices.size()>1) ? (std::string("GPU") + std::to_string(i) + " TEMP") : std::string("GPU TEMP");
          push(lr_align(iw, label, rr.str()), dev_sev);
        }
      }
      // Margin temps summary line (SYSTEM focus): CPU Δ.., GPU Δ..
      if (g_ui.system_focus) {
        int cpu_delta = 0; int gpu_delta = 0; bool have_gpu=false;
        if (s.thermal.has_temp) {
          int warn = s.thermal.has_warn ? (int)(s.thermal.warn_c + 0.5) : getenv_int("MONTAUK_CPU_TEMP_WARNING_C", 90);
          int val = (int)(s.thermal.cpu_max_c + 0.5); cpu_delta = std::max(0, warn - val);
        }
        for (const auto& d : s.vram.devices) {
          int best = INT_MAX; bool any=false;
          if (d.has_temp_edge) { int warn = d.has_thr_edge? (int)(d.thr_edge_c+0.5) : getenv_int("MONTAUK_GPU_TEMP_WARNING_C", 90); int v=(int)(d.temp_edge_c+0.5); best = std::min(best, std::max(0, warn - v)); any=true; }
          if (d.has_temp_hotspot) { int warn = d.has_thr_hotspot? (int)(d.thr_hotspot_c+0.5) : getenv_int("MONTAUK_GPU_TEMP_WARNING_C", 90); int v=(int)(d.temp_hotspot_c+0.5); best = std::min(best, std::max(0, warn - v)); any=true; }
          if (d.has_temp_mem) { int warn = d.has_thr_mem? (int)(d.thr_mem_c+0.5) : getenv_int("MONTAUK_GPU_TEMP_WARNING_C", 90); int v=(int)(d.temp_mem_c+0.5); best = std::min(best, std::max(0, warn - v)); any=true; }
          if (any) { if (!have_gpu) { gpu_delta = best; have_gpu=true; } else { gpu_delta = std::min(gpu_delta, best); } }
        }
        std::ostringstream rr; rr << "CPU \xCE\x94" << cpu_delta << "°C"; if (have_gpu) rr << "  GPU \xCE\x94" << gpu_delta << "°C";
        push(lr_align(iw, "MARGIN TEMPS", rr.str()), 0);
      }
      push("", 0);
    }
    
    // === COLLECTOR & PROCESS STATS ===
    if (!s.collector_name.empty()) {
      push(lr_align(iw, "COLLECTOR", s.collector_name), 0);
    }
    {
      std::ostringstream rr; 
      rr << "ENRICHED:" << s.procs.enriched_count << "  TOTAL:" << s.procs.total_processes;
      push(lr_align(iw, "PROCESSES", rr.str()), 0);
    }
    // System threads (System focus only)
    if (g_ui.system_focus && s.procs.total_threads > 0) {
      std::ostringstream rr;
      double avg_per_proc = (s.procs.total_processes > 0) ? 
        (double)s.procs.total_threads / (double)s.procs.total_processes : 0.0;
      double pct = (s.procs.threads_max > 0) ? 
        (100.0 * (double)s.procs.total_threads / (double)s.procs.threads_max) : 0.0;
      rr << "AVG:" << std::fixed << std::setprecision(1) << avg_per_proc << "/process [" 
         << std::setprecision(1) << pct << "%] " 
         << s.procs.total_threads << "/" << s.procs.threads_max;
      push(lr_align(iw, "SYSTEM THREADS", rr.str()), 0);
    }
    // States breakdown (System focus only)
    if (g_ui.system_focus) {
      std::ostringstream rr; rr << "R:" << s.procs.state_running << "  S:" << s.procs.state_sleeping << "  Z:" << s.procs.state_zombie;
      push(lr_align(iw, "STATES", rr.str()), 0);
    }
    push("", 0);
    
    // PROC CHURN / PROC SECURITY - mutually exclusive display
    if (s.churn.recent_2s_events > 0) {
      // Collect churned processes and categorize them
      std::vector<const montauk::model::ProcSample*> churned;
      int auth_churn = 0, sys_churn = 0, user_churn = 0;
      for (const auto& p : s.procs.processes) {
        if (p.churn_reason != montauk::model::ChurnReason::None) {
          churned.push_back(&p);
          std::string cmd_lower = p.cmd;
          std::transform(cmd_lower.begin(), cmd_lower.end(), cmd_lower.begin(),
                         [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
          if (cmd_lower.find("ssh") != std::string::npos || cmd_lower.find("sudo") != std::string::npos ||
              cmd_lower.find("login") != std::string::npos || cmd_lower.find("pam") != std::string::npos) {
            ++auth_churn;
          } else if (p.user_name == "root" || p.user_name.empty()) {
            ++sys_churn;
          } else {
            ++user_churn;
          }
        }
      }

      // Determine severity: auth churn during high activity = warning, otherwise caution
      int churn_severity = (auth_churn > 0 && s.churn.recent_2s_events >= 3) ? 2 : 1;

      // Summary line with categorized counts
      std::ostringstream summary;
      summary << s.churn.recent_2s_events << " events";
      if (auth_churn > 0) summary << "  AUTH:" << auth_churn;
      if (sys_churn > 0) summary << "  SYS:" << sys_churn;
      if (user_churn > 0) summary << "  USER:" << user_churn;
      push(lr_align(iw, "PROC CHURN", summary.str()), churn_severity);

      // In SYSTEM focus, show detailed churn info matching security format
      if (g_ui.system_focus) {
        // Source breakdown
        if (s.churn.recent_2s_proc > 0 || s.churn.recent_2s_sys > 0) {
          std::ostringstream src;
          src << "SOURCE  /proc:" << s.churn.recent_2s_proc << "  /sys:" << s.churn.recent_2s_sys;
          push(src.str(), 0);
        }

        // Detailed process lines (matching security finding format)
        int lines_used = (int)sys.size();
        int available = inner_min - lines_used;
        int detail_lines = std::min(available, (int)churned.size());

        for (int i = 0; i < detail_lines; ++i) {
          const auto& p = *churned[i];
          std::ostringstream line;
          // Determine per-process severity
          std::string cmd_lower = p.cmd;
          std::transform(cmd_lower.begin(), cmd_lower.end(), cmd_lower.begin(),
                         [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
          bool is_auth = cmd_lower.find("ssh") != std::string::npos || cmd_lower.find("sudo") != std::string::npos ||
                         cmd_lower.find("login") != std::string::npos || cmd_lower.find("pam") != std::string::npos;
          int proc_sev = is_auth ? 2 : 1;

          line << "PROC CHURN ";
          if (proc_sev >= 2) line << "⚠ ";
          else line << "▴ ";
          line << "PID " << p.pid << ' ' << (p.user_name.empty() ? "?" : p.user_name) << ' ';
          // Truncate cmd for display
          std::string cmd_disp = p.cmd.empty() ? std::to_string(p.pid) : p.cmd;
          if (cmd_disp.size() > 40) cmd_disp = cmd_disp.substr(0, 37) + "...";
          line << cmd_disp;
          line << " [" << (is_auth ? "AUTH" : (p.user_name == "root" ? "SYSTEM" : "READ FAILED")) << "]";
          push(line.str(), proc_sev);
        }
      }
    } else {
      // No churn - show PROC SECURITY
      auto findings = montauk::app::collect_security_findings(s);
      if (findings.empty()) {
        push(lr_align(iw, "PROC SECURITY", "OK"), 0);
      } else {
        int warn = 0, caution = 0;
        for (const auto& f : findings) {
          if (f.severity >= 2) ++warn;
          else if (f.severity == 1) ++caution;
        }
        std::ostringstream summary;
        bool wrote = false;
        if (warn > 0) { summary << "WARN:" << warn; wrote = true; }
        if (caution > 0) {
          if (wrote) summary << "  ";
          summary << "CAUTION:" << caution;
          wrote = true;
        }
        if (!wrote) {
          summary << "INFO:" << findings.size();
        }
        int summary_sev = warn > 0 ? 2 : (caution > 0 ? 1 : 0);
        
        // Summary line
        push(lr_align(iw, "PROC SECURITY", summary.str()), summary_sev);
        
        // In SYSTEM focus, show detailed findings - fill ALL available space
        if (g_ui.system_focus) {
          int lines_used = (int)sys.size();
          int available = inner_min - lines_used;
          int max_rows = std::min(available, (int)findings.size());
          
          for (int i = 0; i < max_rows; ++i) {
            const auto& f = findings[i];
            push(montauk::app::format_security_line_default(f), f.severity);
          }
        }
      }
    }
    
    // Build box then apply full-line coloring for temperature lines if needed
    auto sys_box = make_box("SYSTEM", sys, width, inner_min);
    if (!sys_box.empty()) {
      const bool uni = use_unicode(); const std::string V = uni? "│" : "|"; const auto& uic = ui_config();
      for (size_t li=1; li+1<sys_box.size() && (li-1)<sys_sev.size(); ++li) {
        int sv = sys_sev[li-1]; if (sv <= 0) continue;
        auto& line = sys_box[li]; size_t fpos = line.find(V); size_t lpos = line.rfind(V);
        if (fpos==std::string::npos || lpos==std::string::npos || lpos<=fpos) continue;
        size_t start = fpos + V.size();
        std::string pre = line.substr(0, start);
        std::string mid = line.substr(start, lpos - start);
        std::string suf = line.substr(lpos);
        const std::string& col = (sv==2) ? uic.warning : uic.caution;
        line = pre + col + mid + sgr_reset() + suf;
      }
    }
    out.insert(out.end(), sys_box.begin(), sys_box.end());
  }
  // Pad to exactly target_rows to match PROCESS MONITOR height
  while ((int)out.size() < target_rows) {
    out.push_back(std::string(width, ' '));
  }
  return out;
}

} // namespace montauk::ui
