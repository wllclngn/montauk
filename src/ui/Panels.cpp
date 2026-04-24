#include "ui/Panels.hpp"
#include "ui/Config.hpp"
#include "ui/Terminal.hpp"
#include "ui/Formatting.hpp"
#include "ui/widget/Panel.hpp"
#include "ui/widgets/ChartPanel.hpp"
#include "app/ChartHistories.hpp"
#include "util/Retro.hpp"
#include "app/Security.hpp"
#include "util/Churn.hpp"
#include "util/AsciiLower.hpp"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <climits>

namespace montauk::ui {

void render_right_column(widget::Canvas& canvas,
                         const widget::LayoutRect& rect,
                         const montauk::model::Snapshot& s) {
  const int width = rect.width;
  const int iw = std::max(3, width - 2);
  const int target_rows = rect.height;
  int current_y = rect.y;

  // Emit one Panel onto the shared canvas at the current vertical offset.
  auto emit_panel = [&](const std::string& title,
                        const std::vector<std::string>& lines,
                        int min_content_rows) {
    int content_rows = std::max(static_cast<int>(lines.size()), min_content_rows);
    int panel_rows = widget::Panel::height_for(content_rows);
    widget::LayoutRect panel_rect{rect.x, current_y, rect.width, panel_rows};
    widget::Panel panel(title, lines);
    panel.render(canvas, panel_rect, s);
    current_y += panel_rows;
  };

  // Phase 7 layout: normal mode shows the four charted panels only
  // (PROCESSOR, GPU, MEMORY, NETWORK). system_focus = total takeover — all
  // four hidden, the SYSTEM detail block fills the right column. DISK I/O
  // panel is gone from normal mode entirely (details appear inside SYSTEM).
  const bool show_charts  = !g_ui.system_focus;
  const bool show_gpumon  = show_charts && g_ui.show_gpumon;
  const bool show_thermal = g_ui.show_thermal;  // gates thermal detail inside SYSTEM

  // Pre-declare the ChartPanel instances so they persist across frames
  // (scroll buffer + Kitty image ID per instance).
  static widgets::ChartPanel cpu_chart(
      "PROCESSOR", "cpu", &montauk::app::chart_histories().cpu_total);
  static widgets::ChartPanel gpu_util_chart(
      "GPU",  "gpu", &montauk::app::chart_histories().gpu_util);
  static widgets::ChartPanel vram_chart(
      "VRAM", "gpu", &montauk::app::chart_histories().vram_used);
  static widgets::ChartPanel gpu_mem_chart(
      "MEM",  "gpu", &montauk::app::chart_histories().gpu_mem);
  static widgets::ChartPanel enc_chart(
      "ENC",  "gpu", &montauk::app::chart_histories().enc);
  static widgets::ChartPanel dec_chart(
      "DEC",  "gpu", &montauk::app::chart_histories().dec);
  static widgets::ChartPanel mem_chart(
      "MEMORY", "memory", &montauk::app::chart_histories().mem_used);
  static widgets::ChartPanel net_chart(
      "NETWORK", "network",
      widgets::ChartPanel::DualCurveSources{
          &montauk::app::chart_histories().net_rx,
          &montauk::app::chart_histories().net_tx});

  // Dynamic slot sizing: count visible panels, then distribute the full
  // vertical budget proportionally. Panels stretch to fill the column.
  // Minimum slot height of 3 rows (1 content + 2 border) prevents squish
  // on very short terminals.
  struct Slot {
    widgets::ChartPanel* panel;
    bool visible;
  };
  const Slot slots[] = {
      {&cpu_chart,      show_charts},
      {&gpu_util_chart, show_gpumon && s.vram.has_util},
      {&vram_chart,     show_gpumon && s.vram.total_mb > 0},
      {&gpu_mem_chart,  show_gpumon && s.vram.has_mem_util},
      {&enc_chart,      show_gpumon && s.vram.has_encdec},
      {&dec_chart,      show_gpumon && s.vram.has_encdec},
      {&mem_chart,      show_charts},
      {&net_chart,      show_charts},
  };

  // First sweep: any chart that was placed last frame but isn't visible
  // this frame gets its Kitty placement deleted. Without this the
  // terminal keeps rendering the stale image under newly-drawn SYSTEM
  // text (or under a narrower chart set when GPU toggles off). Matches
  // the pattern OUROBOROS uses in AlbumBrowser::clear_all_images().
  for (const auto& sl : slots) {
    if (!sl.visible && sl.panel->is_placed()) {
      sl.panel->hide(canvas);
    }
  }

  if (show_charts) {
    int n_visible = 0;
    for (const auto& sl : slots) if (sl.visible) ++n_visible;

    if (n_visible > 0) {
      // Integer division gives each panel a base height; any remainder is
      // distributed one extra row at a time to the first `remainder` panels
      // so the column fills exactly.
      const int base = std::max(3, target_rows / n_visible);
      int remainder = target_rows - base * n_visible;
      if (remainder < 0) remainder = 0;  // if too many panels, stop filling

      for (const auto& sl : slots) {
        if (!sl.visible) continue;
        if (current_y >= rect.y + target_rows) break;
        int rows = base + (remainder > 0 ? 1 : 0);
        if (remainder > 0) --remainder;
        // Clamp to remaining space.
        int avail = (rect.y + target_rows) - current_y;
        if (rows > avail) rows = avail;
        if (rows < 3) continue;  // not enough room for a meaningful chart
        widget::LayoutRect panel_rect{rect.x, current_y, rect.width, rows};
        sl.panel->render(canvas, panel_rect, s);
        current_y += rows;
      }
    }
  }

  // SYSTEM — only renders in focus mode, fills the full right column.
  // Severity coloring is baked into the lines themselves at build time.
  if (g_ui.system_focus) {
    int remaining = std::max(0, target_rows - (current_y - rect.y));
    int inner_min = std::max(1, remaining - 2);

    const auto& uic = ui_config();
    std::vector<std::string> sys;
    auto push = [&](const std::string& line, int sev = 0) {
      sys.push_back(severity_colored(line, sev));
    };

    // Hostname/Date/Time/Uptime/Kernel (SYSTEM focus only)
    if (g_ui.system_focus) {
      push(lr_align(iw, "HOSTNAME", read_hostname()), 0);
      push(lr_align(iw, "KERNEL", read_kernel_version()), 0);

      bool prefer12 = []() {
        const auto& tf = config().ui.time_format;
        if (!tf.empty()) {
          std::string fmt = tf;
          for (auto& ch : fmt) ch = montauk::util::ascii_lower(static_cast<unsigned char>(ch));
          if (fmt.find("12") != std::string::npos) return true;
          if (fmt.find("24") != std::string::npos) return false;
        }
        return prefer_12h_clock_from_locale();
      }();
      push(lr_align(iw, "DATE", format_date_now_locale()), 0);
      push(lr_align(iw, "TIME", format_time_now(prefer12)), 0);
      push(lr_align(iw, "UPTIME", read_uptime_formatted()), 0);
      push("", 0);
    }

    // COLLECTOR & PROCESS STATS
    if (!s.collector_name.empty()) push(lr_align(iw, "COLLECTOR", s.collector_name), 0);
    if (g_ui.system_focus) push(lr_align(iw, "SCHEDULER", read_scheduler()), 0);
    {
      std::ostringstream rr;
      rr << "ENRICHED:" << s.procs.enriched_count << "  TOTAL:" << s.procs.total_processes;
      push(lr_align(iw, "PROCESSES", rr.str()), 0);
    }
    if (g_ui.system_focus) {
      std::ostringstream rr; rr << "R:" << s.procs.state_running << "  S:" << s.procs.state_sleeping << "  Z:" << s.procs.state_zombie;
      push(lr_align(iw, "STATES", rr.str()), 0);
    }
    push("", 0);

    // CPU SECTION
    if (!s.cpu.model.empty()) push(lr_align(iw, "CPU", s.cpu.model), 0);
    int ncpu = static_cast<int>(std::max<size_t>(1, s.cpu.per_core_pct.size()));
    double topc = 0.0; for (double v : s.cpu.per_core_pct) if (v > topc) topc = v;
    {
      std::ostringstream rr; rr << "AVG:" << (int)(s.cpu.usage_pct+0.5) << "%  TOP:" << (int)(topc+0.5) << "%  COUNT:" << ncpu;
      push(lr_align(iw, "THREADS", rr.str()), 0);
    }
    if (g_ui.system_focus) {
      auto fi = read_cpu_freq_info();
      std::ostringstream rr; rr.setf(std::ios::fixed);
      rr << "CURRENT:";
      if (fi.has_cur) rr << std::setprecision(1) << fi.cur_ghz << "GHz  "; else rr << "N/A  ";
      rr << "MAX:";
      if (fi.has_max) rr << std::setprecision(1) << fi.max_ghz << "GHz "; else rr << "N/A ";
      if (!fi.governor.empty()) rr << "GOV:" << fi.governor << "  ";
      if (!fi.turbo.empty())    rr << "TURBO:" << fi.turbo;
      push(lr_align(iw, "FREQ", rr.str()), 0);

      std::ostringstream ur; ur.setf(std::ios::fixed);
      auto pcti = [](double v){ int x=(int)(v+0.5); return x<0?0:x; };
      ur << "USR:" << pcti(s.cpu.pct_user) << "%  "
         << "SYS:" << pcti(s.cpu.pct_system) << "%  "
         << "IOWAIT:" << pcti(s.cpu.pct_iowait) << "%  "
         << "IRQ:" << pcti(s.cpu.pct_irq) << "%  "
         << "STEAL:" << pcti(s.cpu.pct_steal) << "%";
      push(lr_align(iw, "UTIL", ur.str()), 0);

      double a1=0,a5=0,a15=0; read_loadavg(a1,a5,a15);
      std::ostringstream lr; lr.setf(std::ios::fixed);
      lr << std::setprecision(2) << a1 << "  " << a5 << "  " << a15;
      push(lr_align(iw, "LOAD AVG", lr.str()), 0);

      auto format_rate = [](double rate) -> std::string {
        std::ostringstream os; os.setf(std::ios::fixed);
        os << std::setprecision(0) << rate;
        std::string n = os.str();
        if (rate >= 1000.0) {
          int ip = static_cast<int>(n.length()) - 3;
          while (ip > 0) { n.insert(ip, ","); ip -= 3; }
        }
        return n;
      };
      std::ostringstream cir;
      cir << format_rate(s.cpu.ctxt_per_sec) << "/s  " << format_rate(s.cpu.intr_per_sec) << "/s";
      push(lr_align(iw, "CTXT/INTR", cir.str()), 0);
    }
    push("", 0);

    // GPU SECTION
    if (!s.vram.name.empty()) push(lr_align(iw, "GPU", s.vram.name), 0);
    if (s.vram.has_util || s.vram.total_mb > 0) {
      std::ostringstream rr;
      if (s.vram.has_util) rr << "G:" << (int)(s.vram.gpu_util_pct+0.5) << "% ";
      if (s.vram.total_mb > 0) rr << "VRAM:" << std::fixed << std::setprecision(1) << s.vram.used_pct << "% ";
      if (s.vram.has_util) {
        rr << "M:" << (int)(s.vram.mem_util_pct+0.5) << "%";
        if (s.vram.has_encdec) rr << "  E:" << (int)(s.vram.enc_util_pct+0.5) << "%  D:" << (int)(s.vram.dec_util_pct+0.5) << "%";
      }
      push(lr_align(iw, "UTIL", rr.str()), 0);
    }
    if (s.nvml.available) {
      auto pid_status = [&]() {
        if (s.nvml.sampled_pids > 0) return std::string("nvml");
        int dev_util = static_cast<int>(s.vram.gpu_util_pct + 0.5);
        if (dev_util > 0 && s.nvml.running_pids > 0) return std::string("share");
        return std::string("none");
      }();
      std::ostringstream rr; rr << "PID:" << pid_status
                                << " DEV:" << s.nvml.devices
                                << " RUN:" << s.nvml.running_pids
                                << " SAMP:" << s.nvml.sampled_pids
                                << " AGE:" << s.nvml.sample_age_ms << "ms"
                                << " MIG:" << (s.nvml.mig_enabled ? "on" : "off");
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
          utilp = static_cast<int>((s.vram.power_draw_w / s.vram.power_limit_w) * 100.0 + 0.5);
          if (utilp < 0) utilp = 0;
          if (utilp > 100) utilp = 100;
        }
        std::ostringstream rr;
        rr << utilp << "% UTIL " << grey_bullet() << " " << uic.normal << (int)(s.vram.power_limit_w+0.5) << "W" << sgr_reset();
        push(lr_align(iw, "PLIMIT", rr.str()), 0);
      }
      if (s.vram.has_pstate) {
        std::ostringstream rr; rr << "P" << std::max(0, s.vram.pstate);
        push(lr_align(iw, "PSTATE", rr.str()), 0);
      }
    }
    push("", 0);

    // MEMORY SECTION
    double mem_used_gb = s.mem.used_kb/1048576.0, mem_tot_gb = s.mem.total_kb/1048576.0;
    double mem_avail_gb = s.mem.available_kb/1048576.0;
    {
      std::ostringstream rr;
      if (g_ui.system_focus && s.mem.available_kb > 0) {
        rr << "AVAILABLE:" << std::fixed << std::setprecision(0) << mem_avail_gb << "GB  ";
      }
      rr << std::fixed << std::setprecision(1) << s.mem.used_pct << "% " << grey_bullet() << " "
         << uic.normal << std::setprecision(2) << mem_used_gb << "GB/" << mem_tot_gb << "GB" << sgr_reset();
      push(lr_align(iw, "MEM", rr.str()), 0);
    }
    if (g_ui.system_focus) {
      std::ostringstream rr;
      rr << std::fixed << std::setprecision(1) << (s.mem.cached_kb/1048576.0) << "GB / "
         << std::setprecision(1) << (s.mem.buffers_kb/1048576.0) << "GB";
      push(lr_align(iw, "CACHE/BUF", rr.str()), 0);
    }
    push("", 0);

    // DISK I/O / FILESYSTEMS
    if (!s.fs.mounts.empty()) {
      push("DISK I/O:", 0);
      if (g_ui.system_focus) {
        std::ostringstream os;
        os << (int)(s.disk.total_read_bps/1000000) << "MB/s/" << (int)(s.disk.total_write_bps/1000000) << "MB/s";
        push(lr_align(iw, "READ/WRITE", os.str()), 0);
      }
      auto human_bytes = [](uint64_t b) { return format_size(b, 1, true); };
      size_t lim = std::min<size_t>(s.fs.mounts.size(), 3);
      for (size_t i=0;i<lim;i++) {
        const auto& m = s.fs.mounts[i];
        std::ostringstream right;
        right << (int)(m.used_pct+0.5) << "% " << grey_bullet() << " "
              << uic.normal << human_bytes(m.used_bytes) << "/" << human_bytes(m.total_bytes) << sgr_reset();
        std::string left = m.device.empty() ? m.fstype : m.device;
        push(lr_align(iw, left, right.str()), 0);
      }
      push("", 0);
    }

    // NETWORK SECTION (inside SYSTEM focus)
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

    // TEMPERATURE SECTION
    if (show_thermal) {
      const auto& thr = config().thresholds;
      auto thr_from = [&](bool has_thr, double thr_c, int cfg_warn) {
        int fallback_warn = cfg_warn > 0 ? cfg_warn : thr.gpu_temp_warning_c;
        int warn = has_thr ? static_cast<int>(thr_c + 0.5) : fallback_warn;
        int gpu_cau = thr.gpu_temp_caution_c > 0 ? thr.gpu_temp_caution_c : std::max(0, warn - thr.temp_caution_delta_c);
        return std::pair<int,int>{gpu_cau, warn};
      };
      if (s.thermal.has_temp) {
        int warn = s.thermal.has_warn ? static_cast<int>(s.thermal.warn_c + 0.5) : thr.cpu_temp_warning_c;
        int caution = thr.cpu_temp_caution_c > 0 ? thr.cpu_temp_caution_c : std::max(0, warn - thr.temp_caution_delta_c);
        int val = static_cast<int>(s.thermal.cpu_max_c + 0.5);
        std::ostringstream rr; rr << val << "°C";
        push(lr_align(iw, "CPU TEMP", rr.str()), compute_severity(val, caution, warn));
      }
      for (size_t i = 0; i < s.vram.devices.size(); ++i) {
        const auto& d = s.vram.devices[i];
        if (!(d.has_temp_edge || d.has_temp_hotspot || d.has_temp_mem)) continue;
        std::ostringstream rr;
        bool first = false;
        int dev_sev = 0;
        if (d.has_temp_edge)    { auto [cau,warn] = thr_from(d.has_thr_edge,    d.thr_edge_c,    thr.gpu_temp_edge_warning_c); int v=static_cast<int>(d.temp_edge_c+0.5);    dev_sev = std::max(dev_sev, compute_severity(v, cau, warn)); rr << "E:" << v << "°C"; first=true; }
        if (d.has_temp_hotspot) { auto [cau,warn] = thr_from(d.has_thr_hotspot, d.thr_hotspot_c, thr.gpu_temp_hot_warning_c);  int v=static_cast<int>(d.temp_hotspot_c+0.5); dev_sev = std::max(dev_sev, compute_severity(v, cau, warn)); rr << (first?"  ":"") << "H:" << v << "°C"; first=true; }
        if (d.has_temp_mem)     { auto [cau,warn] = thr_from(d.has_thr_mem,     d.thr_mem_c,     thr.gpu_temp_mem_warning_c);  int v=static_cast<int>(d.temp_mem_c+0.5);     dev_sev = std::max(dev_sev, compute_severity(v, cau, warn)); rr << (first?"  ":"") << "M:" << v << "°C"; }
        std::string label = (s.vram.devices.size() > 1) ? (std::string("GPU") + std::to_string(i) + " TEMP") : std::string("GPU TEMP");
        push(lr_align(iw, label, rr.str()), dev_sev);
      }
      if (g_ui.system_focus) {
        if (s.thermal.has_fan) {
          std::ostringstream rr; rr << (int)(s.thermal.fan_rpm + 0.5) << " RPM";
          push(lr_align(iw, "CPU FAN", rr.str()), 0);
        } else {
          push(lr_align(iw, "CPU FAN", "UNDETECTED"), 0);
        }
        for (size_t i = 0; i < s.vram.devices.size(); ++i) {
          const auto& d = s.vram.devices[i];
          std::string label = (s.vram.devices.size() > 1) ? (std::string("GPU") + std::to_string(i) + " FAN") : std::string("GPU FAN");
          if (d.has_fan) {
            std::ostringstream rr; rr << (int)(d.fan_speed_pct + 0.5) << "%";
            push(lr_align(iw, label, rr.str()), 0);
          } else {
            push(lr_align(iw, label, "UNDETECTED"), 0);
          }
        }
        int cpu_delta = 0, gpu_delta = 0; bool have_gpu = false;
        if (s.thermal.has_temp) {
          int warn = s.thermal.has_warn ? static_cast<int>(s.thermal.warn_c + 0.5) : thr.cpu_temp_warning_c;
          int val = static_cast<int>(s.thermal.cpu_max_c + 0.5); cpu_delta = std::max(0, warn - val);
        }
        for (const auto& d : s.vram.devices) {
          int best = INT_MAX; bool any = false;
          if (d.has_temp_edge)    { int warn = d.has_thr_edge?    static_cast<int>(d.thr_edge_c+0.5)    : thr.gpu_temp_warning_c; int v=static_cast<int>(d.temp_edge_c+0.5);    best = std::min(best, std::max(0, warn - v)); any=true; }
          if (d.has_temp_hotspot) { int warn = d.has_thr_hotspot? static_cast<int>(d.thr_hotspot_c+0.5) : thr.gpu_temp_warning_c; int v=static_cast<int>(d.temp_hotspot_c+0.5); best = std::min(best, std::max(0, warn - v)); any=true; }
          if (d.has_temp_mem)     { int warn = d.has_thr_mem?     static_cast<int>(d.thr_mem_c+0.5)     : thr.gpu_temp_warning_c; int v=static_cast<int>(d.temp_mem_c+0.5);     best = std::min(best, std::max(0, warn - v)); any=true; }
          if (any) { if (!have_gpu) { gpu_delta = best; have_gpu = true; } else gpu_delta = std::min(gpu_delta, best); }
        }
        std::ostringstream rr; rr << "CPU \xCE\x94" << cpu_delta << "°C"; if (have_gpu) rr << "  GPU \xCE\x94" << gpu_delta << "°C";
        push(lr_align(iw, "MARGIN TEMPS", rr.str()), 0);
      }
      push("", 0);
    }

    // PROC CHURN / PROC SECURITY - mutually exclusive
    if (s.churn.recent_2s_events > 0) {
      std::vector<const montauk::model::ProcSample*> churned;
      int auth_churn = 0, sys_churn = 0, user_churn = 0;
      for (const auto& p : s.procs.processes) {
        if (p.churn_reason != montauk::model::ChurnReason::None) {
          churned.push_back(&p);
          std::string cmd_lower = p.cmd;
          std::transform(cmd_lower.begin(), cmd_lower.end(), cmd_lower.begin(),
                         [](unsigned char c){ return static_cast<char>(montauk::util::ascii_lower(c)); });
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

      int churn_severity = (auth_churn > 0 && s.churn.recent_2s_events >= 3) ? 2 : 1;

      std::ostringstream summary;
      summary << s.churn.recent_2s_events << " events";
      if (auth_churn > 0) summary << "  AUTH:" << auth_churn;
      if (sys_churn > 0)  summary << "  SYS:" << sys_churn;
      if (user_churn > 0) summary << "  USER:" << user_churn;
      push(lr_align(iw, "PROC CHURN", summary.str()), churn_severity);

      if (g_ui.system_focus) {
        if (s.churn.recent_2s_proc > 0 || s.churn.recent_2s_sys > 0) {
          std::ostringstream src;
          src << "SOURCE  /proc:" << s.churn.recent_2s_proc << "  /sys:" << s.churn.recent_2s_sys;
          push(src.str(), 0);
        }

        int lines_used = static_cast<int>(sys.size());
        int available = inner_min - lines_used;
        int detail_lines = std::min(available, static_cast<int>(churned.size()));

        for (int i = 0; i < detail_lines; ++i) {
          const auto& p = *churned[i];
          std::ostringstream line;
          std::string cmd_lower = p.cmd;
          std::transform(cmd_lower.begin(), cmd_lower.end(), cmd_lower.begin(),
                         [](unsigned char c){ return static_cast<char>(montauk::util::ascii_lower(c)); });
          bool is_auth = cmd_lower.find("ssh") != std::string::npos || cmd_lower.find("sudo") != std::string::npos ||
                         cmd_lower.find("login") != std::string::npos || cmd_lower.find("pam") != std::string::npos;
          int proc_sev = is_auth ? 2 : 1;

          line << "PROC CHURN ";
          line << (proc_sev >= 2 ? "⚠ " : "▴ ");
          line << "PID " << p.pid << ' ' << (p.user_name.empty() ? "?" : p.user_name) << ' ';
          std::string cmd_disp = p.cmd.empty() ? std::to_string(p.pid) : p.cmd;
          if (cmd_disp.size() > 40) cmd_disp = cmd_disp.substr(0, 37) + "...";
          line << cmd_disp;
          line << " [" << (is_auth ? "AUTH" : (p.user_name == "root" ? "SYSTEM" : "READ FAILED")) << "]";
          push(line.str(), proc_sev);
        }
      }
    } else {
      auto findings = montauk::app::collect_security_findings(s);
      if (findings.empty()) {
        push(lr_align(iw, "PROC SECURITY", "OK"), 0);
      } else {
        int warn = 0, caution = 0;
        for (const auto& f : findings) {
          if      (f.severity >= 2) ++warn;
          else if (f.severity == 1) ++caution;
        }
        std::ostringstream summary; bool wrote = false;
        if (warn > 0)    { summary << "WARN:" << warn; wrote = true; }
        if (caution > 0) { if (wrote) summary << "  "; summary << "CAUTION:" << caution; wrote = true; }
        if (!wrote)      { summary << "INFO:" << findings.size(); }
        int summary_sev = warn > 0 ? 2 : (caution > 0 ? 1 : 0);
        push(lr_align(iw, "PROC SECURITY", summary.str()), summary_sev);

        if (g_ui.system_focus) {
          int lines_used = static_cast<int>(sys.size());
          int available = inner_min - lines_used;
          int max_rows = std::min(available, static_cast<int>(findings.size()));
          for (int i = 0; i < max_rows; ++i) {
            const auto& f = findings[i];
            push(montauk::app::format_security_line_default(f), f.severity);
          }
        }
      }
    }

    emit_panel("SYSTEM", sys, inner_min);
  }
  // Remaining rows in rect (if any) stay untouched on the canvas — they were
  // cleared to blank cells at canvas construction.
}

} // namespace montauk::ui
