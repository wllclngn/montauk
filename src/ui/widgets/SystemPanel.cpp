#include "ui/widgets/SystemPanel.hpp"
#include "ui/Config.hpp"
#include "ui/Formatting.hpp"
#include "ui/Terminal.hpp"   // grey_bullet(), sgr_reset()
#include "ui/widget/Panel.hpp"
#include "app/Security.hpp"
#include "util/Churn.hpp"
#include "util/AsciiLower.hpp"
#include "util/SortDispatch.hpp"

#include <algorithm>
#include <climits>
#include <iomanip>
#include <sstream>
#include <vector>

namespace montauk::ui::widgets {

using widget::Row;
using Snapshot = montauk::model::Snapshot;
// Pull bullet/reset/etc helpers from the ui namespace so the section
// builders read the same as their original Panels.cpp form.
using montauk::ui::grey_bullet;
using montauk::ui::sgr_reset;

namespace {

// Section builders. Each appends rows to `out`. Pure functions of the
// snapshot (and ui_config()/config() singletons). Order in render() defines
// the visible order in the SYSTEM panel.

void section_identity(std::vector<Row>& out, const Snapshot&) {
  out.push_back(Row::kv("HOSTNAME",  read_hostname()));
  out.push_back(Row::kv("KERNEL",    read_kernel_version()));
  out.push_back(Row::kv("SCHEDULER", read_scheduler()));

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
  out.push_back(Row::kv("DATE",   format_date_now_locale()));
  out.push_back(Row::kv("TIME",   format_time_now(prefer12)));
  out.push_back(Row::kv("UPTIME", read_uptime_formatted()));
  out.push_back(Row::empty());
}

void section_runtime(std::vector<Row>& out, const Snapshot& s) {
  if (!s.collector_name.empty()) out.push_back(Row::kv("COLLECTOR", s.collector_name));

  // SORT: which sort backend is currently active. resolve_backend() reads
  // MONTAUK_SORT_BACKEND env on first call and caches; reflects build-time
  // HAVE_SUBLIMATION too (TimSort when sublimation isn't compiled in).
  out.push_back(Row::kv("SORT",
      montauk::util::resolve_backend() == montauk::util::SortBackend::Sublimation
          ? std::string("sublimation")
          : std::string("TimSort")));

  std::ostringstream procs;
  procs << "ENRICHED:" << s.procs.enriched_count << "  TOTAL:" << s.procs.total_processes;
  out.push_back(Row::kv("PROCESSES", procs.str()));

  std::ostringstream states;
  states << "R:" << s.procs.state_running
         << "  S:" << s.procs.state_sleeping
         << "  Z:" << s.procs.state_zombie;
  out.push_back(Row::kv("STATES", states.str()));
  out.push_back(Row::empty());
}

void section_cpu(std::vector<Row>& out, const Snapshot& s) {
  if (!s.cpu.model.empty()) out.push_back(Row::kv("CPU", s.cpu.model));

  int ncpu = static_cast<int>(std::max<size_t>(1, s.cpu.per_core_pct.size()));
  double topc = 0.0;
  for (double v : s.cpu.per_core_pct) if (v > topc) topc = v;
  {
    std::ostringstream rr;
    rr << "AVG:" << static_cast<int>(s.cpu.usage_pct + 0.5)
       << "%  TOP:" << static_cast<int>(topc + 0.5)
       << "%  COUNT:" << ncpu;
    out.push_back(Row::kv("THREADS", rr.str()));
  }

  auto fi = read_cpu_freq_info();
  {
    std::ostringstream rr; rr.setf(std::ios::fixed);
    rr << "CURRENT:";
    if (fi.has_cur) rr << std::setprecision(1) << fi.cur_ghz << "GHz  "; else rr << "N/A  ";
    rr << "MAX:";
    if (fi.has_max) rr << std::setprecision(1) << fi.max_ghz << "GHz "; else rr << "N/A ";
    if (!fi.governor.empty()) rr << "GOV:" << fi.governor << "  ";
    if (!fi.turbo.empty())    rr << "TURBO:" << fi.turbo;
    out.push_back(Row::kv("FREQ", rr.str()));
  }
  {
    auto pcti = [](double v){ int x = static_cast<int>(v + 0.5); return x < 0 ? 0 : x; };
    std::ostringstream rr;
    rr << "USR:" << pcti(s.cpu.pct_user) << "%  "
       << "SYS:" << pcti(s.cpu.pct_system) << "%  "
       << "IOWAIT:" << pcti(s.cpu.pct_iowait) << "%  "
       << "IRQ:" << pcti(s.cpu.pct_irq) << "%  "
       << "STEAL:" << pcti(s.cpu.pct_steal) << "%";
    out.push_back(Row::kv("UTIL", rr.str()));
  }
  {
    double a1 = 0, a5 = 0, a15 = 0;
    read_loadavg(a1, a5, a15);
    std::ostringstream rr; rr.setf(std::ios::fixed);
    rr << std::setprecision(2) << a1 << "  " << a5 << "  " << a15;
    out.push_back(Row::kv("LOAD AVG", rr.str()));
  }
  {
    auto fmt_rate = [](double rate) -> std::string {
      std::ostringstream os; os.setf(std::ios::fixed);
      os << std::setprecision(0) << rate;
      std::string n = os.str();
      if (rate >= 1000.0) {
        int ip = static_cast<int>(n.length()) - 3;
        while (ip > 0) { n.insert(ip, ","); ip -= 3; }
      }
      return n;
    };
    std::ostringstream rr;
    rr << fmt_rate(s.cpu.ctxt_per_sec) << "/s  " << fmt_rate(s.cpu.intr_per_sec) << "/s";
    out.push_back(Row::kv("CTXT/INTR", rr.str()));
  }
  out.push_back(Row::empty());
}

void section_gpu(std::vector<Row>& out, const Snapshot& s) {
  const auto& uic = ui_config();
  if (!s.vram.name.empty()) out.push_back(Row::kv("GPU", s.vram.name));

  if (s.vram.has_util || s.vram.total_mb > 0) {
    std::ostringstream rr;
    if (s.vram.has_util)     rr << "G:" << static_cast<int>(s.vram.gpu_util_pct + 0.5) << "% ";
    if (s.vram.total_mb > 0) rr << "VRAM:" << std::fixed << std::setprecision(1) << s.vram.used_pct << "% ";
    if (s.vram.has_util) {
      rr << "M:" << static_cast<int>(s.vram.mem_util_pct + 0.5) << "%";
      if (s.vram.has_encdec)
        rr << "  E:" << static_cast<int>(s.vram.enc_util_pct + 0.5)
           << "%  D:" << static_cast<int>(s.vram.dec_util_pct + 0.5) << "%";
    }
    out.push_back(Row::kv("UTIL", rr.str()));
  }

  if (s.nvml.available) {
    auto pid_status = [&]() {
      if (s.nvml.sampled_pids > 0) return std::string("nvml");
      int dev_util = static_cast<int>(s.vram.gpu_util_pct + 0.5);
      if (dev_util > 0 && s.nvml.running_pids > 0) return std::string("share");
      return std::string("none");
    }();
    std::ostringstream rr;
    rr << "PID:" << pid_status
       << " DEV:"  << s.nvml.devices
       << " RUN:"  << s.nvml.running_pids
       << " SAMP:" << s.nvml.sampled_pids
       << " AGE:"  << s.nvml.sample_age_ms << "ms"
       << " MIG:"  << (s.nvml.mig_enabled ? "on" : "off");
    out.push_back(Row::kv("NVML", rr.str()));
  }

  if (s.vram.has_power) {
    std::ostringstream rr; rr << static_cast<int>(s.vram.power_draw_w + 0.5) << "W";
    out.push_back(Row::kv("POWER", rr.str()));
  }

  if (s.vram.has_power_limit) {
    int utilp = 0;
    if (s.vram.has_power && s.vram.power_limit_w > 0.0) {
      utilp = static_cast<int>((s.vram.power_draw_w / s.vram.power_limit_w) * 100.0 + 0.5);
      utilp = std::clamp(utilp, 0, 100);
    }
    std::ostringstream rr;
    rr << utilp << "% UTIL " << grey_bullet() << " "
       << uic.normal << static_cast<int>(s.vram.power_limit_w + 0.5) << "W" << sgr_reset();
    out.push_back(Row::kv("PLIMIT", rr.str()));
  }
  if (s.vram.has_pstate) {
    std::ostringstream rr; rr << "P" << std::max(0, s.vram.pstate);
    out.push_back(Row::kv("PSTATE", rr.str()));
  }
  out.push_back(Row::empty());
}

void section_memory(std::vector<Row>& out, const Snapshot& s) {
  const auto& uic = ui_config();
  const double mem_used_gb  = s.mem.used_kb / 1048576.0;
  const double mem_tot_gb   = s.mem.total_kb / 1048576.0;
  const double mem_avail_gb = s.mem.available_kb / 1048576.0;
  {
    std::ostringstream rr;
    if (s.mem.available_kb > 0)
      rr << "AVAILABLE:" << std::fixed << std::setprecision(0) << mem_avail_gb << "GB  ";
    rr << std::fixed << std::setprecision(1) << s.mem.used_pct << "% " << grey_bullet() << " "
       << uic.normal << std::setprecision(2) << mem_used_gb << "GB/" << mem_tot_gb << "GB" << sgr_reset();
    out.push_back(Row::kv("MEM", rr.str()));
  }
  {
    std::ostringstream rr;
    rr << std::fixed << std::setprecision(1) << (s.mem.cached_kb / 1048576.0) << "GB / "
       << std::setprecision(1) << (s.mem.buffers_kb / 1048576.0) << "GB";
    out.push_back(Row::kv("CACHE/BUF", rr.str()));
  }
  out.push_back(Row::empty());
}

void section_disk(std::vector<Row>& out, const Snapshot& s) {
  if (s.fs.mounts.empty()) return;
  const auto& uic = ui_config();
  out.push_back(Row::header("DISK I/O"));
  {
    std::ostringstream os;
    os << static_cast<int>(s.disk.total_read_bps / 1000000) << "MB/s/"
       << static_cast<int>(s.disk.total_write_bps / 1000000) << "MB/s";
    out.push_back(Row::kv("READ/WRITE", os.str()));
  }
  size_t lim = std::min<size_t>(s.fs.mounts.size(), 3);
  for (size_t i = 0; i < lim; ++i) {
    const auto& m = s.fs.mounts[i];
    std::ostringstream right;
    right << static_cast<int>(m.used_pct + 0.5) << "% " << grey_bullet() << " "
          << uic.normal << format_size(m.used_bytes, 1, true)
          << "/"        << format_size(m.total_bytes, 1, true) << sgr_reset();
    std::string left = m.device.empty() ? m.fstype : m.device;
    out.push_back(Row::kv(std::move(left), right.str()));
  }
  out.push_back(Row::empty());
}

void section_network(std::vector<Row>& out, const Snapshot& s) {
  out.push_back(Row::header("NETWORK"));
  {
    std::ostringstream rs;
    rs << "\xE2\x86\x93" << static_cast<int>(s.net.agg_rx_bps / 1024)
       << "KB/s  \xE2\x86\x91" << static_cast<int>(s.net.agg_tx_bps / 1024) << "KB/s";
    out.push_back(Row::kv("DOWN/UP", rs.str()));
  }
  size_t lim = std::min<size_t>(s.net.interfaces.size(), 2);
  for (size_t i = 0; i < lim; ++i) {
    const auto& n = s.net.interfaces[i];
    std::ostringstream rr;
    rr << "\xE2\x86\x93" << static_cast<int>(n.rx_bps / 1024)
       << "KB/s  \xE2\x86\x91" << static_cast<int>(n.tx_bps / 1024) << "KB/s";
    out.push_back(Row::kv(n.name, rr.str()));
  }
  out.push_back(Row::empty());
}

void section_thermal(std::vector<Row>& out, const Snapshot& s, bool show_thermal) {
  if (!show_thermal) return;
  const auto& thr = config().thresholds;
  auto thr_from = [&](bool has_thr, double thr_c, int cfg_warn) {
    int fallback_warn = cfg_warn > 0 ? cfg_warn : thr.gpu_temp_warning_c;
    int warn = has_thr ? static_cast<int>(thr_c + 0.5) : fallback_warn;
    int caution = thr.gpu_temp_caution_c > 0
                      ? thr.gpu_temp_caution_c
                      : std::max(0, warn - thr.temp_caution_delta_c);
    return std::pair<int, int>{caution, warn};
  };

  if (s.thermal.has_temp) {
    int warn = s.thermal.has_warn ? static_cast<int>(s.thermal.warn_c + 0.5) : thr.cpu_temp_warning_c;
    int caution = thr.cpu_temp_caution_c > 0
                      ? thr.cpu_temp_caution_c
                      : std::max(0, warn - thr.temp_caution_delta_c);
    int val = static_cast<int>(s.thermal.cpu_max_c + 0.5);
    std::ostringstream rr; rr << val << "°C";
    out.push_back(Row::kv("CPU TEMP", rr.str(), compute_severity(val, caution, warn)));
  }
  for (size_t i = 0; i < s.vram.devices.size(); ++i) {
    const auto& d = s.vram.devices[i];
    if (!(d.has_temp_edge || d.has_temp_hotspot || d.has_temp_mem)) continue;
    std::ostringstream rr;
    bool first = false;
    int dev_sev = 0;
    if (d.has_temp_edge)    { auto [c, w] = thr_from(d.has_thr_edge,    d.thr_edge_c,    thr.gpu_temp_edge_warning_c); int v = static_cast<int>(d.temp_edge_c + 0.5);    dev_sev = std::max(dev_sev, compute_severity(v, c, w)); rr << "E:" << v << "°C"; first = true; }
    if (d.has_temp_hotspot) { auto [c, w] = thr_from(d.has_thr_hotspot, d.thr_hotspot_c, thr.gpu_temp_hot_warning_c);  int v = static_cast<int>(d.temp_hotspot_c + 0.5); dev_sev = std::max(dev_sev, compute_severity(v, c, w)); rr << (first ? "  " : "") << "H:" << v << "°C"; first = true; }
    if (d.has_temp_mem)     { auto [c, w] = thr_from(d.has_thr_mem,     d.thr_mem_c,     thr.gpu_temp_mem_warning_c);  int v = static_cast<int>(d.temp_mem_c + 0.5);     dev_sev = std::max(dev_sev, compute_severity(v, c, w)); rr << (first ? "  " : "") << "M:" << v << "°C"; }
    std::string label = (s.vram.devices.size() > 1)
                            ? (std::string("GPU") + std::to_string(i) + " TEMP")
                            : std::string("GPU TEMP");
    out.push_back(Row::kv(std::move(label), rr.str(), dev_sev));
  }
  if (s.thermal.has_fan) {
    std::ostringstream rr; rr << static_cast<int>(s.thermal.fan_rpm + 0.5) << " RPM";
    out.push_back(Row::kv("CPU FAN", rr.str()));
  } else {
    out.push_back(Row::kv("CPU FAN", "UNDETECTED"));
  }
  for (size_t i = 0; i < s.vram.devices.size(); ++i) {
    const auto& d = s.vram.devices[i];
    std::string label = (s.vram.devices.size() > 1)
                            ? (std::string("GPU") + std::to_string(i) + " FAN")
                            : std::string("GPU FAN");
    if (d.has_fan) {
      std::ostringstream rr; rr << static_cast<int>(d.fan_speed_pct + 0.5) << "%";
      out.push_back(Row::kv(std::move(label), rr.str()));
    } else {
      out.push_back(Row::kv(std::move(label), "UNDETECTED"));
    }
  }
  // Margins
  int cpu_delta = 0, gpu_delta = 0; bool have_gpu = false;
  if (s.thermal.has_temp) {
    int warn = s.thermal.has_warn ? static_cast<int>(s.thermal.warn_c + 0.5) : thr.cpu_temp_warning_c;
    int val = static_cast<int>(s.thermal.cpu_max_c + 0.5);
    cpu_delta = std::max(0, warn - val);
  }
  for (const auto& d : s.vram.devices) {
    int best = INT_MAX; bool any = false;
    if (d.has_temp_edge)    { int w = d.has_thr_edge    ? static_cast<int>(d.thr_edge_c    + 0.5) : thr.gpu_temp_warning_c; int v = static_cast<int>(d.temp_edge_c    + 0.5); best = std::min(best, std::max(0, w - v)); any = true; }
    if (d.has_temp_hotspot) { int w = d.has_thr_hotspot ? static_cast<int>(d.thr_hotspot_c + 0.5) : thr.gpu_temp_warning_c; int v = static_cast<int>(d.temp_hotspot_c + 0.5); best = std::min(best, std::max(0, w - v)); any = true; }
    if (d.has_temp_mem)     { int w = d.has_thr_mem     ? static_cast<int>(d.thr_mem_c     + 0.5) : thr.gpu_temp_warning_c; int v = static_cast<int>(d.temp_mem_c     + 0.5); best = std::min(best, std::max(0, w - v)); any = true; }
    if (any) { if (!have_gpu) { gpu_delta = best; have_gpu = true; } else gpu_delta = std::min(gpu_delta, best); }
  }
  std::ostringstream rr;
  rr << "CPU \xCE\x94" << cpu_delta << "°C";
  if (have_gpu) rr << "  GPU \xCE\x94" << gpu_delta << "°C";
  out.push_back(Row::kv("MARGIN TEMPS", rr.str()));
  out.push_back(Row::empty());
}

void section_security(std::vector<Row>& out, const Snapshot& s, int budget) {
  // Mutually exclusive: PROC CHURN takes precedence over PROC SECURITY when
  // the system is actively spawning processes.
  if (s.churn.recent_2s_events > 0) {
    std::vector<const montauk::model::ProcSample*> churned;
    for (const auto& p : s.procs.processes) {
      if (p.churn_reason == montauk::model::ChurnReason::None) continue;
      churned.push_back(&p);
    }
    out.push_back(Row::header("PROC CHURN"));
    std::ostringstream rr;
    rr << s.churn.recent_2s_events << " events [LAST 2s]";
    out.push_back(Row::kv("EVENTS", rr.str(), 1));
    int max_show = std::min<int>(static_cast<int>(churned.size()),
                                 std::max(0, budget - static_cast<int>(out.size())));
    for (int i = 0; i < max_show; ++i) {
      std::ostringstream lbl; lbl << "PID:" << churned[i]->pid;
      out.push_back(Row::kv(lbl.str(), churned[i]->cmd));
    }
    return;
  }

  out.push_back(Row::header("PROC SECURITY"));
  std::vector<montauk::app::SecurityFinding> findings = montauk::app::collect_security_findings(s);
  if (findings.empty()) {
    out.push_back(Row::kv("STATUS", "OK"));
    return;
  }
  int max_rows = std::min(static_cast<int>(findings.size()),
                          std::max(0, budget - static_cast<int>(out.size())));
  for (int i = 0; i < max_rows; ++i) {
    const auto& f = findings[i];
    out.push_back(Row::header(montauk::app::format_security_line_default(f), f.severity));
  }
}

} // namespace

void SystemPanel::render(widget::Canvas& canvas,
                         const widget::LayoutRect& rect,
                         const Snapshot& s) {
  std::vector<Row> rows;
  rows.reserve(64);
  section_identity(rows, s);
  section_runtime (rows, s);
  section_cpu     (rows, s);
  section_gpu     (rows, s);
  section_memory  (rows, s);
  section_disk    (rows, s);
  section_network (rows, s);
  section_thermal (rows, s, show_thermal_);

  // Reserve rows for the security section's dynamic detail lines so they
  // don't overflow the panel.
  const int border_rows = 2;
  const int budget = std::max(1, rect.height - border_rows);
  section_security(rows, s, budget);

  // Pad to fill the column.
  while (static_cast<int>(rows.size()) < budget) rows.push_back(Row::empty());

  widget::Panel panel("SYSTEM", std::move(rows));
  panel.render(canvas, rect, s);
}

} // namespace montauk::ui::widgets
