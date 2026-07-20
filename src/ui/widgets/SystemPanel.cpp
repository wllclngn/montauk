#include "ui/widgets/SystemPanel.hpp"
#include "ui/Config.hpp"
#include "ui/Formatting.hpp"
#include "ui/Terminal.hpp"   // grey_bullet(), sgr_reset()
#include "ui/widget/Panel.hpp"
#include "app/Security.hpp"
#include "util/Churn.hpp"
#include "util/AsciiLower.hpp"

#include <algorithm>
#include <cctype>
#include <climits>
#include <iomanip>
#include <sstream>
#include <string_view>
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

// Snapshot::alerts is populated every frame by AlertEngine::evaluate
// (src/app/Alerts.cpp) but had no UI consumer before this -- generated and
// never rendered. Rather than a separate alert list, its severity colors
// the existing CPU/memory rows it already describes, the same
// normal/caution/warning (0/1/2) convention compute_severity() and every
// thermal/security row already use. Matched by message substring since
// Alerts.cpp's exact wording is this file's only handle on "which alert" --
// both files are montauk's own source, so the coupling stays in-tree.
int alert_severity_for(const Snapshot& s, std::string_view needle) {
  int sev = 0;
  for (const auto& a : s.alerts) {
    if (a.message.find(needle) == std::string::npos) continue;
    int this_sev = a.severity == "crit" ? 2 : (a.severity == "warn" ? 1 : 0);
    sev = std::max(sev, this_sev);
  }
  return sev;
}

// /proc/diskstats lists whole disks and their partitions as separate
// entries (sda, sda1, sda2, ...; nvme0n1, nvme0n1p1, ...), so an unfiltered
// busiest-N ranking shows a disk and its own partition as two rows --
// confirmed live via a PTY capture, not theoretical: an idle box's top-2
// came back as "sda" and "sda1", the same physical device twice. Strip a
// trailing digit run (and one 'p' before it, the nvme/mmc convention); if
// what's left names another device already in the same snapshot, this
// entry is a partition of it and gets skipped in the ranking.
bool is_partition_of_listed_device(const std::string& name,
                                   const std::vector<montauk::model::DiskDev>& all) {
  size_t end = name.size();
  while (end > 0 && std::isdigit(static_cast<unsigned char>(name[end - 1]))) --end;
  if (end == name.size()) return false; // no trailing digit run -> not partition-shaped
  size_t base_end = end;
  if (base_end > 0 && name[base_end - 1] == 'p') --base_end; // nvme0n1p1 -> nvme0n1
  std::string base = name.substr(0, base_end);
  if (base.empty() || base == name) return false;
  for (const auto& d : all) if (d.name == base) return true;
  return false;
}

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

  // CORE: montauk's search / sort / match core. sublimation is the only one —
  // linked unconditionally, no runtime choice.
  out.push_back(Row::kv("CORE", std::string("sublimation")));

  // Total is the headline; the enrichment count only means something when it
  // trails total (some rows lack cmdline/GPU detail), so it appears only then.
  std::ostringstream procs;
  procs << s.procs.total_processes;
  if (s.procs.enriched_count < s.procs.total_processes)
    procs << "  ENRICHED:" << s.procs.enriched_count;
  out.push_back(Row::kv("PROCESSES", procs.str()));

  // R/S/Z is meaningful only when the collector fills it; the kernel-module
  // backend reports all-zero, which would read as "nothing running" against a
  // live process count. Show the row only when at least one state is populated.
  if (s.procs.state_running || s.procs.state_sleeping || s.procs.state_zombie) {
    std::ostringstream states;
    states << "R:" << std::setw(3) << s.procs.state_running
           << " " << grey_bullet() << " S:" << std::setw(3) << s.procs.state_sleeping
           << " " << grey_bullet() << " Z:" << std::setw(3) << s.procs.state_zombie;
    out.push_back(Row::kv("STATES", states.str()));
  }
  out.push_back(Row::empty());
}

void section_cpu(std::vector<Row>& out, const Snapshot& s) {
  if (!s.cpu.model.empty()) out.push_back(Row::kv("CPU", s.cpu.model));

  double topc = 0.0;
  for (double v : s.cpu.per_core_pct) if (v > topc) topc = v;
  {
    // COUNT dropped: the per-core TOPOLOGY grid already shows thread count at
    // a glance, so it was a third redundant number on this row. TOP leads and
    // both percents are width-3 padded: the row is right-aligned to the panel
    // edge, so an unpadded TOP (the volatile one, 5% -> 100%) shifted the
    // whole line every frame. Fixed width, no rubberbanding.
    std::ostringstream rr;
    rr << "TOP:" << std::setw(3) << static_cast<int>(topc + 0.5)
       << "% " << grey_bullet() << " AVG:" << std::setw(3) << static_cast<int>(s.cpu.usage_pct + 0.5) << "%";
    out.push_back(Row::kv("THREADS", rr.str()));
  }

  auto fi = read_cpu_freq_info();
  {
    std::ostringstream rr; rr.setf(std::ios::fixed);
    rr << "CUR: ";
    if (fi.has_cur) rr << std::setprecision(1) << fi.cur_ghz; else rr << "N/A";
    rr << " " << grey_bullet() << " MAX: ";
    if (fi.has_max) rr << std::setprecision(1) << fi.max_ghz << " GHz"; else rr << "N/A GHz";
    if (!fi.governor.empty()) rr << " " << grey_bullet() << " GOV: " << fi.governor;
    if (!fi.turbo.empty())    rr << " " << grey_bullet() << " TURBO: " << fi.turbo;
    out.push_back(Row::kv("FREQ", rr.str()));
  }
  {
    auto pcti = [](double v){ int x = static_cast<int>(v + 0.5); return x < 0 ? 0 : x; };
    std::ostringstream rr;
    rr << "USR:" << std::setw(2) << pcti(s.cpu.pct_user) << "% " << grey_bullet()
       << " SYS:" << std::setw(2) << pcti(s.cpu.pct_system) << "% " << grey_bullet()
       << " IOWAIT:" << std::setw(2) << pcti(s.cpu.pct_iowait) << "% " << grey_bullet()
       << " IRQ:" << std::setw(2) << pcti(s.cpu.pct_irq) << "% " << grey_bullet()
       << " STEAL:" << std::setw(2) << pcti(s.cpu.pct_steal) << "%";
    int sev = alert_severity_for(s, "CPU total sustained high");
    out.push_back(Row::kv("UTIL", rr.str(), sev));
  }
  {
    double a1 = 0, a5 = 0, a15 = 0;
    read_loadavg(a1, a5, a15);
    std::ostringstream rr; rr.setf(std::ios::fixed);
    rr << std::setprecision(2) << a1 << " " << grey_bullet() << " "
       << a5 << " " << grey_bullet() << " " << a15;
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
    rr << std::setw(8) << (fmt_rate(s.cpu.ctxt_per_sec) + "/s") << " " << grey_bullet()
       << " " << std::setw(8) << (fmt_rate(s.cpu.intr_per_sec) + "/s");
    out.push_back(Row::kv("CTXT/INTR", rr.str()));
  }
  out.push_back(Row::empty());
}

// PMU: IPC, L2/L3 cache-miss rates and the hottest core's L2 misses -- all
// already computed by PmuCollector (montauk::model::PmuSnapshot), just never
// rendered anywhere in the TUI before this (only reachable via --json /
// --metrics). Absent entirely when the collector never opened (permission
// denied without CAP_PERFMON / perf_event_paranoid > 0).
void section_pmu(std::vector<Row>& out, const Snapshot& s) {
  if (!s.pmu.available) return;
  out.push_back(Row::header("PMU"));
  {
    std::ostringstream rr; rr << std::fixed << std::setprecision(2) << s.pmu.ipc;
    out.push_back(Row::kv("IPC", rr.str()));
  }
  {
    std::ostringstream rr; rr << std::fixed << std::setprecision(1) << s.pmu.l2_miss_pct << "%";
    out.push_back(Row::kv("L2 MISS", rr.str()));
  }
  if (s.pmu.l3_available && !s.pmu.l3_per_cache_domain.empty()) {
    bool multi = s.pmu.l3_per_cache_domain.size() > 1;
    for (const auto& dom : s.pmu.l3_per_cache_domain) {
      std::string label = multi ? (std::string("L3 MISS D") + std::to_string(dom.domain_cpu))
                                 : std::string("L3 MISS");
      std::ostringstream rr; rr << std::fixed << std::setprecision(1) << dom.miss_pct << "%";
      out.push_back(Row::kv(std::move(label), rr.str()));
    }
  }
  if (!s.pmu.per_cpu_ids.empty() && s.pmu.per_cpu_ids.size() == s.pmu.per_cpu_l2_misses.size()) {
    size_t hot = 0;
    for (size_t i = 1; i < s.pmu.per_cpu_l2_misses.size(); ++i)
      if (s.pmu.per_cpu_l2_misses[i] > s.pmu.per_cpu_l2_misses[hot]) hot = i;
    std::ostringstream rr;
    rr << "cpu" << s.pmu.per_cpu_ids[hot] << ": " << s.pmu.per_cpu_l2_misses[hot] << " misses";
    out.push_back(Row::kv("HOT CORE", rr.str()));
  }
  out.push_back(Row::empty());
}

void section_gpu(std::vector<Row>& out, const Snapshot& s) {
  if (!s.vram.name.empty()) out.push_back(Row::kv("GPU", s.vram.name));

  if (s.vram.has_util || s.vram.total_mb > 0) {
    // G (compute) / MEM (controller) / VRAM (fill), then ENC/DEC only when a
    // codec is actually running -- both idle at zero was pure noise.
    std::ostringstream rr;
    bool first = true;
    auto sep = [&]{ if (!first) rr << " " << grey_bullet() << " "; first = false; };
    if (s.vram.has_util)     { sep(); rr << "G:" << std::setw(2) << static_cast<int>(s.vram.gpu_util_pct + 0.5) << "%"; }
    if (s.vram.has_util)     { sep(); rr << "MEM:" << std::setw(2) << static_cast<int>(s.vram.mem_util_pct + 0.5) << "%"; }
    if (s.vram.total_mb > 0) { sep(); rr << "VRAM:" << std::fixed << std::setprecision(1) << std::setw(4) << s.vram.used_pct << "%"; }
    if (s.vram.has_util && s.vram.has_encdec &&
        (s.vram.enc_util_pct > 0.0 || s.vram.dec_util_pct > 0.0)) {
      sep(); rr << "ENC:" << static_cast<int>(s.vram.enc_util_pct + 0.5)
                << "% " << grey_bullet() << " DEC:" << static_cast<int>(s.vram.dec_util_pct + 0.5) << "%";
    }
    out.push_back(Row::kv("UTIL", rr.str()));
  }

  // NVML: device topology only -- devices, running processes, MIG. The
  // sampler internals (per-PID mode, sample count, sample age) were a debug
  // dump on a user panel and are dropped.
  if (s.nvml.available) {
    std::ostringstream rr;
    rr << "DEV:" << s.nvml.devices
       << " " << grey_bullet() << " RUN:" << std::setw(2) << s.nvml.running_pids
       << " " << grey_bullet() << " MIG:" << (s.nvml.mig_enabled ? "on" : "off");
    out.push_back(Row::kv("NVML", rr.str()));
  }

  // GPU power/temp move to the POWER / THERMAL section; PLIMIT (which only
  // restated power/limit) is dropped. PSTATE stays here as a GPU-state fact.
  if (s.vram.has_pstate) {
    std::ostringstream rr; rr << "P" << std::max(0, s.vram.pstate);
    out.push_back(Row::kv("PSTATE", rr.str()));
  }
  out.push_back(Row::empty());
}

void section_memory(std::vector<Row>& out, const Snapshot& s) {
  const auto& uic = ui_config();
  // Labeled, no slash: percent leads, then USED and AVAIL each wear their own
  // name. AVAIL is the kernel's MemAvailable (reclaimable-cache-aware), NOT
  // total - used, so it is a genuine second number, not the same fact again.
  const double mem_used_gb  = s.mem.used_kb / 1048576.0;
  {
    std::ostringstream rr;
    rr << std::fixed << std::setprecision(0) << s.mem.used_pct << "% " << grey_bullet() << " "
       << uic.normal << "USED: " << std::setprecision(2) << mem_used_gb << "GB" << sgr_reset();
    if (s.mem.available_kb > 0)
      rr << " " << grey_bullet() << " AVAIL: " << (s.mem.available_kb / 1048576.0) << "GB";
    int sev = alert_severity_for(s, "Memory usage sustained high");
    out.push_back(Row::kv("MEM", rr.str(), sev));
  }
  {
    // Two parallel figures, so labeled halves, not a slash: cache AND buffers.
    std::ostringstream rr;
    rr << "CACHE: " << std::fixed << std::setprecision(1) << (s.mem.cached_kb / 1048576.0) << "GB "
       << grey_bullet() << " BUF: " << (s.mem.buffers_kb / 1048576.0) << "GB";
    out.push_back(Row::kv("CACHE/BUF", rr.str()));
  }
  if (s.mem.swap_total_kb > 0) {
    const double swap_used_gb = s.mem.swap_used_kb / 1048576.0;
    const double swap_free_gb = (s.mem.swap_total_kb - s.mem.swap_used_kb) / 1048576.0;
    const double swap_pct = 100.0 * static_cast<double>(s.mem.swap_used_kb)
                                   / static_cast<double>(s.mem.swap_total_kb);
    std::ostringstream rr;
    rr << std::fixed << std::setprecision(0) << swap_pct << "% " << grey_bullet() << " "
       << uic.normal << "USED: " << std::setprecision(2) << swap_used_gb << "GB" << sgr_reset()
       << " " << grey_bullet() << " FREE: " << swap_free_gb << "GB";
    out.push_back(Row::kv("SWAP", rr.str()));
  }
  out.push_back(Row::empty());
}

// DISK I/O: physical devices only, busy% and throughput. Filesystem fullness
// moved to its own section (section_filesystems) so a 69%-full mount and a
// 0%-busy disk never sit in one list under one meaning again, and no device
// appears twice (as a disk and as its partitions).
void section_disk(std::vector<Row>& out, const Snapshot& s) {
  if (s.disk.devices.empty()) return;
  const auto& uic = ui_config();
  out.push_back(Row::header("DISK I/O"));
  // Labeled R:/W:, and every number width-padded: the value is right-aligned
  // to the panel edge, so an unpadded rate shifts the whole line each frame.
  {
    std::ostringstream os;
    os << "R: " << static_cast<int>(s.disk.total_read_bps / 1000000)
       << " " << grey_bullet() << " W: "
       << static_cast<int>(s.disk.total_write_bps / 1000000) << " MB/s";
    out.push_back(Row::kv("TOTAL", os.str()));
  }
  std::vector<const montauk::model::DiskDev*> devs;
  for (const auto& d : s.disk.devices) {
    if (is_partition_of_listed_device(d.name, s.disk.devices)) continue;
    devs.push_back(&d);
  }
  // Top two by util_pct: a two-slot selection scan (strict >, first-encountered
  // wins ties) instead of sorting the vector.
  const montauk::model::DiskDev* top[2] = {nullptr, nullptr};
  for (const auto* d : devs) {
    if (!top[0] || d->util_pct > top[0]->util_pct) { top[1] = top[0]; top[0] = d; }
    else if (!top[1] || d->util_pct > top[1]->util_pct) { top[1] = d; }
  }
  size_t dlim = std::min<size_t>(devs.size(), 2);
  for (size_t i = 0; i < dlim; ++i) {
    const auto& d = *top[i];
    std::ostringstream rr;
    rr << static_cast<int>(d.util_pct + 0.5) << "% " << grey_bullet() << " "
       << uic.normal << "R: " << static_cast<int>(d.read_bps / 1000000)
       << " " << grey_bullet() << " W: "
       << static_cast<int>(d.write_bps / 1000000) << " MB/s" << sgr_reset();
    out.push_back(Row::kv(d.name, rr.str()));
  }
  out.push_back(Row::empty());
}

// FILESYSTEMS: mount-point fullness. Keyed on the mount point (/, /boot), the
// answer a user actually wants, not the /dev/... device node.
void section_filesystems(std::vector<Row>& out, const Snapshot& s) {
  if (s.fs.mounts.empty()) return;
  const auto& uic = ui_config();
  out.push_back(Row::header("FILESYSTEMS"));
  size_t lim = std::min<size_t>(s.fs.mounts.size(), 3);
  for (size_t i = 0; i < lim; ++i) {
    const auto& m = s.fs.mounts[i];
    // Labeled USED:/AVAIL: (avail = total - used, the room-left figure a user
    // actually wants), each size width-padded so the row holds still frame to
    // frame. format_size widths vary (156.8G vs 19K), so setw right-justifies.
    uint64_t avail = m.total_bytes > m.used_bytes ? m.total_bytes - m.used_bytes : 0;
    std::ostringstream right;
    right << static_cast<int>(m.used_pct + 0.5) << "% " << grey_bullet() << " "
          << uic.normal << "USED: " << format_size(m.used_bytes, 1, true)
          << " " << grey_bullet() << " AVAIL: " << format_size(avail, 1, true)
          << sgr_reset();
    std::string left = !m.mountpoint.empty() ? m.mountpoint
                     : !m.device.empty()     ? m.device
                                             : m.fstype;
    out.push_back(Row::kv(std::move(left), right.str()));
  }
  out.push_back(Row::empty());
}

void section_network(std::vector<Row>& out, const Snapshot& s) {
  out.push_back(Row::header("NETWORK"));
  auto rate_row = [](double rx_bps, double tx_bps) {
    std::ostringstream rr;
    rr << "\xE2\x86\x93" << static_cast<int>(rx_bps / 1024)
       << "KB/s " << grey_bullet() << " \xE2\x86\x91" << static_cast<int>(tx_bps / 1024) << "KB/s";
    return rr.str();
  };
  // The DOWN/UP aggregate only adds information when the per-interface list is
  // truncated (more interfaces than we render); with every interface shown, it
  // just repeats their sum, so it appears only past the render cap.
  const size_t cap = 3;
  if (s.net.interfaces.size() > cap)
    out.push_back(Row::kv("DOWN/UP", rate_row(s.net.agg_rx_bps, s.net.agg_tx_bps)));
  size_t lim = std::min<size_t>(s.net.interfaces.size(), cap);
  for (size_t i = 0; i < lim; ++i) {
    const auto& n = s.net.interfaces[i];
    out.push_back(Row::kv(n.name, rate_row(n.rx_bps, n.tx_bps)));
  }
  out.push_back(Row::empty());
}

// POWER / THERMAL: CPU and GPU power, temperature and energy in one place
// (GPU power used to live in the GPU block, splitting the story). Each temp
// carries its throttle margin inline as (Δ N° margin) instead of a separate
// MARGIN TEMPS row that restated both temps, and the two fan rows collapse
// to one FANS row. The header appears only if any of it is present.
void section_power_thermal(std::vector<Row>& out, const Snapshot& s, bool show_thermal) {
  if (!show_thermal) return;
  const auto& thr = config().thresholds;

  bool started = false;
  auto header = [&] { if (!started) { out.push_back(Row::header("POWER / THERMAL")); started = true; } };

  // CPU temperature with inline throttle margin.
  if (s.thermal.has_temp) {
    header();
    int warn = s.thermal.has_warn ? static_cast<int>(s.thermal.warn_c + 0.5) : thr.cpu_temp_warning_c;
    int caution = thr.cpu_temp_caution_c > 0
                      ? thr.cpu_temp_caution_c
                      : std::max(0, warn - thr.temp_caution_delta_c);
    int val = static_cast<int>(s.thermal.cpu_max_c + 0.5);
    std::ostringstream rr;
    rr << std::setw(3) << val << "°C " << grey_bullet() << " MARGIN: \xCE\x94" << std::setw(2) << std::max(0, warn - val) << "°C";
    out.push_back(Row::kv("CPU TEMP", rr.str(), compute_severity(val, caution, warn)));
  }

  // GPU temperature: the hottest available sensor (edge/hotspot/mem) with its
  // margin. The per-sensor breakdown was three cryptic prefixes; the summary
  // a user reads is "how hot, how much headroom".
  for (size_t i = 0; i < s.vram.devices.size(); ++i) {
    const auto& d = s.vram.devices[i];
    int hottest = INT_MIN, warn_at = thr.gpu_temp_warning_c;
    auto consider = [&](bool has, double temp_c, bool has_thr, double thr_c, int cfg_warn) {
      if (!has) return;
      int v = static_cast<int>(temp_c + 0.5);
      if (v > hottest) { hottest = v; warn_at = has_thr ? static_cast<int>(thr_c + 0.5)
                                            : (cfg_warn > 0 ? cfg_warn : thr.gpu_temp_warning_c); }
    };
    consider(d.has_temp_edge,    d.temp_edge_c,    d.has_thr_edge,    d.thr_edge_c,    thr.gpu_temp_edge_warning_c);
    consider(d.has_temp_hotspot, d.temp_hotspot_c, d.has_thr_hotspot, d.thr_hotspot_c, thr.gpu_temp_hot_warning_c);
    consider(d.has_temp_mem,     d.temp_mem_c,     d.has_thr_mem,     d.thr_mem_c,     thr.gpu_temp_mem_warning_c);
    if (hottest == INT_MIN) continue;
    header();
    int caution = thr.gpu_temp_caution_c > 0 ? thr.gpu_temp_caution_c
                                             : std::max(0, warn_at - thr.temp_caution_delta_c);
    std::string label = (s.vram.devices.size() > 1)
                            ? (std::string("GPU") + std::to_string(i) + " TEMP")
                            : std::string("GPU TEMP");
    std::ostringstream rr;
    rr << std::setw(3) << hottest << "°C " << grey_bullet() << " MARGIN: \xCE\x94" << std::setw(2) << std::max(0, warn_at - hottest) << "°C";
    out.push_back(Row::kv(std::move(label), rr.str(), compute_severity(hottest, caution, warn_at)));
  }

  if (s.thermal.has_power) {
    header();
    std::ostringstream rr; rr << std::setw(3) << static_cast<int>(s.thermal.power_watts + 0.5) << "W";
    out.push_back(Row::kv("CPU POWER", rr.str()));
  }
  if (s.vram.has_power) {
    header();
    std::ostringstream rr; rr << std::setw(3) << static_cast<int>(s.vram.power_draw_w + 0.5) << "W";
    out.push_back(Row::kv("GPU POWER", rr.str()));
  }
  if (s.thermal.has_energy) {
    // Cumulative since the collector started (monotonic, wrap-safe): a session
    // energy total, not a per-interval rate, so no delta math needed.
    header();
    std::ostringstream rr;
    rr << std::fixed << std::setprecision(1) << std::setw(6) << (s.thermal.energy_joules_total / 1000.0) << "kJ";
    out.push_back(Row::kv("CPU ENERGY", rr.str()));
  }
  if (!s.thermal.cstates.empty()) {
    header();
    std::ostringstream rr;
    for (size_t i = 0; i < s.thermal.cstates.size(); ++i) {
      if (i) rr << " " << grey_bullet() << " ";
      rr << s.thermal.cstates[i].name << ":" << std::setw(3)
         << static_cast<int>(s.thermal.cstates[i].residency_pct + 0.5) << "%";
    }
    out.push_back(Row::kv("C-STATES", rr.str()));
  }

  // One FANS row instead of a CPU FAN row plus a GPU FAN row per device.
  {
    std::ostringstream rr;
    rr << "CPU:";
    if (s.thermal.has_fan) rr << std::setw(4) << static_cast<int>(s.thermal.fan_rpm + 0.5) << "rpm"; else rr << "n/a";
    for (size_t i = 0; i < s.vram.devices.size(); ++i) {
      const auto& d = s.vram.devices[i];
      rr << " " << grey_bullet() << " " << ((s.vram.devices.size() > 1) ? ("GPU" + std::to_string(i)) : std::string("GPU")) << ":";
      if (d.has_fan) rr << std::setw(3) << static_cast<int>(d.fan_speed_pct + 0.5) << "%"; else rr << "n/a";
    }
    if (started) out.push_back(Row::kv("FANS", rr.str()));
  }
  if (started) out.push_back(Row::empty());
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
  section_identity    (rows, s);
  section_runtime     (rows, s);
  section_cpu         (rows, s);
  section_pmu         (rows, s);
  section_gpu         (rows, s);
  section_memory      (rows, s);
  section_disk        (rows, s);
  section_filesystems (rows, s);
  section_network     (rows, s);
  section_power_thermal(rows, s, show_thermal_);

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
