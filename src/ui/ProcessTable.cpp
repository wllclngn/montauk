#include "ui/ProcessTable.hpp"
#include "ui/Config.hpp"
#include "ui/Terminal.hpp"
#include "ui/Formatting.hpp"
#include "ui/Renderer.hpp"
#include "util/AdaptiveSort.hpp"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cmath>
#include <numeric>

namespace montauk::ui {

// Helper to format CPU percentage field with color coding
static std::string fmt_cpu_field(double cpu_pct, bool colorize=true) {
  std::string digits;
  int display_val;
  
  // For values < 1%, show decimal precision (0.1%, 0.2%, etc.)
  if (cpu_pct > 0.0 && cpu_pct < 1.0) {
    double rounded = std::round(cpu_pct * 10.0) / 10.0;
    if (rounded < 0.1) rounded = 0.1; // minimum 0.1%
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(1) << rounded;
    digits = oss.str();
    display_val = 0; // for color thresholding
  } else {
    display_val = (int)(cpu_pct + 0.5);
    digits = std::to_string(display_val);
  }
  
  // Build the value string with %
  std::string value_str = digits + "%";
  int pad = 4 - (int)value_str.size(); if (pad < 0) pad = 0;
  
  const auto& ui = ui_config();
  const std::string* col = nullptr;
  if (colorize) {
    if (display_val >= ui.warning_pct) col = &ui.warning;
    else if (display_val >= ui.caution_pct) col = &ui.caution;
  }
  
  std::string out;
  out.reserve(4 + 3 + 16);
  out.append(pad, ' ');
  if (col) out += *col;
  out += digits;
  if (col) out += sgr_reset();
  out += "%  ";
  return out;
}

std::vector<std::string> render_process_table(
    const montauk::model::Snapshot& s, 
    int width, 
    int target_rows
) {
  std::vector<std::string> all;
  int iw = std::max(3, width - 2);
  auto ncpu = (int)std::max<size_t>(1, s.cpu.per_core_pct.size());
  auto scale_proc_cpu = [&](double raw)->double{
    return (g_ui.cpu_scale==UIState::CPUScale::Total) ? (raw / (double)ncpu) : raw;
  };
  // Helper for human-readable KB formatting
  auto human_kib = [](uint64_t kib){ 
    if (kib >= (1024ull*1024ull)) { 
      double g=kib/(1024.0*1024.0); 
      return std::to_string((int)(g+0.5))+"G"; 
    } 
    if (kib>=1024ull){ 
      double m=kib/1024.0; 
      return std::to_string((int)(m+0.5))+"M";
    } 
    return std::to_string((int)kib)+"K"; 
  };
  // CPU and Memory panels moved to right column.

  // Processes
  std::vector<std::string> proc_lines; proc_lines.reserve(64);
  std::vector<int> proc_sev; proc_sev.reserve(64); // 0=none,1=caution,2=warning
  // Prepare order and sorting for process list
  std::vector<size_t> order(s.procs.processes.size());
  std::iota(order.begin(), order.end(), 0);
  std::vector<double> sm(order.size(), 0.0);
  for (size_t i = 0; i < order.size(); ++i) {
    const auto& p = s.procs.processes[i];
    sm[i] = montauk::ui::smooth_value(std::string("proc.cpu.") + std::to_string(p.pid), scale_proc_cpu(p.cpu_pct), 0.35);
  }
  montauk::util::adaptive_timsort(order.begin(), order.end(), [&](size_t a, size_t b){
    const auto& A = s.procs.processes[a];
    const auto& B = s.procs.processes[b];
    switch (g_ui.sort) {
      case SortMode::CPU:
        if (sm[a] != sm[b]) return sm[a] > sm[b];
        break;
      case SortMode::MEM:
        if (A.rss_kb != B.rss_kb) return A.rss_kb > B.rss_kb;
        break;
      case SortMode::PID:
        if (A.pid != B.pid) return A.pid < B.pid;
        break;
      case SortMode::NAME:
        if (A.cmd != B.cmd) return A.cmd < B.cmd;
        break;
      case SortMode::GPU:
        if (A.gpu_util_pct != B.gpu_util_pct) return A.gpu_util_pct > B.gpu_util_pct;
        break;
      case SortMode::GMEM:
        if (A.gpu_mem_kb != B.gpu_mem_kb) return A.gpu_mem_kb > B.gpu_mem_kb;
        break;
    }
    // tiebreaker: higher CPU, then higher MEM, then lower PID
    if (sm[a] != sm[b]) return sm[a] > sm[b];
    if (A.rss_kb != B.rss_kb) return A.rss_kb > B.rss_kb;
    return A.pid < B.pid;
  });
  // Calculate how many process rows fit in available space
  // This must match the box height calculation later
  int used_fixed = 0;  // Process table is rendered first, so nothing used yet
  int remaining_for_proc = std::max(5, target_rows - used_fixed);
  int proc_inner_min = std::max(14, remaining_for_proc - 2);  // minus borders
  int desired_rows = std::max(1, proc_inner_min - 1);  // minus header row
  g_ui.last_proc_page_rows = desired_rows;
  g_ui.last_proc_total = (int)order.size();

  // Pagination by scroll
  const int skip = g_ui.scroll;
  const int take = desired_rows;
  // Determine displayed rows
  std::vector<const montauk::model::ProcSample*> displayed; displayed.reserve((size_t)take);
  int limit = std::min((int)order.size(), skip + take);
  for (int i = skip; i < limit; ++i) {
    displayed.push_back(&s.procs.processes[order[i]]);
  }
  // Measure ALL processes for all column widths (so columns don't shift when scrolling)
  int pid_w_meas = 5, user_w_meas = 4, gpu_digit_w_meas = 3, mem_w_meas = 4, gmem_w_meas = 4;
  for (size_t ii = 0; ii < order.size(); ++ii) {
    const auto& p = s.procs.processes[order[ii]];
    int pid_digits = (int)std::to_string(p.pid).size();
    if (pid_digits > pid_w_meas) pid_w_meas = pid_digits;
    int user_vis = (int)p.user_name.size();
    if (user_vis > user_w_meas) user_w_meas = user_vis;
    if (p.has_gpu_util) {
      int gdig = (int)std::to_string((int)(p.gpu_util_pct + 0.5)).size();
      if (gdig > gpu_digit_w_meas) gpu_digit_w_meas = gdig;
    }
    std::string hm = human_kib(p.rss_kb);
    if ((int)hm.size() > mem_w_meas) mem_w_meas = (int)hm.size();
    std::string hg = human_kib(p.gpu_mem_kb);
    if ((int)hg.size() > gmem_w_meas) gmem_w_meas = (int)hg.size();
  }
  // Clamp
  pid_w_meas = std::min(8, std::max(5, pid_w_meas));
  user_w_meas = std::min(12, std::max(4, user_w_meas));
  gpu_digit_w_meas = std::min(4, std::max(3, gpu_digit_w_meas));
  mem_w_meas = std::min(6, std::max(4, mem_w_meas));
  gmem_w_meas = std::min(6, std::max(4, gmem_w_meas));
  
  // Sticky columns: expand immediately when needed, never shrink
  g_ui.col_pid_w = std::max(g_ui.col_pid_w, pid_w_meas);
  g_ui.col_user_w = std::max(g_ui.col_user_w, user_w_meas);
  g_ui.col_gpu_digit_w = std::max(g_ui.col_gpu_digit_w, gpu_digit_w_meas);
  g_ui.col_mem_w = std::max(g_ui.col_mem_w, mem_w_meas);
  g_ui.col_gmem_w = std::max(g_ui.col_gmem_w, gmem_w_meas);
  
  int pidw = g_ui.col_pid_w;
  int userw = g_ui.col_user_w;
  int gpud = g_ui.col_gpu_digit_w;
  int memw = g_ui.col_mem_w;
  int gmemw = g_ui.col_gmem_w;
  // Header (align numeric headers to the right of their columns)
  {
    std::ostringstream h;
    h << std::setw(pidw) << "PID" << "  "
      << rpad_trunc("USER", userw) << "  "
      << std::setw(4) << "CPU%" << "  "
      << std::setw(gpud + 1) << "GPU%" << "  ";
    if (g_ui.show_gmem) {
      h << std::setw(gmemw) << "GMEM" << "  ";
    }
    h << std::setw(memw) << "MEM" << "  "
      << "COMMAND";
    proc_lines.push_back(h.str());
  }
  proc_sev.push_back(0);
  // Calculate command column width dynamically
  int fields_w = 6 + (gpud+3);
  if (g_ui.show_gmem) fields_w += (gmemw+2);
  fields_w += (memw+2);
  int cmd_w = iw - (pidw+2 + userw+2 + fields_w);
  if (cmd_w < 8) cmd_w = 8;
  // Process rows
  const auto& ui = ui_config();
  for (auto* p : displayed) {
    double scaled_cpu = scale_proc_cpu(p->cpu_pct);
    double smooth_cpu = montauk::ui::smooth_value(std::string("proc.cpu.") + std::to_string(p->pid), scaled_cpu, 0.35);
    int severity = 0;
    if ((int)(smooth_cpu + 0.5) >= ui.warning_pct) severity = 2;
    else if ((int)(smooth_cpu + 0.5) >= ui.caution_pct) severity = 1;
    
    std::ostringstream os;
    os << std::setw(pidw) << p->pid << "  "
       << rpad_trunc(sanitize_for_display(p->user_name, userw), userw) << "  "
       << fmt_cpu_field(smooth_cpu, severity == 0);
    
    // Format GPU% with right-alignment
    {
      double display_gpu = (g_ui.gpu_scale==UIState::GPUScale::Capacity) ? p->gpu_util_pct : p->gpu_util_pct;
      std::string digits;
      if (display_gpu > 0.0 && display_gpu < 1.0) {
        double rounded = std::round(display_gpu * 10.0) / 10.0;
        if (rounded < 0.1) rounded = 0.1;
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(1) << rounded;
        digits = oss.str();
      } else {
        digits = std::to_string((int)(display_gpu + 0.5));
      }
      int pad = gpud - (int)digits.size();
      if (pad < 0) pad = 0;
      os << std::string(pad, ' ') << digits << "%  ";
    }
    
    // GMEM with right-alignment
    if (g_ui.show_gmem) {
      std::string gmem_str = human_kib(p->gpu_mem_kb);
      int pad = gmemw - (int)gmem_str.size();
      if (pad < 0) pad = 0;
      os << std::string(pad, ' ') << gmem_str << "  ";
    }
    
    // MEM with right-alignment
    {
      std::string mem_str = human_kib(p->rss_kb);
      int pad = memw - (int)mem_str.size();
      if (pad < 0) pad = 0;
      os << std::string(pad, ' ') << mem_str << "  ";
    }
    
    // COMMAND (left-aligned)
    std::string proc_name = p->cmd.empty() ? std::to_string(p->pid) : 
                            sanitize_for_display(p->cmd, cmd_w + 10);
    os << trunc_pad(proc_name, cmd_w);
    proc_lines.push_back(os.str());
    proc_sev.push_back(severity);
  }
  // Box - use the same proc_inner_min calculated above
  std::string title = "PROCESS MONITOR";
  auto proc_box = make_box(title, proc_lines, width, proc_inner_min);
  // Colorize rows based on severity
  {
    const std::string& V = use_unicode() ? "│" : "|";
    const auto& uic = ui_config();
    for (int li = 1; li < (int)proc_box.size() - 1; ++li) {
      if (li - 1 >= (int)proc_sev.size()) break;
      int sev = proc_sev[li-1];
      if (sev <= 0) continue; // skip header and non-severe rows
      auto& line = proc_box[li];
      size_t fpos = line.find(V);
      size_t lpos = line.rfind(V);
      if (fpos == std::string::npos || lpos == std::string::npos || lpos <= fpos) continue;
      size_t start = fpos + V.size();
      std::string pre = line.substr(0, start);
      std::string mid = line.substr(start, lpos - start);
      std::string suf = line.substr(lpos);
      const std::string& col = (sev==2) ? uic.warning : uic.caution;
      line = pre + col + mid + sgr_reset() + suf;
    }
  }
  all.insert(all.end(), proc_box.begin(), proc_box.end());
  return all;
}

} // namespace montauk::ui
