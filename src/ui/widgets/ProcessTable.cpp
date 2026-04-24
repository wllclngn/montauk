#include "ui/widgets/ProcessTable.hpp"
#include "ui/Config.hpp"
#include "ui/Terminal.hpp"
#include "ui/Formatting.hpp"
#include "util/TimSort.hpp"
#include "util/SortDispatch.hpp"
#include "util/ThompsonNFA.hpp"
#include "app/Filter.hpp"

#include <algorithm>
#include <cmath>
#include <iomanip>
#include <numeric>
#include <sstream>
#include <unordered_set>

namespace montauk::ui::widgets {

namespace {

// Colorize a command string using NFA pattern classification.
// Kernel threads [kworker/...] → fully muted.
// Path prefix /usr/bin/ → muted, binary name → default fg, args → muted.
std::string colorize_command(std::string_view cmd, int width, const UIConfig& ui) {
  if (!tty_stdout()) return trunc_pad(std::string(cmd), width);

  static const montauk::util::ThompsonNFA kernel_re("^\\[.+\\]$");

  if (kernel_re.full_match(cmd))
    return trunc_pad(ui.muted + std::string(cmd) + sgr_reset(), width);

  size_t first_space = cmd.find(' ');
  size_t exe_end = (first_space == std::string_view::npos) ? cmd.size() : first_space;
  size_t last_slash = cmd.rfind('/', exe_end);

  std::string colored;
  colored.reserve(cmd.size() + 32);
  if (last_slash != std::string_view::npos) {
    colored += ui.muted;
    colored.append(cmd.data(), last_slash + 1);
    colored += sgr_reset();
    colored += ui.binary;
    colored.append(cmd.data() + last_slash + 1, exe_end - last_slash - 1);
    colored += sgr_reset();
  } else {
    colored += ui.binary;
    colored.append(cmd.data(), exe_end);
    colored += sgr_reset();
  }

  if (first_space != std::string_view::npos) {
    colored += ui.muted;
    colored.append(cmd.data() + first_space, cmd.size() - first_space);
    colored += sgr_reset();
  }

  return trunc_pad(colored, width);
}

std::string fmt_cpu_field(double cpu_pct, bool colorize = true) {
  std::string digits;
  int display_val;

  if (cpu_pct > 0.0 && cpu_pct < 1.0) {
    double rounded = std::round(cpu_pct * 10.0) / 10.0;
    if (rounded < 0.1) rounded = 0.1;
    std::ostringstream oss; oss << std::fixed << std::setprecision(1) << rounded;
    digits = oss.str();
    display_val = 0;
  } else {
    display_val = static_cast<int>(cpu_pct + 0.5);
    digits = std::to_string(display_val);
  }

  std::string value_str = digits + "%";
  int pad = 4 - static_cast<int>(value_str.size()); if (pad < 0) pad = 0;

  const auto& ui = ui_config();
  const std::string* col = nullptr;
  if (colorize) {
    int sev = compute_severity(display_val, ui.caution_pct, ui.warning_pct);
    if      (sev == 2) col = &ui.warning;
    else if (sev == 1) col = &ui.caution;
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

} // namespace

void ProcessTable::render(widget::Canvas& canvas,
                          const widget::LayoutRect& rect,
                          const montauk::model::Snapshot& s) {
  const int width = rect.width;
  const int iw = std::max(3, width - 2);
  const auto& ui = ui_config();

  auto ncpu = static_cast<int>(std::max<size_t>(1, s.cpu.per_core_pct.size()));
  auto scale_proc_cpu = [&](double raw) {
    return (g_ui.cpu_scale == UIState::CPUScale::Total) ? (raw / static_cast<double>(ncpu)) : raw;
  };
  auto human_kib = [](uint64_t kib) { return format_size_kib(kib); };

  // Build sorted/filtered index order
  std::vector<size_t> order(s.procs.processes.size());
  std::iota(order.begin(), order.end(), 0);
  std::vector<double> sm(order.size(), 0.0);
  for (size_t i = 0; i < order.size(); ++i) {
    const auto& p = s.procs.processes[i];
    sm[i] = montauk::ui::smooth_value(std::string("proc.cpu.") + std::to_string(p.pid), scale_proc_cpu(p.cpu_pct), 0.35);
  }

  // Sort dispatch. The sublimation switch path at this precise site is a hard
  // constraint of the refactor — do not touch.
  if (montauk::util::resolve_backend() == montauk::util::SortBackend::Sublimation) {
    const size_t n = order.size();
    std::vector<uint32_t> idx32(n);
    for (size_t i = 0; i < n; ++i) idx32[i] = static_cast<uint32_t>(i);
    switch (g_ui.sort) {
      case SortMode::CPU: {
        std::vector<float> keys(n);
        for (size_t i = 0; i < n; ++i) keys[i] = static_cast<float>(sm[i]);
        montauk::util::sort_by_key_f32(keys, idx32, /*descending=*/true);
        break;
      }
      case SortMode::MEM: {
        std::vector<uint32_t> keys(n);
        for (size_t i = 0; i < n; ++i) keys[i] = static_cast<uint32_t>(s.procs.processes[i].rss_kb);
        montauk::util::sort_by_key_u32(keys, idx32, /*descending=*/true);
        break;
      }
      case SortMode::PID: {
        std::vector<uint32_t> keys(n);
        for (size_t i = 0; i < n; ++i) keys[i] = static_cast<uint32_t>(s.procs.processes[i].pid);
        montauk::util::sort_by_key_u32(keys, idx32, /*descending=*/false);
        break;
      }
      case SortMode::GPU: {
        std::vector<float> keys(n);
        for (size_t i = 0; i < n; ++i) keys[i] = static_cast<float>(s.procs.processes[i].gpu_util_pct);
        montauk::util::sort_by_key_f32(keys, idx32, /*descending=*/true);
        break;
      }
      case SortMode::GMEM: {
        std::vector<uint32_t> keys(n);
        for (size_t i = 0; i < n; ++i) keys[i] = static_cast<uint32_t>(s.procs.processes[i].gpu_mem_kb);
        montauk::util::sort_by_key_u32(keys, idx32, /*descending=*/true);
        break;
      }
      case SortMode::NAME: {
        std::vector<const char*> ptrs(n);
        for (size_t i = 0; i < n; ++i) ptrs[i] = s.procs.processes[i].cmd.c_str();
        montauk::util::sort_by_string(ptrs, idx32);
        break;
      }
    }
    for (size_t i = 0; i < n; ++i) order[i] = static_cast<size_t>(idx32[i]);
  } else {
    montauk::util::timsort(order.begin(), order.end(), [&](size_t a, size_t b) {
      const auto& A = s.procs.processes[a];
      const auto& B = s.procs.processes[b];
      switch (g_ui.sort) {
        case SortMode::CPU:  if (sm[a] != sm[b]) return sm[a] > sm[b]; break;
        case SortMode::MEM:  if (A.rss_kb != B.rss_kb) return A.rss_kb > B.rss_kb; break;
        case SortMode::PID:  if (A.pid != B.pid) return A.pid < B.pid; break;
        case SortMode::NAME: if (A.cmd != B.cmd) return A.cmd < B.cmd; break;
        case SortMode::GPU:  if (A.gpu_util_pct != B.gpu_util_pct) return A.gpu_util_pct > B.gpu_util_pct; break;
        case SortMode::GMEM: if (A.gpu_mem_kb != B.gpu_mem_kb) return A.gpu_mem_kb > B.gpu_mem_kb; break;
      }
      if (sm[a] != sm[b]) return sm[a] > sm[b];
      if (A.rss_kb != B.rss_kb) return A.rss_kb > B.rss_kb;
      return A.pid < B.pid;
    });
  }

  // Search filter
  if (!g_ui.filter_query.empty()) {
    montauk::app::ProcessFilterSpec fspec{};
    fspec.name_contains = g_ui.filter_query;
    montauk::app::ProcessFilter filt(fspec);
    auto matched = filt.apply(s.procs);
    std::unordered_set<size_t> match_set(matched.begin(), matched.end());
    std::erase_if(order, [&](size_t idx) { return !match_set.contains(idx); });
  }

  // Layout math: figure out how many process rows fit
  const int search_rows = g_ui.search_mode ? 2 : 0; // divider was bottom border, plus input + new bottom
  const int proc_inner_min = std::max(14, target_rows_ - 2 - search_rows);
  const int desired_rows = std::max(1, proc_inner_min - 1); // minus header row
  g_ui.last_proc_page_rows = desired_rows;
  g_ui.last_proc_total = static_cast<int>(order.size());
  int max_scroll = std::max(0, static_cast<int>(order.size()) - desired_rows);
  if (g_ui.scroll > max_scroll) g_ui.scroll = max_scroll;

  const int skip = g_ui.scroll;
  const int take = desired_rows;
  std::vector<const montauk::model::ProcSample*> displayed; displayed.reserve(static_cast<size_t>(take));
  int limit = std::min(static_cast<int>(order.size()), skip + take);
  for (int i = skip; i < limit; ++i) displayed.push_back(&s.procs.processes[order[i]]);

  // Measure column widths across ALL sorted processes (sticky)
  int pid_w_meas = 5, user_w_meas = 4, gpu_digit_w_meas = 3, mem_w_meas = 4, gmem_w_meas = 4;
  for (size_t ii = 0; ii < order.size(); ++ii) {
    const auto& p = s.procs.processes[order[ii]];
    int pid_digits = static_cast<int>(std::to_string(p.pid).size());
    if (pid_digits > pid_w_meas) pid_w_meas = pid_digits;
    int user_vis = static_cast<int>(p.user_name.size());
    if (user_vis > user_w_meas) user_w_meas = user_vis;
    if (p.has_gpu_util) {
      int gdig = static_cast<int>(std::to_string(static_cast<int>(p.gpu_util_pct + 0.5)).size());
      if (gdig > gpu_digit_w_meas) gpu_digit_w_meas = gdig;
    }
    std::string hm = human_kib(p.rss_kb);
    if (static_cast<int>(hm.size()) > mem_w_meas) mem_w_meas = static_cast<int>(hm.size());
    std::string hg = human_kib(p.gpu_mem_kb);
    if (static_cast<int>(hg.size()) > gmem_w_meas) gmem_w_meas = static_cast<int>(hg.size());
  }
  pid_w_meas       = std::min(8,  std::max(5, pid_w_meas));
  user_w_meas      = std::min(12, std::max(4, user_w_meas));
  gpu_digit_w_meas = std::min(4,  std::max(3, gpu_digit_w_meas));
  mem_w_meas       = std::min(6,  std::max(4, mem_w_meas));
  gmem_w_meas      = std::min(6,  std::max(4, gmem_w_meas));

  g_ui.col_pid_w       = std::max(g_ui.col_pid_w,       pid_w_meas);
  g_ui.col_user_w      = std::max(g_ui.col_user_w,      user_w_meas);
  g_ui.col_gpu_digit_w = std::max(g_ui.col_gpu_digit_w, gpu_digit_w_meas);
  g_ui.col_mem_w       = std::max(g_ui.col_mem_w,       mem_w_meas);
  g_ui.col_gmem_w      = std::max(g_ui.col_gmem_w,      gmem_w_meas);

  const int pidw  = g_ui.col_pid_w;
  const int userw = g_ui.col_user_w;
  const int gpud  = g_ui.col_gpu_digit_w;
  const int memw  = g_ui.col_mem_w;
  const int gmemw = g_ui.col_gmem_w;

  // Build content lines
  std::vector<std::string> content;
  content.reserve(static_cast<size_t>(proc_inner_min));

  // Header
  {
    std::ostringstream h;
    h << std::setw(pidw) << "PID" << "  "
      << rpad_trunc("USER", userw) << "  "
      << std::setw(4) << "CPU%" << "  "
      << std::setw(gpud + 1) << "GPU%" << "  ";
    if (g_ui.show_gmem) h << std::setw(gmemw) << "GMEM" << "  ";
    h << std::setw(memw) << "MEM" << "  " << "COMMAND";
    content.push_back(tty_stdout() ? (ui.accent + h.str() + sgr_reset()) : h.str());
  }

  // Rows
  int fields_w = 6 + (gpud + 3);
  if (g_ui.show_gmem) fields_w += (gmemw + 2);
  fields_w += (memw + 2);
  int cmd_w = iw - (pidw + 2 + userw + 2 + fields_w);
  if (cmd_w < 8) cmd_w = 8;

  for (auto* p : displayed) {
    double scaled_cpu = scale_proc_cpu(p->cpu_pct);
    double smooth_cpu = montauk::ui::smooth_value(std::string("proc.cpu.") + std::to_string(p->pid), scaled_cpu, 0.35);
    int severity = compute_severity(static_cast<int>(smooth_cpu + 0.5), ui.caution_pct, ui.warning_pct);

    std::ostringstream os;
    os << std::setw(pidw) << p->pid << "  "
       << rpad_trunc(sanitize_for_display(p->user_name, userw), userw) << "  "
       << fmt_cpu_field(smooth_cpu, severity == 0);

    // GPU%
    {
      int ngpu_dev = std::max(1, s.nvml.devices);
      double display_gpu = (g_ui.gpu_scale == UIState::GPUScale::Capacity) ? p->gpu_util_pct / static_cast<double>(ngpu_dev) : p->gpu_util_pct;
      std::string digits;
      if (display_gpu > 0.0 && display_gpu < 1.0) {
        double rounded = std::round(display_gpu * 10.0) / 10.0;
        if (rounded < 0.1) rounded = 0.1;
        std::ostringstream oss; oss << std::fixed << std::setprecision(1) << rounded;
        digits = oss.str();
      } else {
        digits = std::to_string(static_cast<int>(display_gpu + 0.5));
      }
      int pad = gpud - static_cast<int>(digits.size());
      if (pad < 0) pad = 0;
      int gpu_display_val = static_cast<int>(display_gpu + 0.5);
      const std::string* gcol = nullptr;
      if (severity == 0 && tty_stdout()) {
        int gpu_sev = compute_severity(gpu_display_val, ui.caution_pct, ui.warning_pct);
        if      (gpu_sev == 2) gcol = &ui.warning;
        else if (gpu_sev == 1) gcol = &ui.caution;
      }
      os << std::string(pad, ' ');
      if (gcol) os << *gcol;
      os << digits;
      if (gcol) os << sgr_reset();
      os << "%  ";
    }

    if (g_ui.show_gmem) {
      std::string gmem_str = human_kib(p->gpu_mem_kb);
      int pad = gmemw - static_cast<int>(gmem_str.size()); if (pad < 0) pad = 0;
      os << std::string(pad, ' ') << gmem_str << "  ";
    }
    {
      std::string mem_str = human_kib(p->rss_kb);
      int pad = memw - static_cast<int>(mem_str.size()); if (pad < 0) pad = 0;
      os << std::string(pad, ' ') << mem_str << "  ";
    }
    {
      std::string raw = p->cmd.empty() ? std::to_string(p->pid) : sanitize_for_display(p->cmd, cmd_w + 10);
      os << colorize_command(raw, cmd_w, ui);
    }

    content.push_back(severity_colored(os.str(), severity));
  }

  // Pad content to proc_inner_min
  while (static_cast<int>(content.size()) < proc_inner_min) content.push_back(std::string());

  // Draw: the main frame sits at rect.y .. rect.y + proc_inner_min + 1 (top + content + bottom).
  // When search mode is active, two extra rows follow below for the input + new bottom border.
  widget::Style border_style = widget::parse_sgr_style(ui.border);
  const int main_h = proc_inner_min + 2;

  canvas.draw_rect(rect.x, rect.y, rect.width, main_h, border_style);

  // Title centered on the top border row.
  std::string title = "PROCESS MONITOR";
  if (!g_ui.filter_query.empty()) {
    std::string suffix = (order.size() == 1) ? " RESULT" : " RESULTS";
    title = "PROCESS MONITOR: " + std::to_string(order.size()) + suffix;
  }
  std::string title_text = " " + title + " ";
  int title_x = rect.x + (rect.width - static_cast<int>(title_text.size())) / 2;
  if (title_x < rect.x + 2) title_x = rect.x + 2;
  widget::Style title_style = widget::parse_sgr_style(ui.accent);
  canvas.draw_text(title_x, rect.y, title_text, title_style);

  // Content lines
  int content_x = rect.x + 1;
  int content_y = rect.y + 1;
  for (size_t i = 0; i < content.size() && static_cast<int>(i) < proc_inner_min; ++i) {
    canvas.draw_text(content_x, content_y + static_cast<int>(i), content[i]);
  }

  // Search bar
  if (g_ui.search_mode) {
    // Overwrite the bottom border row of the main frame with ├──┤
    int divider_y = rect.y + main_h - 1;
    canvas.put(rect.x, divider_y, "├", border_style);
    for (int x = 1; x < rect.width - 1; ++x) canvas.put(rect.x + x, divider_y, "─", border_style);
    canvas.put(rect.x + rect.width - 1, divider_y, "┤", border_style);

    // Input row
    int input_y = divider_y + 1;
    canvas.put(rect.x, input_y, "│", border_style);
    canvas.put(rect.x + rect.width - 1, input_y, "│", border_style);
    std::string label = " SEARCH/FILTER: ";
    std::string input = g_ui.filter_query + "\xE2\x96\x88";
    std::string input_row = ui.accent + label + sgr_reset() + input;
    canvas.draw_text(rect.x + 1, input_y, input_row);

    // New bottom border with right-aligned hint
    int bottom_y = input_y + 1;
    canvas.put(rect.x, bottom_y, "└", border_style);
    for (int x = 1; x < rect.width - 1; ++x) canvas.put(rect.x + x, bottom_y, "─", border_style);
    canvas.put(rect.x + rect.width - 1, bottom_y, "┘", border_style);

    std::string hint = " Press ESC to exit. ";
    int hint_x = rect.x + rect.width - 1 - static_cast<int>(hint.size()) - 1;
    if (hint_x < rect.x + 1) hint_x = rect.x + 1;
    widget::Style muted_style = widget::parse_sgr_style(ui.muted);
    canvas.draw_text(hint_x, bottom_y, hint, muted_style);
  }
}

} // namespace montauk::ui::widgets
