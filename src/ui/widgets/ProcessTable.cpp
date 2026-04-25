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

int right_align_x(int col_x, int col_w, int value_visible_cols) {
  int x = col_x + col_w - value_visible_cols;
  if (x < col_x) x = col_x;
  return x;
}

std::string format_pct_digits(double pct) {
  if (pct > 0.0 && pct < 1.0) {
    double r = std::round(pct * 10.0) / 10.0;
    if (r < 0.1) r = 0.1;
    std::ostringstream oss; oss << std::fixed << std::setprecision(1) << r;
    return oss.str();
  }
  std::ostringstream oss; oss << static_cast<int>(pct + 0.5);
  return oss.str();
}

widget::Style severity_to_style(int severity) {
  const auto& uic = ui_config();
  if (severity >= 2) return widget::parse_sgr_style(uic.warning);
  if (severity >= 1) return widget::parse_sgr_style(uic.caution);
  return widget::Style{};
}

void draw_command_classified(widget::Canvas& canvas, int x, int y,
                             int max_width, std::string_view cmd,
                             const UIConfig& ui, int row_severity) {
  if (max_width <= 0 || cmd.empty()) return;
  static const montauk::util::ThompsonNFA kernel_re("^\\[.+\\]$");
  const widget::Style muted_style  = widget::parse_sgr_style(ui.muted);
  const widget::Style binary_style = widget::parse_sgr_style(ui.binary);
  const widget::Style row_style    = severity_to_style(row_severity);

  if (row_severity > 0) {
    canvas.draw_text(x, y, cmd.substr(0, std::min<size_t>(cmd.size(), max_width)), row_style);
    return;
  }

  if (kernel_re.full_match(cmd)) {
    canvas.draw_text(x, y, cmd.substr(0, std::min<size_t>(cmd.size(), max_width)), muted_style);
    return;
  }

  size_t first_space = cmd.find(' ');
  size_t exe_end = (first_space == std::string_view::npos) ? cmd.size() : first_space;
  size_t last_slash = cmd.rfind('/', exe_end);

  int budget = max_width;
  int cur_x = x;
  auto draw_seg = [&](std::string_view seg, widget::Style st) {
    if (budget <= 0 || seg.empty()) return;
    int take = static_cast<int>(std::min<size_t>(seg.size(), static_cast<size_t>(budget)));
    canvas.draw_text(cur_x, y, seg.substr(0, take), st);
    cur_x += take;
    budget -= take;
  };

  if (last_slash != std::string_view::npos) {
    draw_seg(cmd.substr(0, last_slash + 1), muted_style);
    draw_seg(cmd.substr(last_slash + 1, exe_end - last_slash - 1), binary_style);
  } else {
    draw_seg(cmd.substr(0, exe_end), binary_style);
  }
  if (first_space != std::string_view::npos) {
    draw_seg(cmd.substr(first_space, cmd.size() - first_space), muted_style);
  }
}

} // namespace

void ProcessTable::reset_view() {
  sort_mode_   = SortMode::CPU;
  scroll_      = 0;
  cpu_scale_   = CPUScale::Total;
  gpu_scale_   = GPUScale::Utilization;
  filter_query_.clear();
  search_mode_ = false;
}

void ProcessTable::handle_input(const widget::InputEvent& ev) {
  // Search mode swallows printable input as filter chars.
  if (search_mode_) {
    if (ev.is(widget::Key::Escape)) {
      search_mode_ = false;
      return;
    }
    if (ev.is(widget::Key::Enter)) {
      search_mode_ = false;
      scroll_ = 0;
      return;
    }
    if (ev.is(widget::Key::Backspace)) {
      if (!filter_query_.empty()) {
        filter_query_.pop_back();
        scroll_ = 0;
      } else {
        search_mode_ = false;
      }
      return;
    }
    if (ev.is_printable_char()) {
      filter_query_ += ev.character;
      scroll_ = 0;
    }
    return;
  }

  // Esc with a non-empty filter clears it.
  if (ev.is(widget::Key::Escape)) {
    if (!filter_query_.empty()) {
      filter_query_.clear();
      scroll_ = 0;
    }
    return;
  }

  // Scroll keys.
  const int max_scroll = std::max(0, last_total_ - last_page_rows_);
  if (ev.is(widget::Key::ArrowUp))   { if (scroll_ > 0) --scroll_; return; }
  if (ev.is(widget::Key::ArrowDown)) { scroll_ = std::min(scroll_ + 1, max_scroll); return; }
  if (ev.is(widget::Key::PageUp))    {
    int page = std::max(1, last_page_rows_ - 2);
    scroll_ = std::max(0, scroll_ - page);
    return;
  }
  if (ev.is(widget::Key::PageDown))  {
    int page = std::max(1, last_page_rows_ - 2);
    scroll_ = std::min(scroll_ + page, max_scroll);
    return;
  }

  // Single-char bindings.
  if (!ev.is(widget::Key::Char)) return;
  switch (ev.character) {
    case 'c': sort_mode_ = SortMode::CPU;  scroll_ = 0; break;
    case 'm': sort_mode_ = SortMode::MEM;  scroll_ = 0; break;
    case 'p': sort_mode_ = SortMode::PID;  scroll_ = 0; break;
    case 'n': sort_mode_ = SortMode::NAME; scroll_ = 0; break;
    case 'g': sort_mode_ = SortMode::GPU;  scroll_ = 0; break;
    case 'v': sort_mode_ = SortMode::GMEM; scroll_ = 0; break;
    case '/':
      search_mode_ = true;
      filter_query_.clear();
      scroll_ = 0;
      break;
    case 'i':
      cpu_scale_ = (cpu_scale_ == CPUScale::Total) ? CPUScale::Core : CPUScale::Total;
      break;
    case 'u':
      gpu_scale_ = (gpu_scale_ == GPUScale::Capacity)
                       ? GPUScale::Utilization : GPUScale::Capacity;
      break;
    default: break;
  }
}

void ProcessTable::render(widget::Canvas& canvas,
                          const widget::LayoutRect& rect,
                          const montauk::model::Snapshot& s) {
  const auto& ui = ui_config();
  const int target_rows = rect.height;
  const int ncpu = static_cast<int>(std::max<size_t>(1, s.cpu.per_core_pct.size()));
  auto scale_proc_cpu = [&](double raw) {
    return (cpu_scale_ == CPUScale::Total) ? (raw / static_cast<double>(ncpu)) : raw;
  };

  // 1. Smooth + sort + filter.
  std::vector<size_t> order(s.procs.processes.size());
  std::iota(order.begin(), order.end(), 0);
  std::vector<double> sm(order.size(), 0.0);
  for (size_t i = 0; i < order.size(); ++i) {
    const auto& p = s.procs.processes[i];
    sm[i] = montauk::ui::smooth_value(
        std::string("proc.cpu.") + std::to_string(p.pid),
        scale_proc_cpu(p.cpu_pct), 0.35);
  }

  // Sort dispatch — sublimation switch path is a hard-pinned constraint.
  if (montauk::util::resolve_backend() == montauk::util::SortBackend::Sublimation) {
    const size_t n = order.size();
    std::vector<uint32_t> idx32(n);
    for (size_t i = 0; i < n; ++i) idx32[i] = static_cast<uint32_t>(i);
    switch (sort_mode_) {
      case SortMode::CPU: {
        std::vector<float> keys(n);
        for (size_t i = 0; i < n; ++i) keys[i] = static_cast<float>(sm[i]);
        montauk::util::sort_by_key_f32(keys, idx32, /*descending=*/true); break;
      }
      case SortMode::MEM: {
        std::vector<uint32_t> keys(n);
        for (size_t i = 0; i < n; ++i) keys[i] = static_cast<uint32_t>(s.procs.processes[i].rss_kb);
        montauk::util::sort_by_key_u32(keys, idx32, /*descending=*/true); break;
      }
      case SortMode::PID: {
        std::vector<uint32_t> keys(n);
        for (size_t i = 0; i < n; ++i) keys[i] = static_cast<uint32_t>(s.procs.processes[i].pid);
        montauk::util::sort_by_key_u32(keys, idx32, /*descending=*/false); break;
      }
      case SortMode::GPU: {
        std::vector<float> keys(n);
        for (size_t i = 0; i < n; ++i) keys[i] = static_cast<float>(s.procs.processes[i].gpu_util_pct);
        montauk::util::sort_by_key_f32(keys, idx32, /*descending=*/true); break;
      }
      case SortMode::GMEM: {
        std::vector<uint32_t> keys(n);
        for (size_t i = 0; i < n; ++i) keys[i] = static_cast<uint32_t>(s.procs.processes[i].gpu_mem_kb);
        montauk::util::sort_by_key_u32(keys, idx32, /*descending=*/true); break;
      }
      case SortMode::NAME: {
        std::vector<const char*> ptrs(n);
        for (size_t i = 0; i < n; ++i) ptrs[i] = s.procs.processes[i].cmd.c_str();
        montauk::util::sort_by_string(ptrs, idx32); break;
      }
    }
    for (size_t i = 0; i < n; ++i) order[i] = static_cast<size_t>(idx32[i]);
  } else {
    montauk::util::timsort(order.begin(), order.end(), [&](size_t a, size_t b) {
      const auto& A = s.procs.processes[a];
      const auto& B = s.procs.processes[b];
      switch (sort_mode_) {
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

  if (!filter_query_.empty()) {
    montauk::app::ProcessFilterSpec fspec{};
    fspec.name_contains = filter_query_;
    montauk::app::ProcessFilter filt(fspec);
    auto matched = filt.apply(s.procs);
    std::unordered_set<size_t> match_set(matched.begin(), matched.end());
    std::erase_if(order, [&](size_t idx) { return !match_set.contains(idx); });
  }

  // 2. Layout / pagination.
  const int search_rows = search_mode_ ? 2 : 0;
  const int main_h = std::max(3, target_rows - search_rows);
  const int proc_inner_min = std::max(2, main_h - 2);
  const int desired_rows = std::max(1, proc_inner_min - 1);
  last_page_rows_ = desired_rows;
  last_total_     = static_cast<int>(order.size());
  int max_scroll = std::max(0, last_total_ - desired_rows);
  if (scroll_ > max_scroll) scroll_ = max_scroll;

  const int skip = scroll_;
  const int take = desired_rows;
  std::vector<const montauk::model::ProcSample*> displayed;
  displayed.reserve(static_cast<size_t>(take));
  int limit = std::min(static_cast<int>(order.size()), skip + take);
  for (int i = skip; i < limit; ++i) displayed.push_back(&s.procs.processes[order[i]]);

  // 3. Sticky column widths.
  int pid_w_meas = 5, user_w_meas = 4, gpu_d_meas = 3, mem_w_meas = 4, gmem_w_meas = 4;
  for (size_t i = 0; i < order.size(); ++i) {
    const auto& p = s.procs.processes[order[i]];
    pid_w_meas  = std::max(pid_w_meas,  static_cast<int>(std::to_string(p.pid).size()));
    user_w_meas = std::max(user_w_meas, static_cast<int>(p.user_name.size()));
    if (p.has_gpu_util) {
      gpu_d_meas = std::max(gpu_d_meas,
          static_cast<int>(std::to_string(static_cast<int>(p.gpu_util_pct + 0.5)).size()));
    }
    mem_w_meas  = std::max(mem_w_meas,  static_cast<int>(format_size_kib(p.rss_kb).size()));
    gmem_w_meas = std::max(gmem_w_meas, static_cast<int>(format_size_kib(p.gpu_mem_kb).size()));
  }
  pid_w_meas  = std::clamp(pid_w_meas,  5,  8);
  user_w_meas = std::clamp(user_w_meas, 4, 12);
  gpu_d_meas  = std::clamp(gpu_d_meas,  3,  4);
  mem_w_meas  = std::clamp(mem_w_meas,  4,  6);
  gmem_w_meas = std::clamp(gmem_w_meas, 4,  6);
  col_pid_w_       = std::max(col_pid_w_,       pid_w_meas);
  col_user_w_      = std::max(col_user_w_,      user_w_meas);
  col_gpu_digit_w_ = std::max(col_gpu_digit_w_, gpu_d_meas);
  col_mem_w_       = std::max(col_mem_w_,       mem_w_meas);
  col_gmem_w_      = std::max(col_gmem_w_,      gmem_w_meas);

  const int pidw  = col_pid_w_;
  const int userw = col_user_w_;
  const int gpud  = col_gpu_digit_w_;
  const int memw  = col_mem_w_;
  const int gmemw = col_gmem_w_;
  const int cpuw  = 4;
  const int gpuw  = gpud + 1;
  const int gap   = 2;

  const widget::Style border_style = widget::parse_sgr_style(ui.border);
  const widget::Style title_style  = widget::parse_sgr_style(ui.accent);
  const widget::Style muted_style  = widget::parse_sgr_style(ui.muted);

  canvas.draw_rect(rect.x, rect.y, rect.width, main_h, border_style);

  std::string title = "PROCESS MONITOR";
  if (!filter_query_.empty()) {
    std::string suffix = (order.size() == 1) ? " RESULT" : " RESULTS";
    title = "PROCESS MONITOR: " + std::to_string(order.size()) + suffix;
  }
  const std::string title_text = " " + title + " ";
  int title_x = rect.x + (rect.width - static_cast<int>(title_text.size())) / 2;
  if (title_x < rect.x + 2) title_x = rect.x + 2;
  canvas.draw_text(title_x, rect.y, title_text, title_style);

  const int inner_x = rect.x + 1;
  const int inner_y = rect.y + 1;
  const int inner_w = rect.width - 2;
  if (inner_w <= 0) return;

  const int x_pid_r   = inner_x + pidw;
  const int x_user    = x_pid_r + gap;
  const int x_user_r  = x_user + userw;
  const int x_cpu     = x_user_r + gap;
  const int x_cpu_r   = x_cpu + cpuw;
  const int x_gpu     = x_cpu_r + gap;
  const int x_gpu_r   = x_gpu + gpuw;
  int x_gmem = 0, x_gmem_r = 0;
  if (show_gmem_) {
    x_gmem   = x_gpu_r + gap;
    x_gmem_r = x_gmem + gmemw;
  }
  const int x_mem   = (show_gmem_ ? x_gmem_r : x_gpu_r) + gap;
  const int x_mem_r = x_mem + memw;
  const int x_cmd   = x_mem_r + gap;
  const int cmd_w   = std::max(8, (inner_x + inner_w) - x_cmd);

  int header_y = inner_y;
  canvas.draw_text(right_align_x(inner_x, pidw, 3),  header_y, "PID",  title_style);
  canvas.draw_text(x_user,                            header_y, "USER", title_style);
  canvas.draw_text(right_align_x(x_cpu, cpuw, 4),     header_y, "CPU%", title_style);
  canvas.draw_text(right_align_x(x_gpu, gpuw, 4),     header_y, "GPU%", title_style);
  if (show_gmem_) {
    canvas.draw_text(right_align_x(x_gmem, gmemw, 4), header_y, "GMEM", title_style);
  }
  canvas.draw_text(right_align_x(x_mem, memw, 3),     header_y, "MEM",  title_style);
  canvas.draw_text(x_cmd,                             header_y, "COMMAND", title_style);

  for (size_t i = 0; i < displayed.size(); ++i) {
    const auto* p = displayed[i];
    const int y = inner_y + 1 + static_cast<int>(i);
    if (y >= rect.y + main_h - 1) break;

    const double scaled_cpu = scale_proc_cpu(p->cpu_pct);
    const double smooth_cpu = montauk::ui::smooth_value(
        std::string("proc.cpu.") + std::to_string(p->pid), scaled_cpu, 0.35);
    const int row_severity = compute_severity(static_cast<int>(smooth_cpu + 0.5),
                                               ui.caution_pct, ui.warning_pct);
    const widget::Style row_style = severity_to_style(row_severity);

    {
      std::string pid_str = std::to_string(p->pid);
      canvas.draw_text(right_align_x(inner_x, pidw, static_cast<int>(pid_str.size())),
                       y, pid_str, row_style);
    }
    {
      std::string u = p->user_name;
      if (static_cast<int>(u.size()) > userw) u = u.substr(0, static_cast<size_t>(userw));
      canvas.draw_text(x_user, y, u, row_style);
    }
    {
      std::string digits = format_pct_digits(smooth_cpu);
      std::string field  = digits + "%";
      const widget::Style cpu_style = (row_severity > 0) ? row_style : widget::Style{};
      canvas.draw_text(right_align_x(x_cpu, cpuw, static_cast<int>(field.size())),
                       y, field, cpu_style);
    }
    {
      const int ngpu_dev = std::max(1, s.nvml.devices);
      double display_gpu = (gpu_scale_ == GPUScale::Capacity)
                              ? p->gpu_util_pct / static_cast<double>(ngpu_dev)
                              : p->gpu_util_pct;
      std::string digits = format_pct_digits(display_gpu);
      std::string field  = digits + "%";
      widget::Style gpu_style = row_style;
      if (row_severity == 0) {
        int gsev = compute_severity(static_cast<int>(display_gpu + 0.5),
                                    ui.caution_pct, ui.warning_pct);
        gpu_style = severity_to_style(gsev);
      }
      canvas.draw_text(right_align_x(x_gpu, gpuw, static_cast<int>(field.size())),
                       y, field, gpu_style);
    }
    if (show_gmem_) {
      std::string g = format_size_kib(p->gpu_mem_kb);
      canvas.draw_text(right_align_x(x_gmem, gmemw, static_cast<int>(g.size())),
                       y, g, row_style);
    }
    {
      std::string m = format_size_kib(p->rss_kb);
      canvas.draw_text(right_align_x(x_mem, memw, static_cast<int>(m.size())),
                       y, m, row_style);
    }
    {
      std::string raw = p->cmd.empty() ? std::to_string(p->pid)
                                       : sanitize_for_display(p->cmd, cmd_w + 10);
      draw_command_classified(canvas, x_cmd, y, cmd_w, raw, ui, row_severity);
    }
  }

  if (search_mode_) {
    const int divider_y = rect.y + main_h - 1;
    canvas.put(rect.x, divider_y, "├", border_style);
    for (int x = 1; x < rect.width - 1; ++x) canvas.put(rect.x + x, divider_y, "─", border_style);
    canvas.put(rect.x + rect.width - 1, divider_y, "┤", border_style);

    const int input_y = divider_y + 1;
    canvas.put(rect.x, input_y, "│", border_style);
    canvas.put(rect.x + rect.width - 1, input_y, "│", border_style);
    canvas.draw_text(rect.x + 1, input_y, " SEARCH/FILTER: ", title_style);
    int after_label = rect.x + 1 + 16;
    std::string input = filter_query_ + "\xE2\x96\x88";
    canvas.draw_text(after_label, input_y, input);

    const int bottom_y = input_y + 1;
    canvas.put(rect.x, bottom_y, "└", border_style);
    for (int x = 1; x < rect.width - 1; ++x) canvas.put(rect.x + x, bottom_y, "─", border_style);
    canvas.put(rect.x + rect.width - 1, bottom_y, "┘", border_style);

    std::string hint = " Press ESC to exit. ";
    int hint_x = rect.x + rect.width - 1 - static_cast<int>(hint.size()) - 1;
    if (hint_x < rect.x + 1) hint_x = rect.x + 1;
    canvas.draw_text(hint_x, bottom_y, hint, muted_style);
  }
}

} // namespace montauk::ui::widgets
