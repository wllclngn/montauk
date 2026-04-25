#include "ui/Renderer.hpp"
#include "ui/HelpOverlay.hpp"
#include "ui/Terminal.hpp"
#include "ui/Config.hpp"
#include "ui/widget/Canvas.hpp"
#include "ui/widget/FlexLayout.hpp"
#include "ui/widget/LayoutRect.hpp"
#include "ui/widgets/ProcessTable.hpp"
#include "ui/widgets/RightColumn.hpp"

#include <algorithm>
#include <format>
#include <sstream>

namespace montauk::ui {

namespace {

// Serialize a Canvas to ANSI-encoded bytes ready for stdout. Emits SGR
// codes only on Style transitions, terminates with a cursor-park escape,
// returns one contiguous buffer so the caller issues a single write().
std::string canvas_to_frame(const widget::Canvas& canvas, int rows, int cols) {
  std::string frame;
  frame.reserve(static_cast<size_t>(rows) * static_cast<size_t>(cols) + 64);
  frame += "\x1B[H";

  auto emit_sgr = [&frame](const widget::Style& s) {
    if (s.fg == widget::Color::Default && s.bg == widget::Color::Default
        && s.attr == widget::Attribute::None) {
      frame += "\x1b[0m";
      return;
    }
    std::ostringstream oss;
    oss << "\x1b[0";
    if (widget::has_attribute(s.attr, widget::Attribute::Bold))      oss << ";1";
    if (widget::has_attribute(s.attr, widget::Attribute::Dim))       oss << ";2";
    if (widget::has_attribute(s.attr, widget::Attribute::Underline)) oss << ";4";
    if (widget::has_attribute(s.attr, widget::Attribute::Blink))     oss << ";5";
    if (widget::has_attribute(s.attr, widget::Attribute::Reverse))   oss << ";7";
    if (widget::is_truecolor(s.fg)) {
      oss << ";38;2;" << static_cast<int>(widget::color_r(s.fg)) << ';'
                       << static_cast<int>(widget::color_g(s.fg)) << ';'
                       << static_cast<int>(widget::color_b(s.fg));
    } else if (s.fg != widget::Color::Default) {
      int idx = static_cast<int>(s.fg);
      if (idx >= 1 && idx <= 8)       oss << ';' << (29 + idx);
      else if (idx >= 9 && idx <= 16) oss << ';' << (81 + idx);
    }
    if (widget::is_truecolor(s.bg)) {
      oss << ";48;2;" << static_cast<int>(widget::color_r(s.bg)) << ';'
                       << static_cast<int>(widget::color_g(s.bg)) << ';'
                       << static_cast<int>(widget::color_b(s.bg));
    } else if (s.bg != widget::Color::Default) {
      int idx = static_cast<int>(s.bg);
      if (idx >= 1 && idx <= 8)       oss << ';' << (39 + idx);
      else if (idx >= 9 && idx <= 16) oss << ';' << (91 + idx);
    }
    oss << 'm';
    frame += oss.str();
  };

  widget::Style current{};
  bool style_dirty = true;
  for (int y = 0; y < rows; ++y) {
    for (int x = 0; x < cols; ++x) {
      const widget::Cell& cell = canvas.at(x, y);
      if (style_dirty || !(cell.style == current)) {
        emit_sgr(cell.style);
        current = cell.style;
        style_dirty = false;
      }
      if (!cell.content.empty()) frame += cell.content;
    }
    frame += "\x1b[0m";
    if (y < rows - 1) frame += "\n";
    style_dirty = true;
  }
  for (const auto& cmd : canvas.graphics_commands()) frame += cmd.escape;
  frame += std::format("\x1B[{};{}H", rows, cols);
  return frame;
}

} // namespace

struct Renderer::Impl {
  widgets::ProcessTable proc_table;
  widgets::RightColumn  right_column;
  HelpOverlay           help_overlay;
  int                   sleep_ms   = 250;
  bool                  quit       = false;
};

Renderer::Renderer() : impl_(std::make_unique<Impl>()) {}
Renderer::~Renderer() = default;

void Renderer::seed_from_config() {
  const auto& cfg = config();
  impl_->right_column.set_system_focus(cfg.ui.system_focus);
  impl_->right_column.set_show_gpumon(true);
  impl_->right_column.set_show_thermal(true);

  std::string scale = cfg.ui.cpu_scale;
  for (auto& ch : scale) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
  impl_->proc_table.set_cpu_scale(
      (scale == "core" || scale == "percore" || scale == "irix")
          ? widgets::ProcessTable::CPUScale::Core
          : widgets::ProcessTable::CPUScale::Total);

  std::string gscale = cfg.ui.gpu_scale;
  for (auto& ch : gscale) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
  impl_->proc_table.set_gpu_scale(
      (gscale == "capacity")
          ? widgets::ProcessTable::GPUScale::Capacity
          : widgets::ProcessTable::GPUScale::Utilization);
}

bool Renderer::should_quit() const { return impl_->quit; }
int  Renderer::sleep_ms()    const { return impl_->sleep_ms; }

void Renderer::handle_input(const widget::InputEvent& ev) {
  // Help overlay swallows everything while visible.
  if (impl_->help_overlay.visible()) {
    impl_->help_overlay.handle_input(ev);
    return;
  }

  // Search-mode in the process table is modal — same routing.
  if (impl_->proc_table.search_mode()) {
    impl_->proc_table.handle_input(ev);
    return;
  }

  // '?' is the universal help toggle, available whenever search is closed.
  if (ev.is_char('?')) { impl_->help_overlay.toggle(); return; }

  // Global single-key bindings: quit / fps / mode toggles / reset.
  if (ev.is(widget::Key::Char)) {
    switch (ev.character) {
      case 'q': impl_->quit = true;                                 return;
      case 'h': impl_->help_overlay.toggle();                       return;
      case '+': impl_->sleep_ms = std::max(33, impl_->sleep_ms - 10); return;
      case '-': impl_->sleep_ms = std::min(1000, impl_->sleep_ms + 10); return;
      case 'G': impl_->right_column.set_show_gpumon (!impl_->right_column.show_gpumon());  return;
      case 't': impl_->right_column.set_show_thermal(!impl_->right_column.show_thermal()); return;
      case 's': impl_->right_column.set_system_focus(!impl_->right_column.system_focus()); return;
      case 'R':
        impl_->proc_table.reset_view();
        impl_->right_column.reset();
        return;
      default: break;  // fall through to ProcessTable
    }
  }

  // Everything else (sort, scroll, search, scale toggles) belongs to
  // the process table.
  impl_->proc_table.handle_input(ev);
}

void Renderer::render(const montauk::model::Snapshot& s) {
  const int cols = term_cols();
  const int rows = std::max(5, term_rows());

  widget::FlexLayout root;
  root.set_direction(widget::FlexDirection::Row);
  root.set_spacing(1);
  root.add_item(widget::LayoutConstraints::flexible(40, cols, 2.0f));
  root.add_item(widget::LayoutConstraints::flexible(20, cols, 1.0f));
  auto rects = root.compute_layout(cols, rows);

  widget::Canvas canvas(cols, rows);
  const widget::LayoutRect left_rect{rects[0].x, 0, rects[0].width, rows};
  const widget::LayoutRect right_rect{rects[1].x, 0, rects[1].width, rows};

  if (impl_->help_overlay.visible()) {
    impl_->help_overlay.render(canvas, left_rect, s);
  } else {
    impl_->proc_table.render(canvas, left_rect, s);
  }
  impl_->right_column.render(canvas, right_rect, s);

  std::string frame = canvas_to_frame(canvas, rows, cols);
  best_effort_write(STDOUT_FILENO, frame.data(), frame.size());
}

} // namespace montauk::ui
