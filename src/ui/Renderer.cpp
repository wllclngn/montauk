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

// Append an SGR escape for `s` onto `frame`. Emits a single CSI sequence
// per call; callers track when the style has actually changed.
void append_sgr(std::string& frame, const widget::Style& s) {
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
}

// Build a frame buffer that contains only the cells that changed between
// `prev` and `curr`. For each changed run, emit one cursor-position
// escape, an SGR if the style differs from the last emitted style, and
// the content. Adjacent changed cells on the same row reuse the cursor
// position implicitly (the terminal advances as it draws). Style is
// tracked across cell boundaries so we don't repeat SGRs.
//
// On `full_repaint`, prev is treated as all-blank and every non-blank
// cell of curr is emitted (used for the first frame and after a resize).
std::string canvas_diff_to_frame(const widget::Canvas& curr,
                                  const widget::Canvas& prev,
                                  int rows, int cols,
                                  bool full_repaint) {
  std::string frame;
  // Worst case is a full repaint, but typical steady-state diffs are
  // tiny. Reserve modestly.
  frame.reserve(full_repaint
                    ? static_cast<size_t>(rows) * static_cast<size_t>(cols) + 64
                    : 1024);

  if (full_repaint) {
    frame += "\x1B[2J\x1B[H";  // clear + home
  }

  widget::Style current_style{};
  bool style_known = false;
  int  cursor_x = -1;
  int  cursor_y = -1;

  const widget::Cell blank;  // default Cell{" ", {}} for full-repaint sentinel

  for (int y = 0; y < rows; ++y) {
    for (int x = 0; x < cols; ++x) {
      const widget::Cell& cell = curr.at(x, y);
      const widget::Cell& base = full_repaint ? blank : prev.at(x, y);
      if (cell == base) continue;

      // Position the cursor (skip the move if we're already there from
      // the previous emit on this row).
      if (cursor_y != y || cursor_x != x) {
        frame += std::format("\x1B[{};{}H", y + 1, x + 1);
        cursor_x = x;
        cursor_y = y;
      }
      // Style transition.
      if (!style_known || !(cell.style == current_style)) {
        append_sgr(frame, cell.style);
        current_style = cell.style;
        style_known = true;
      }
      // Content. Empty content means image-occupied or default-blank —
      // emit a single space so the prior frame's character is overwritten.
      frame += cell.content.empty() ? std::string(" ") : cell.content;
      cursor_x += 1;  // single-cell content; double-width chars don't appear in montauk's UI strings
    }
  }

  // Graphics commands are appended verbatim — each one carries its own
  // cursor positioning prefix. Chart panels already throttle so most
  // frames have an empty graphics-command list.
  for (const auto& cmd : curr.graphics_commands()) frame += cmd.escape;

  // Reset SGR so any out-of-band terminal output after our frame doesn't
  // inherit our last color, and park the cursor at the bottom-right.
  if (style_known) frame += "\x1b[0m";
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

  // Previous frame's canvas, kept for dirty-cell diffing in render().
  // Empty until the first frame; on resize we replace it with a fresh
  // blank canvas at the new size and force a full repaint.
  widget::Canvas        prev_canvas{1, 1};
  int                   last_cols  = 0;
  int                   last_rows  = 0;
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

  // On size change, the previous canvas is the wrong shape — treat the
  // next frame as a full repaint against a fresh blank baseline.
  const bool size_changed = (cols != impl_->last_cols || rows != impl_->last_rows);
  if (size_changed) {
    impl_->prev_canvas = widget::Canvas(cols, rows);
    impl_->last_cols = cols;
    impl_->last_rows = rows;
  }

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

  std::string frame = canvas_diff_to_frame(canvas, impl_->prev_canvas,
                                            rows, cols, size_changed);
  enqueue_frame(std::move(frame));

  // Move the just-rendered canvas into prev for next frame's diff.
  impl_->prev_canvas = std::move(canvas);
}

} // namespace montauk::ui
