#include "ui/Renderer.hpp"
#include "ui/HelpOverlay.hpp"
#include "ui/Panels.hpp"
#include "ui/Terminal.hpp"
#include "ui/Formatting.hpp"
#include "ui/widget/Canvas.hpp"
#include "ui/widget/LayoutRect.hpp"
#include "ui/widgets/ProcessTable.hpp"

#include <algorithm>
#include <format>
#include <sstream>
#include <string>

namespace montauk::ui {

namespace {

// Serialize a Canvas to ANSI-encoded bytes ready for stdout. Emits SGR codes
// only on Style transitions, terminates with a cursor-park escape, and
// returns one contiguous buffer so the caller can issue a single write().
std::string canvas_to_frame(const widget::Canvas& canvas, int rows, int cols) {
  std::string frame;
  frame.reserve(static_cast<size_t>(rows) * static_cast<size_t>(cols) + 64);
  frame += "\x1B[H";

  auto emit_sgr = [&frame](const widget::Style& s) {
    if (s.fg == widget::Color::Default && s.bg == widget::Color::Default && s.attr == widget::Attribute::None) {
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
      if (!cell.content.empty()) {
        frame += cell.content;
      }
    }
    frame += "\x1b[0m";
    if (y < rows - 1) frame += "\n";
    style_dirty = true;
  }

  // Flush queued graphics commands after the cell-grid pass. Each command's
  // escape already contains its cursor-positioning prefix — we just append.
  for (const auto& cmd : canvas.graphics_commands()) {
    frame += cmd.escape;
  }

  frame += std::format("\x1B[{};{}H", rows, cols);
  return frame;
}

} // namespace

void render_screen(const montauk::model::Snapshot& s,
                   bool show_help_line,
                   const std::string& help_text,
                   HelpOverlay* overlay) {
  const int cols = term_cols();
  const int rows = term_rows();

  // Layout math — same fractions the previous string-concat renderer used.
  const int gutter = 1;
  int left_w = (cols * 2) / 3;
  if (left_w < 40) left_w = cols - 20;
  if (left_w > cols - 20) left_w = cols - 20;
  if ((cols - (left_w + 1) - gutter) >= 20) left_w += 1;
  int right_w = cols - left_w - gutter;
  if (right_w < 20) right_w = 20;

  const int header_lines = show_help_line ? 1 : 0;
  const int body_rows = std::max(5, rows - header_lines);

  widget::Canvas canvas(cols, rows);

  if (show_help_line) {
    canvas.draw_text(0, 0, trunc_pad(help_text, cols));
  }

  const int body_y = header_lines;
  widget::LayoutRect left_rect{0, body_y, left_w, body_rows};
  widget::LayoutRect right_rect{left_w + gutter, body_y, right_w, body_rows};

  if (overlay && overlay->visible()) {
    overlay->render(canvas, left_rect, s);
  } else {
    widgets::ProcessTable pt(body_rows);
    pt.render(canvas, left_rect, s);
  }
  render_right_column(canvas, right_rect, s);

  std::string frame = canvas_to_frame(canvas, rows, cols);
  best_effort_write(STDOUT_FILENO, frame.data(), frame.size());
}

} // namespace montauk::ui
