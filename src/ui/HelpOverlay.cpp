#include "ui/HelpOverlay.hpp"
#include "ui/Config.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <format>
#include <fstream>

namespace montauk::ui {

namespace {

// The manpage formatted at `width` columns. Runs on a worker thread: man takes
// a few hundred milliseconds, and on the render thread every resize stalled
// the UI for that long.
std::vector<std::string> read_manpage(int width) {
  std::vector<std::string> lines;
  // MANWIDTH tells man to reformat the page at our actual column width, so
  // the content reflows on resize / split-screen instead of being chopped.
  // `col -b` strips overstrike (man's bold rendering); user opted plain text.
  std::string cmd = std::format(
      "MANWIDTH={} man -P cat montauk 2>/dev/null | col -b", std::max(20, width));
  FILE* p = popen(cmd.c_str(), "r");
  if (p) {
    char buf[4096];
    while (std::fgets(buf, sizeof(buf), p)) {
      std::string line(buf);
      if (!line.empty() && line.back() == '\n') line.pop_back();
      lines.push_back(std::move(line));
    }
    pclose(p);
  }

  // Dev-mode fallback: if popen produced nothing (man not installed, manpage
  // not yet copied to /usr/local/share/man/), try the manpage in cwd.
  if (lines.empty()) {
    std::ifstream f("montauk.1");
    std::string line;
    while (std::getline(f, line)) lines.push_back(line);
  }

  if (lines.empty()) {
    lines.push_back("Help unavailable: install montauk via ./install.py to populate the manpage.");
  }
  return lines;
}

}  // namespace

void HelpOverlay::toggle() {
  visible_ = !visible_;
  if (visible_) scroll_offset_ = 0;
  // Lazy loading happens in render() at the actual column width.
}

void HelpOverlay::handle_input(const widget::InputEvent& ev) {
  if (!visible_) return;

  if (ev.is(widget::Key::Escape))     { close(); return; }
  if (ev.is(widget::Key::ArrowUp))    { if (scroll_offset_ > 0) --scroll_offset_; return; }
  if (ev.is(widget::Key::ArrowDown))  { ++scroll_offset_; return; }
  if (ev.is(widget::Key::PageUp))     { scroll_offset_ = std::max(0, scroll_offset_ - 20); return; }
  if (ev.is(widget::Key::PageDown))   { scroll_offset_ += 20; return; }

  if (!ev.is(widget::Key::Char)) return;
  switch (ev.character) {
    case 'q':
    case '?':                 close(); break;
    case 'j':                 ++scroll_offset_; break;
    case 'k':                 if (scroll_offset_ > 0) --scroll_offset_; break;
    case 'd':
    case ' ':                 scroll_offset_ += 20; break;
    case 'u':                 scroll_offset_ = std::max(0, scroll_offset_ - 20); break;
    case 'g':                 scroll_offset_ = 0; break;
    case 'G':                 scroll_offset_ = static_cast<int>(lines_.size()); break;
    default: break;
  }
}

void HelpOverlay::render(widget::Canvas& canvas,
                         const widget::LayoutRect& rect,
                         const montauk::model::Snapshot& /*snap*/) {
  const int inner_w = std::max(1, rect.width - 2);
  const int inner_h = std::max(1, rect.height - 2);

  // A finished load replaces the page; a page at the wrong width starts one.
  // Until it lands the previous page stays up, and before the first, a line
  // says it is coming. One load at a time: a std::async future blocks in its
  // destructor, so replacing one in flight would stall this thread anyway.
  if (pending_.valid() && pending_.wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
    lines_ = pending_.get();
    cached_width_ = pending_width_;
  }
  if (cached_width_ != inner_w && !pending_.valid()) {
    pending_width_ = inner_w;
    pending_ = std::async(std::launch::async, read_manpage, inner_w);
  }
  if (lines_.empty()) {
    widget::LayoutRect inner = draw_box_border(canvas, rect, "HELP",
                                               widget::parse_sgr_style(ui_config().border),
                                               widget::parse_sgr_style(ui_config().accent));
    canvas.draw_text(inner.x, inner.y, "Loading the manual page...");
    return;
  }

  const int total = static_cast<int>(lines_.size());
  const int max_scroll = std::max(0, total - inner_h);
  if (scroll_offset_ > max_scroll) scroll_offset_ = max_scroll;
  if (scroll_offset_ < 0) scroll_offset_ = 0;

  int pct = (max_scroll > 0) ? (scroll_offset_ * 100) / max_scroll : 100;
  std::string title = std::format("HELP   {}%", pct);

  widget::Style border_style = widget::parse_sgr_style(ui_config().border);
  widget::Style title_style  = widget::parse_sgr_style(ui_config().accent);
  widget::LayoutRect inner = draw_box_border(canvas, rect, title, border_style, title_style);

  // Draw body lines. Canvas::draw_text parses embedded SGR and clips at the
  // inner rect — no manual sanitizing needed. Tabs are expanded because man
  // emits them.
  int y = inner.y;
  int end = std::min(total, scroll_offset_ + inner_h);
  for (int i = scroll_offset_; i < end; ++i, ++y) {
    std::string expanded;
    expanded.reserve(lines_[i].size());
    for (char c : lines_[i]) {
      if (c == '\t') expanded += "  ";
      else expanded += c;
    }
    canvas.draw_text(inner.x, y, expanded);
  }
}

} // namespace montauk::ui
