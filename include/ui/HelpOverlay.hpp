#pragma once

#include "ui/widget/Component.hpp"
#include <string>
#include <vector>

namespace montauk::ui {

// Manpage-driven help overlay. Loads `man montauk | col -b` once on first
// open, caches the lines, and renders a scrollable view. The manpage is the
// source of truth — no hand-coded help content.
class HelpOverlay : public widget::Component {
public:
  void toggle();
  void close() { visible_ = false; }
  [[nodiscard]] bool visible() const { return visible_; }

  void scroll_up();
  void scroll_down();
  void page_up();
  void page_down();
  void scroll_top()    { scroll_offset_ = 0; }
  void scroll_bottom() { scroll_offset_ = static_cast<int>(lines_.size()); }

  void render(widget::Canvas& canvas,
              const widget::LayoutRect& rect,
              const montauk::model::Snapshot& snap) override;

private:
  // Reformats the manpage at the given column width via MANWIDTH=N.
  void load_manpage(int width);

  bool visible_ = false;
  int  scroll_offset_ = 0;
  int  cached_width_  = -1;
  std::vector<std::string> lines_;
};

} // namespace montauk::ui
