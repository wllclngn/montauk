#pragma once

#include "ui/widget/Component.hpp"
#include <future>
#include <string>
#include <vector>

namespace montauk::ui {

// Manpage-driven help overlay. Formats `man montauk | col -b` at the panel's
// width off the render thread, caches the lines, and renders a scrollable
// view. The manpage is the source of truth — no hand-coded help content.
class HelpOverlay : public widget::Component {
public:
  void toggle();
  void close() { visible_ = false; }
  [[nodiscard]] bool visible() const { return visible_; }

  void render(widget::Canvas& canvas,
              const widget::LayoutRect& rect,
              const montauk::model::Snapshot& snap) override;

  void handle_input(const widget::InputEvent& event) override;

private:
  bool visible_ = false;
  int  scroll_offset_ = 0;
  int  cached_width_  = -1;   // the width lines_ was formatted at
  int  pending_width_ = -1;   // the width the load in flight formats at
  std::vector<std::string> lines_;
  std::future<std::vector<std::string>> pending_;   // at most one load in flight
};

} // namespace montauk::ui
