#pragma once

#include "ui/widget/Component.hpp"
#include <string>
#include <vector>

namespace montauk::ui::widget {

// Generic bordered panel. Accepts a title and a list of pre-formatted content
// lines (which may carry embedded ANSI SGR codes for per-line coloring) and
// renders them inside a box. Data-source agnostic — callers assemble lines
// from any source (Snapshot fields, static strings, external queries, etc.)
// and hand them to Panel for rendering.
//
// Use this for all right-column montauk panels. Widgets with genuinely
// unique state (HelpOverlay, ProcessTable) remain their own Component
// subclasses.
class Panel : public Component {
public:
  Panel() = default;
  Panel(std::string title, std::vector<std::string> lines)
      : title_(std::move(title)), lines_(std::move(lines)) {}

  void set_title(std::string title) { title_ = std::move(title); }
  void set_lines(std::vector<std::string> lines) { lines_ = std::move(lines); }

  // Height (rows) needed to display `content_rows` content lines plus top
  // and bottom borders.
  [[nodiscard]] static int height_for(int content_rows) { return content_rows + 2; }

  // Snapshot is unused — Panel content is provided via set_title/set_lines.
  // The parameter is present to satisfy the Component interface.
  void render(Canvas& canvas,
              const LayoutRect& rect,
              const montauk::model::Snapshot& snap) override;

private:
  std::string title_;
  std::vector<std::string> lines_;
};

} // namespace montauk::ui::widget
