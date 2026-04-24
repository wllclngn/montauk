#include "ui/widget/Panel.hpp"
#include "ui/Config.hpp"

namespace montauk::ui::widget {

void Panel::render(Canvas& canvas,
                   const LayoutRect& rect,
                   const montauk::model::Snapshot& /*snap*/) {
  Style border_style = parse_sgr_style(ui_config().border);
  Style title_style  = parse_sgr_style(ui_config().accent);
  LayoutRect inner = draw_box_border(canvas, rect, title_, border_style, title_style);

  int y = inner.y;
  const int max_y = inner.y + inner.height;
  for (const auto& line : lines_) {
    if (y >= max_y) break;
    canvas.draw_text(inner.x, y++, line);
  }
}

} // namespace montauk::ui::widget
