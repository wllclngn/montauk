#include "ui/widget/Component.hpp"
#include <algorithm>

namespace montauk::ui::widget {

LayoutRect Component::draw_box_border(Canvas& canvas,
                                       const LayoutRect& rect,
                                       const std::string& title,
                                       Style border_style,
                                       Style title_style) const {
    canvas.draw_rect(rect.x, rect.y, rect.width, rect.height, border_style);

    if (!title.empty() && rect.width > 4) {
        // Center the title on the top border between the corners.
        const std::string t = " " + title + " ";
        const int span = rect.width - 2;
        const int tlen = static_cast<int>(t.size());
        const int pad_left = std::max(0, (span - tlen) / 2);
        canvas.draw_text(rect.x + 1 + pad_left, rect.y, t, title_style);
    }

    return LayoutRect{rect.x + 1, rect.y + 1,
                      std::max(0, rect.width - 2),
                      std::max(0, rect.height - 2)};
}

} // namespace montauk::ui::widget
