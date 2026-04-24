#pragma once

#include "ui/widget/Canvas.hpp"
#include "ui/widget/LayoutRect.hpp"
#include "ui/widget/InputEvent.hpp"
#include "model/Snapshot.hpp"

namespace montauk::ui::widget {

// Base class for all widgets in montauk's cell-based UI.
//
// Components render to a Canvas at their assigned LayoutRect. The Canvas clips
// at rect boundaries by construction — no defensive width math needed.
class Component {
public:
    virtual ~Component() = default;

    // Render this component into the canvas within the given rect.
    // The parent has already computed position and size — just draw.
    virtual void render(
        Canvas& canvas,
        const LayoutRect& rect,
        const montauk::model::Snapshot& snap
    ) = 0;

    // Handle an input event. Default: no-op.
    virtual void handle_input(const InputEvent& event) {
        (void)event;
    }

    // Return size preferences for layout computation. Default: fully flexible.
    virtual SizeConstraints get_constraints() const {
        return SizeConstraints{};
    }

protected:
    // Draw a bordered box with an optional title at the top-left. Returns the
    // inner content rect (one cell inside the border on every side).
    // Style params are explicit so the helper is testable without depending
    // on ui_config() initialization.
    LayoutRect draw_box_border(
        Canvas& canvas,
        const LayoutRect& rect,
        const std::string& title,
        Style border_style = {},
        Style title_style = {}
    ) const;

    // Truncate text to fit within max_width (display characters), appending
    // "..." when truncated. Byte-length-based — does not account for UTF-8
    // multi-byte or double-width chars. Good enough for ASCII UI strings.
    std::string truncate_text(const std::string& text, int max_width) const {
        if (static_cast<int>(text.length()) <= max_width) {
            return text;
        }
        if (max_width <= 3) {
            return text.substr(0, static_cast<size_t>(max_width));
        }
        return text.substr(0, static_cast<size_t>(max_width - 3)) + "...";
    }

    std::string format_duration(int total_seconds) const;
    std::string center_text(const std::string& text, int width) const;
    std::string pad_right(const std::string& text, int width) const;
    std::string format_filesize(size_t bytes) const;
};

} // namespace montauk::ui::widget
