#pragma once

#include "ui/widget/Canvas.hpp"
#include "ui/widget/InputEvent.hpp"
#include "ui/widget/LayoutRect.hpp"
#include "model/Snapshot.hpp"
#include <string>

namespace montauk::ui::widget {

// Base class for all widgets in montauk's cell-based UI.
//
// Components render to a Canvas at their assigned LayoutRect. The Canvas
// clips at rect boundaries by construction — no defensive width math needed.
// Input events are dispatched by the renderer to whichever widget owns
// focus; widgets that don't take input simply ignore handle_input().
class Component {
public:
    virtual ~Component() = default;

    virtual void render(Canvas& canvas,
                        const LayoutRect& rect,
                        const montauk::model::Snapshot& snap) = 0;

    // Default: no-op. Widgets that consume input override.
    virtual void handle_input(const InputEvent& event) { (void)event; }

protected:
    // Draw a bordered rect with an optional title centered on the top
    // border. Returns the inner content rect (one cell inside on every
    // side). Style params explicit so the helper is testable without
    // depending on ui_config() initialization.
    LayoutRect draw_box_border(Canvas& canvas,
                                const LayoutRect& rect,
                                const std::string& title,
                                Style border_style = {},
                                Style title_style = {}) const;
};

} // namespace montauk::ui::widget
