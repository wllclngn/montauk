#pragma once

#include "model/Snapshot.hpp"
#include "ui/widget/Canvas.hpp"
#include "ui/widget/LayoutRect.hpp"

namespace montauk::ui {

// Render the right-column panel stack (PROCESSOR / GPU / MEMORY / DISK /
// NETWORK / SYSTEM) directly onto the given canvas at the given rect.
// Reads `g_ui` visibility flags (show_disk / show_net / show_thermal /
// show_gpumon / system_focus) to choose which panels to show.
void render_right_column(widget::Canvas& canvas,
                         const widget::LayoutRect& rect,
                         const montauk::model::Snapshot& s);

} // namespace montauk::ui
