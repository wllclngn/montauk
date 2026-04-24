#pragma once

#include "model/Snapshot.hpp"
#include <string>

namespace montauk::ui {

class HelpOverlay;

// Render one frame of the TUI to stdout. Composes the process table (or the
// help overlay if active) on the left, and the right-column panel stack on
// the right, via the widget::Canvas pipeline. Writes the frame in a single
// atomic stdout write.
//
// help_text + show_help_line: optional status line rendered at the top.
// overlay (may be null): if non-null and visible(), replaces the process
//                        table with the help overlay content.
void render_screen(const montauk::model::Snapshot& s,
                   bool show_help_line,
                   const std::string& help_text,
                   HelpOverlay* overlay = nullptr);

} // namespace montauk::ui
