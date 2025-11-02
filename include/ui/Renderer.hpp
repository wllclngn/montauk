#pragma once

#include "model/Snapshot.hpp"
#include <string>
#include <vector>

namespace montauk::ui {

// Box drawing
std::vector<std::string> make_box(
    const std::string& title, 
    const std::vector<std::string>& lines, 
    int width, 
    int min_height = 0
);

// Line colorization
std::string colorize_line(const std::string& s);

// Frame rendering
void render_screen(const montauk::model::Snapshot& s, bool show_help_line, const std::string& help_text);

// NOTE: render_left_column and render_right_column remain in main.cpp
// They are ~900 lines and tightly coupled to the main rendering loop

} // namespace montauk::ui
