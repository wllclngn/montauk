#pragma once

#include "model/Snapshot.hpp"
#include <string>
#include <vector>

namespace montauk::ui {

// Process table rendering
std::vector<std::string> render_process_table(
    const montauk::model::Snapshot& s, 
    int width, 
    int target_rows
);

} // namespace montauk::ui
