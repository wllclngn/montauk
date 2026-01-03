#pragma once

#include "model/Snapshot.hpp"
#include <string>
#include <vector>

namespace montauk::ui {

// Individual panel renderers
std::vector<std::string> render_gpu_panel(const montauk::model::Snapshot& s, int width);
std::vector<std::string> render_memory_panel(const montauk::model::Snapshot& s, int width);
std::vector<std::string> render_disk_panel(const montauk::model::Snapshot& s, int width);
std::vector<std::string> render_network_panel(const montauk::model::Snapshot& s, int width);
std::vector<std::string> render_system_panel(const montauk::model::Snapshot& s, int width, int target_rows);

// Main orchestrator
std::vector<std::string> render_right_column(const montauk::model::Snapshot& s, int width, int target_rows);

} // namespace montauk::ui
