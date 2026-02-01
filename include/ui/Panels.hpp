#pragma once

#include "model/Snapshot.hpp"
#include <string>
#include <vector>

namespace montauk::ui {

std::vector<std::string> render_right_column(const montauk::model::Snapshot& s, int width, int target_rows);

} // namespace montauk::ui
