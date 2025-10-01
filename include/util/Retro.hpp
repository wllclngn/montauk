#pragma once
#include <string>

namespace lsm::util {

// Build a retro‐styled progress bar: [████░░░░] pct%.
// pct in 0..100, width is the number of cells inside the brackets.
// Uses UTF-8 block characters for fill/track by default.
auto retro_bar(double pct, int width = 20, const std::string& fill = "█", const std::string& track = "░") -> std::string;

} // namespace lsm::util
