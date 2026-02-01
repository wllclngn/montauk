#include "util/Retro.hpp"
#include <algorithm>
#include <cmath>

namespace montauk::util {

auto retro_bar(double pct, int width, const std::string& fill, const std::string& track) -> std::string {
  pct = std::clamp(pct, 0.0, 100.0);
  int filled = static_cast<int>(std::round((pct / 100.0) * width));
  if (filled > width) filled = width;
  std::string s;
  s.reserve(width + 10);
  s.push_back(' ');
  for (int i = 0; i < width; ++i) {
    if (i < filled) s += fill; else s += track;
  }
  s.push_back(' ');
  return s;
}

} // namespace montauk::util
