#pragma once
#include <string_view>

namespace montauk::util {

// `v` without the whitespace at either end: spaces, tabs, CR, LF, VT and FF.
[[nodiscard]] constexpr std::string_view trim(std::string_view v) {
  constexpr std::string_view ws = " \t\r\n\v\f";
  const size_t b = v.find_first_not_of(ws);
  if (b == std::string_view::npos) return {};
  return v.substr(b, v.find_last_not_of(ws) - b + 1);
}

} // namespace montauk::util
