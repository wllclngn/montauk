#include "util/fmt_double.h"

#include <charconv>

// std::to_chars is locale-independent by definition, which also retires the
// radix-character fixup the JSON face used to need: montauk calls
// setlocale(LC_ALL, "") at startup, so snprintf("%g") under a comma-decimal
// LC_NUMERIC (de_DE, fr_FR) emitted "3,14" and produced invalid JSON.
extern "C" int montauk_fmt_double(char* buf, size_t cap, double v) {
  auto [ptr, ec] = std::to_chars(buf, buf + cap, v);
  if (ec != std::errc{}) return -1;
  return static_cast<int>(ptr - buf);
}
