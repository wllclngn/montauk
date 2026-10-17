// sublimation_fmt.h -- the one double formatter.
//
// Shortest round-trip text for a binary64, byte for byte what
// std::to_chars(first, last, value) writes: The fewest digits that parse back
// to the same double, in fixed or scientific notation, whichever is shorter
// (fixed on a tie). Locale-independent by construction, so a comma-decimal
// LC_NUMERIC cannot turn a number into invalid JSON. Every face that renders
// a double calls this, which is what lets two faces never disagree about one.
#ifndef SUBLIMATION_FMT_H
#define SUBLIMATION_FMT_H

#include <stddef.h>

#include "internal/c23_compat.h"   // SUB_API

#ifdef __cplusplus
extern "C" {
#endif

// Writes at most `cap` bytes, NOT null-terminated. Returns the number written,
// or -1 if the buffer was too small. 32 bytes is always enough for a double.
SUB_API int sublimation_fmt_double(char *buf, size_t cap, double v);

#ifdef __cplusplus
}
#endif

#endif // SUBLIMATION_FMT_H
