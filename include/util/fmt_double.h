#pragma once
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// THE one double formatter for every montauk face.
//
// The JSON face used snprintf("%.12g") while the Prometheus face used
// std::to_chars, and those are not the same string: %.12g truncates at twelve
// significant digits, to_chars is shortest round-trip. 1/3 rendered as
// 0.333333333333 in JSON and 0.3333333333333333 in Prometheus, off the SAME
// computed double. The README's claim that the surfaces "cannot disagree on a
// number" was true of the computation and false of the rendering.
//
// One function, called by both, is what makes the claim true. It is C-callable
// because util/json.h is a C header (tests/test_json.c compiles it as C23) while
// std::to_chars is C++; the implementation lives in a C++ TU.
//
// Writes at most `cap` bytes, NOT null-terminated. Returns the number written,
// or -1 if the buffer was too small. 32 bytes is always enough for a double.
int montauk_fmt_double(char* buf, size_t cap, double v);

#ifdef __cplusplus
}
#endif
