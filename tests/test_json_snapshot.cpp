// The two RENDERING FACES of one computed value must agree.
//
// This file used to freeze snapshot_to_json / snapshot_to_prometheus /
// trace_to_prometheus / trace_to_json byte-identically against goldens captured
// before the renderer-unification refactor. THOSE GOLDENS ARE GONE (v8.13.0).
// They were red from 8.9.0 through the whole of v8.10.0 without anyone noticing,
// because the build directory had MONTAUK_BUILD_TESTS=OFF -- and the one real
// defect in this area was invisible to them by construction: the JSON face
// formatted 1/3 as 0.333333333333 while the Prometheus face wrote
// 0.3333333333333333, and each face was frozen against ITSELF, so both compared
// "correct" and neither was ever compared to the other. Declared-structure
// coverage is montauk --static's job now; what belongs here is the PROPERTY a
// frozen blob could not express.
#include "minitest.hpp"
#include "util/fmt_double.h"
#include "util/json.h"

#include <cstring>
#include <string>

// THE TWO FACES MUST FORMAT ONE DOUBLE ONE WAY.
//
// The JSON face used snprintf("%.12g") while the Prometheus face used
// std::to_chars, so one computed double rendered as two different strings --
// 1/3 as 0.333333333333 in JSON and 0.3333333333333333 in Prometheus. The
// byte-identical goldens could not catch it: each face was frozen against
// itself, so both were "correct" and neither was ever compared to the other.
//
// Both now call montauk_fmt_double, so the property to hold down is that the
// shared formatter is shortest round-trip and that the JSON face actually uses
// it. The Prometheus face calls the same function.
//
// An earlier version of this test scraped numeric literals out of the rendered
// text with a hand-rolled scanner. That scanner had an infinite loop on a date
// like 2026-08-17 and hung the suite. A test for a simple property should not
// need a parser -- this one asserts the property at the source instead.
TEST(shared_double_formatter_is_shortest_round_trip) {
  static const double vals[] = {
    1.0 / 3.0, 2.0 / 3.0, 0.1, 0.2, 0.3, 1.5, 100.0, 0.0, -0.0,
    3.141592653589793, 123456789.12345679, 1e30, 1e-30, 1e308, 5e-324, -2.5,
  };
  for (double v : vals) {
    char buf[40];
    int n = montauk_fmt_double(buf, sizeof buf, v);
    ASSERT_TRUE(n > 0);
    std::string got(buf, (size_t)n);
    // Shortest ROUND-TRIP: the text must read back as the identical double.
    // %.12g fails this on 1/3, which is the defect that started this.
    ASSERT_EQ(strtod(got.c_str(), nullptr), v);
    // And it must be canonical -- reformatting its own output is a fixed point,
    // so no caller can produce two spellings of one value.
    char again[40];
    int n2 = montauk_fmt_double(again, sizeof again, strtod(got.c_str(), nullptr));
    ASSERT_EQ(std::string(again, (size_t)n2), got);
  }
}

TEST(json_face_uses_the_shared_double_formatter) {
  static const double vals[] = {1.0 / 3.0, 0.1, 123456789.12345679, 1e30, -2.5};
  for (double v : vals) {
    montauk_sink sink;
    montauk_sink_init(&sink, -1);
    montauk_json j;
    montauk_json_init(&j, &sink);
    montauk_json_num(&j, v);

    char buf[40];
    int n = montauk_fmt_double(buf, sizeof buf, v);
    ASSERT_EQ(std::string(sink.data, sink.len), std::string(buf, (size_t)n));
    montauk_sink_free(&sink);
  }
}
