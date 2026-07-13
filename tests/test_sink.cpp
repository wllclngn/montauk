// montauk_sink (C++ side): append/format/grow-past-SBO behavior of the
// shared C23/C++23 output sink.
#include "minitest.hpp"
#include "util/sink.h"

#include <format>
#include <iterator>
#include <string>
#include <stdexcept>
#include <cstdio>
#include <unistd.h>

// Drain to a pipe and read it back, so we assert the exact bytes the sink
// emits (not just its internal buffer).
static std::string drained_bytes(montauk::Sink& sink) {
  int fds[2];
  if (::pipe(fds) != 0) throw std::runtime_error("pipe");
  sink.s.fd = fds[1];
  montauk_sink_drain(&sink.s);
  ::close(fds[1]);
  std::string out;
  char buf[4096];
  ssize_t n;
  while ((n = ::read(fds[0], buf, sizeof(buf))) > 0) out.append(buf, (size_t)n);
  ::close(fds[0]);
  return out;
}

TEST(sink_append_and_drain) {
  montauk::Sink sink;
  sink.append("hello ");
  sink.append("world", 5);
  ASSERT_EQ(sink.size(), 11u);
  ASSERT_EQ(drained_bytes(sink), std::string("hello world"));
}

TEST(sink_format_to_back_inserter) {
  montauk::Sink sink;
  std::format_to(std::back_inserter(sink), "n={} s={} x={:#x}\n", 42, "abc", 255);
  ASSERT_EQ(drained_bytes(sink), std::string("n=42 s=abc x=0xff\n"));
}

TEST(sink_grows_past_sbo) {
  montauk::Sink sink;
  std::string expect;
  for (int i = 0; i < 2000; ++i) {  // far past the 512B inline store
    std::format_to(std::back_inserter(sink), "{},", i);
    expect += std::to_string(i) + ",";
  }
  ASSERT_TRUE(sink.size() > MONTAUK_SINK_SBO);
  ASSERT_EQ(drained_bytes(sink), expect);
}

TEST(sink_u64_matches_snprintf) {
  const uint64_t vals[] = {0, 7, 10, 99, 100, 12345, 9999999999ull,
                           18446744073709551615ull};
  for (uint64_t v : vals) {
    montauk::Sink sink;
    montauk_sink_append_u64(&sink.s, v);
    char ref[32];
    std::snprintf(ref, sizeof(ref), "%llu", (unsigned long long)v);
    ASSERT_EQ(drained_bytes(sink), std::string(ref));
  }
}

TEST(sink_i64_signed) {
  montauk::Sink sink;
  montauk_sink_append_i64(&sink.s, -9223372036854775807LL - 1);  // INT64_MIN
  ASSERT_EQ(drained_bytes(sink), std::string("-9223372036854775808"));
}

TEST(sink_appendf) {
  montauk::Sink sink;
  montauk_sink_appendf(&sink.s, "%s=%d %.2f", "k", 5, 1.5);
  ASSERT_EQ(drained_bytes(sink), std::string("k=5 1.50"));
}
