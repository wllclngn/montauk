// Proves include/util/sink.h is valid C23 and the C front-end works on the
// same POD the C++ side uses. Compiled with -std=c23; exits non-zero on
// mismatch. The C++ behaviour is covered by test_sink.cpp.

#include "util/sink.h"
#include <assert.h>
#include <string.h>

static char captured[256];
static size_t captured_len;

static size_t drain_to_mem(montauk_sink* s) {
  // Copy the buffer out instead of writing to an fd, so the check is hermetic.
  size_t n = s->len < sizeof(captured) ? s->len : sizeof(captured);
  memcpy(captured, s->data, n);
  captured_len = n;
  s->len = 0;
  return n;
}

int main(void) {
  montauk_sink s;
  montauk_sink_init(&s, 1);

  montauk_sink_append(&s, "x=", 2);
  montauk_sink_append_u64(&s, 18446744073709551615ull);
  montauk_sink_appendc(&s, ' ');
  montauk_sink_appendf(&s, "%s=%d", "k", -7);
  drain_to_mem(&s);
  assert(captured_len == strlen("x=18446744073709551615 k=-7"));
  assert(memcmp(captured, "x=18446744073709551615 k=-7", captured_len) == 0);

  // Grow past the inline store.
  for (int i = 0; i < 1000; ++i) montauk_sink_append_u64(&s, (uint64_t)i);
  assert(s.cap > MONTAUK_SINK_SBO);
  assert(s.data != s.sbo);
  montauk_sink_free(&s);
  assert(s.data == s.sbo);

  return 0;
}
