#ifndef MONTAUK_UTIL_SINK_H
#define MONTAUK_UTIL_SINK_H

// montauk's C++ front-end over sublimation's output sink (sublimation_sink.h),
// which owns the buffer, its growth and its drain.

#include "sublimation_sink.h"

#ifdef __cplusplus

namespace montauk {

// RAII C++ front-end over the same POD. Drains and frees on scope exit (the
// fill-then-drain final flush), and models a back-insert container so
// std::format_to(std::back_inserter(sink), "...", args) appends into it.
struct Sink {
  sublimation_sink s;

  explicit Sink(int fd = 1) { sublimation_sink_init(&s, fd); }
  ~Sink() { sublimation_sink_drain(&s); sublimation_sink_free(&s); }
  Sink(const Sink&) = delete;
  Sink& operator=(const Sink&) = delete;

  // back_insert_iterator contract: value_type + push_back.
  using value_type = char;
  void push_back(char c) { sublimation_sink_appendc(&s, c); }

  void append(const char* p, size_t n) { sublimation_sink_append(&s, p, n); }
  void append(const char* z) { sublimation_sink_append(&s, z, ::strlen(z)); }

  size_t size() const { return s.len; }
  const char* data() const { return s.data; }
};

}  // namespace montauk

#endif  // __cplusplus

#endif  // MONTAUK_UTIL_SINK_H
