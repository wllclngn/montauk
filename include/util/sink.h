#ifndef MONTAUK_UTIL_SINK_H
#define MONTAUK_UTIL_SINK_H

// A buffered output sink shared by montauk (C++23) and the sublimation CLI
// (C23). The contract is fill-then-drain: build a whole report into one
// growable buffer, then emit it with a single write(). That replaces the
// scatter of printf/std::printf/fprintf calls -- each its own syscall -- with
// one buffer and one drain, and gives both languages the same bytes.
//
// POD by construction: the struct below uses only C types, so its layout is
// identical in C and C++ and the two front-ends operate on the exact same
// object. The C front-end (append / appendf / append_u64) is plain static
// inline; the C++ front-end is a thin RAII wrapper that also models a
// back-insert container so std::format_to(std::back_inserter(sink), ...) works.
//
// Header-only: every function is static inline, so there is no link
// dependency -- the C TU and the C++ TU each get their own internal copies.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>

// Inline small-buffer size. A typical report line is tens of bytes; ~512 keeps
// short emissions allocation-free while staying small on the stack.
#define MONTAUK_SINK_SBO 512

typedef struct montauk_sink {
  char*  data;  // points at sbo while small, heap after the first spill
  size_t len;   // bytes written
  size_t cap;   // capacity of data
  int    fd;    // drain target: 1 = stdout (data), 2 = stderr (logs)
  char   sbo[MONTAUK_SINK_SBO];
} montauk_sink;

static inline void montauk_sink_init(montauk_sink* s, int fd) {
  s->data = s->sbo;
  s->len = 0;
  s->cap = MONTAUK_SINK_SBO;
  s->fd = fd;
}

// Ensure room for `need` more bytes. 1.5x geometric growth; first spill copies
// the inline store out to the heap. Best-effort: on OOM the write is dropped
// rather than aborting (output is not worth crashing a diagnostic tool over).
static inline void montauk_sink_reserve(montauk_sink* s, size_t need) {
  if (s->len + need <= s->cap) return;
  size_t ncap = s->cap + s->cap / 2;
  if (ncap < s->len + need) ncap = s->len + need;
  char* nd;
  if (s->data == s->sbo) {
    nd = (char*)malloc(ncap);
    if (nd) memcpy(nd, s->sbo, s->len);
  } else {
    nd = (char*)realloc(s->data, ncap);
  }
  if (!nd) return;
  s->data = nd;
  s->cap = ncap;
}

static inline void montauk_sink_append(montauk_sink* s, const char* p, size_t n) {
  montauk_sink_reserve(s, n);
  if (s->len + n <= s->cap) {
    memcpy(s->data + s->len, p, n);
    s->len += n;
  }
}

static inline void montauk_sink_appendc(montauk_sink* s, char c) {
  montauk_sink_append(s, &c, 1);
}

// printf-style append. Measures with vsnprintf(NULL,0), grows once, formats in.
#if defined(__GNUC__)
__attribute__((format(printf, 2, 3)))
#endif
static inline void montauk_sink_appendf(montauk_sink* s, const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  va_list ap2;
  va_copy(ap2, ap);
  int need = vsnprintf(NULL, 0, fmt, ap);
  va_end(ap);
  if (need > 0) {
    montauk_sink_reserve(s, (size_t)need + 1);  // +1 for vsnprintf's NUL
    if (s->len + (size_t)need < s->cap) {
      vsnprintf(s->data + s->len, (size_t)need + 1, fmt, ap2);
      s->len += (size_t)need;
    }
  }
  va_end(ap2);
}

// Alexandrescu digit-pairs itoa -- C has no std::to_chars, and this beats a
// per-digit loop by formatting two decimal digits per step from a fixed table.
static inline void montauk_sink_append_u64(montauk_sink* s, uint64_t v) {
  static const char D[201] =
      "0001020304050607080910111213141516171819"
      "2021222324252627282930313233343536373839"
      "4041424344454647484950515253545556575859"
      "6061626364656667686970717273747576777879"
      "8081828384858687888990919293949596979899";
  char tmp[20];  // 2^64-1 is 20 digits
  char* p = tmp + sizeof(tmp);
  while (v >= 100) {
    unsigned idx = (unsigned)((v % 100) * 2);
    v /= 100;
    *--p = D[idx + 1];
    *--p = D[idx];
  }
  if (v >= 10) {
    unsigned idx = (unsigned)(v * 2);
    *--p = D[idx + 1];
    *--p = D[idx];
  } else {
    *--p = (char)('0' + v);
  }
  montauk_sink_append(s, p, (size_t)(tmp + sizeof(tmp) - p));
}

static inline void montauk_sink_append_i64(montauk_sink* s, int64_t v) {
  if (v < 0) {
    montauk_sink_appendc(s, '-');
    montauk_sink_append_u64(s, (uint64_t)(-(v + 1)) + 1u);  // INT64_MIN-safe
  } else {
    montauk_sink_append_u64(s, (uint64_t)v);
  }
}

// Drain the buffer to its fd with one (partial-write-safe) write loop, then
// reset length. The backing store is kept for reuse.
static inline void montauk_sink_drain(montauk_sink* s) {
  size_t off = 0;
  while (off < s->len) {
    ssize_t n = write(s->fd, s->data + off, s->len - off);
    if (n <= 0) break;  // best-effort
    off += (size_t)n;
  }
  s->len = 0;
}

static inline void montauk_sink_free(montauk_sink* s) {
  if (s->data && s->data != s->sbo) free(s->data);
  s->data = s->sbo;
  s->len = 0;
  s->cap = MONTAUK_SINK_SBO;
}

#ifdef __cplusplus

namespace montauk {

// RAII C++ front-end over the same POD. Drains and frees on scope exit (the
// fill-then-drain final flush), and models a back-insert container so
// std::format_to(std::back_inserter(sink), "...", args) appends into it.
struct Sink {
  montauk_sink s;

  explicit Sink(int fd = 1) { montauk_sink_init(&s, fd); }
  ~Sink() { montauk_sink_drain(&s); montauk_sink_free(&s); }
  Sink(const Sink&) = delete;
  Sink& operator=(const Sink&) = delete;

  // back_insert_iterator contract: value_type + push_back.
  using value_type = char;
  void push_back(char c) { montauk_sink_appendc(&s, c); }

  void append(const char* p, size_t n) { montauk_sink_append(&s, p, n); }
  void append(const char* z) { montauk_sink_append(&s, z, ::strlen(z)); }
  void drain() { montauk_sink_drain(&s); }

  size_t size() const { return s.len; }
  const char* data() const { return s.data; }
};

}  // namespace montauk

#endif  // __cplusplus

#endif  // MONTAUK_UTIL_SINK_H
