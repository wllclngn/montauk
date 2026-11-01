#ifndef SUBLIMATION_SINK_H
#define SUBLIMATION_SINK_H

// A buffered output sink, C23 and C++23 alike. The contract is fill-then-drain:
// Build a whole report into one growable buffer, then emit it with a single
// write(). That replaces a scatter of printf/fprintf calls -- each its own
// syscall -- with one buffer and one drain, and gives every language that
// includes it the same bytes.
//
// POD by construction: The struct below uses only C types, so its layout is
// identical in C and C++ and a C++ wrapper can operate on the exact same
// object.
//
// Header-only: Every function is static inline, so there is no link
// dependency -- each TU gets its own internal copies.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>

// Inline small-buffer size. A typical report line is tens of bytes; ~512 keeps
// short emissions allocation-free while staying small on the stack.
#define SUBLIMATION_SINK_SBO 512

typedef struct sublimation_sink {
  char*  data;  // points at sbo while small, heap after the first spill
  size_t len;   // bytes written
  size_t cap;   // capacity of data
  int    fd;    // drain target: 1 = stdout (data), 2 = stderr (logs)
  char   sbo[SUBLIMATION_SINK_SBO];
} sublimation_sink;

static inline void sublimation_sink_init(sublimation_sink* s, int fd) {
  s->data = s->sbo;
  s->len = 0;
  s->cap = SUBLIMATION_SINK_SBO;
  s->fd = fd;
}

// Ensure room for `need` more bytes. 1.5x geometric growth; first spill copies
// the inline store out to the heap. Best-effort: on OOM the write is dropped
// rather than aborting (output is not worth crashing a diagnostic tool over).
static inline void sublimation_sink_reserve(sublimation_sink* s, size_t need) {
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

static inline void sublimation_sink_append(sublimation_sink* s, const char* p, size_t n) {
  sublimation_sink_reserve(s, n);
  if (s->len + n <= s->cap) {
    memcpy(s->data + s->len, p, n);
    s->len += n;
  }
}

static inline void sublimation_sink_appendc(sublimation_sink* s, char c) {
  sublimation_sink_append(s, &c, 1);
}

// printf-style append. Measures with vsnprintf(NULL,0), grows once, formats in.
#if defined(__GNUC__)
__attribute__((format(printf, 2, 3)))
#endif
static inline void sublimation_sink_appendf(sublimation_sink* s, const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  va_list ap2;
  va_copy(ap2, ap);
  int need = vsnprintf(NULL, 0, fmt, ap);
  va_end(ap);
  if (need > 0) {
    sublimation_sink_reserve(s, (size_t)need + 1);  // +1 for vsnprintf's NUL
    if (s->len + (size_t)need < s->cap) {
      vsnprintf(s->data + s->len, (size_t)need + 1, fmt, ap2);
      s->len += (size_t)need;
    }
  }
  va_end(ap2);
}

// Alexandrescu digit-pairs itoa -- C has no std::to_chars, and this beats a
// per-digit loop by formatting two decimal digits per step from a fixed table.
static inline void sublimation_sink_append_u64(sublimation_sink* s, uint64_t v) {
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
  sublimation_sink_append(s, p, (size_t)(tmp + sizeof(tmp) - p));
}

static inline void sublimation_sink_append_i64(sublimation_sink* s, int64_t v) {
  if (v < 0) {
    sublimation_sink_appendc(s, '-');
    sublimation_sink_append_u64(s, (uint64_t)(-(v + 1)) + 1u);  // INT64_MIN-safe
  } else {
    sublimation_sink_append_u64(s, (uint64_t)v);
  }
}

// Drain the buffer to its fd with one (partial-write-safe) write loop, then
// reset length. The backing store is kept for reuse.
static inline void sublimation_sink_drain(sublimation_sink* s) {
  size_t off = 0;
  while (off < s->len) {
    ssize_t n = write(s->fd, s->data + off, s->len - off);
    if (n <= 0) break;  // best-effort
    off += (size_t)n;
  }
  s->len = 0;
}

static inline void sublimation_sink_free(sublimation_sink* s) {
  if (s->data && s->data != s->sbo) free(s->data);
  s->data = s->sbo;
  s->len = 0;
  s->cap = SUBLIMATION_SINK_SBO;
}

// Initialize `s` for `fd` and drain it at exit, so every return path flushes
// what it buffered. atexit takes no argument, so the sinks to drain are held
// here: A few per translation unit, each tool's output sink.
#define SUBLIMATION_SINK_AT_EXIT_MAX 4
static inline sublimation_sink** sublimation_sink_at_exit_slots_(void) {
  static sublimation_sink* slots[SUBLIMATION_SINK_AT_EXIT_MAX];
  return slots;
}
static inline void sublimation_sink_drain_at_exit_(void) {
  sublimation_sink** slots = sublimation_sink_at_exit_slots_();
  for (int i = 0; i < SUBLIMATION_SINK_AT_EXIT_MAX && slots[i]; ++i) sublimation_sink_drain(slots[i]);
}
static inline void sublimation_sink_init_at_exit(sublimation_sink* s, int fd) {
  sublimation_sink_init(s, fd);
  sublimation_sink** slots = sublimation_sink_at_exit_slots_();
  int i = 0;
  while (i < SUBLIMATION_SINK_AT_EXIT_MAX && slots[i] && slots[i] != s) ++i;
  if (i == SUBLIMATION_SINK_AT_EXIT_MAX || slots[i] == s) return;
  if (i == 0) atexit(sublimation_sink_drain_at_exit_);
  slots[i] = s;
}

#endif  // SUBLIMATION_SINK_H
