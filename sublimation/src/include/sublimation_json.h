// sublimation_json.h -- write-only JSON serializer on the sublimation sink.
//
// The JSON analog of the sink's text/appendf formatting: A thin state machine
// that emits well-formed JSON through sublimation_sink, handling comma placement
// and string escaping. No DOM, no parsing, no third-party dependency -- its
// callers only ever WRITE JSON. Header-only, static inline, like the sink.
//
// Comma model: Keys are the comma points in an object, elements are the comma
// points in an array. A value emitted right after a key (an object member's
// value) takes no comma; sublimation_json_pre_ suppresses it via after_key.
#ifndef SUBLIMATION_JSON_H
#define SUBLIMATION_JSON_H

#include "sublimation_sink.h"
#include "sublimation_fmt.h"
#include <stdint.h>
#include <float.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SUBLIMATION_JSON_MAX_DEPTH 32

typedef struct sublimation_json {
  sublimation_sink* sink;
  int depth;
  int after_key;                                       // next value is a key's value: no comma
  unsigned char has_member[SUBLIMATION_JSON_MAX_DEPTH]; // per level: has a member been written?
} sublimation_json;

static inline void sublimation_json_init(sublimation_json* j, sublimation_sink* s) {
  j->sink = s; j->depth = 0; j->after_key = 0;
}

// Comma-before-value for array elements and top-level; suppressed for a key's value.
static inline void sublimation_json_pre_(sublimation_json* j) {
  if (j->after_key) { j->after_key = 0; return; }
  if (j->depth == 0) return;
  int lvl = j->depth - 1;
  if (lvl >= SUBLIMATION_JSON_MAX_DEPTH) return;  // past tracked depth: skip comma bookkeeping, never index OOB
  if (j->has_member[lvl]) sublimation_sink_appendc(j->sink, ',');
  j->has_member[lvl] = 1;
}

// Escaped JSON string literal ("..."), UTF-8 bytes passed through verbatim.
static inline void sublimation_json_rawstr_(sublimation_json* j, const char* s) {
  static const char hex[] = "0123456789abcdef";
  sublimation_sink_appendc(j->sink, '"');
  for (const unsigned char* p = (const unsigned char*)s; *p; ++p) {
    unsigned char c = *p;
    switch (c) {
      case '"':  sublimation_sink_append(j->sink, "\\\"", 2); break;
      case '\\': sublimation_sink_append(j->sink, "\\\\", 2); break;
      case '\n': sublimation_sink_append(j->sink, "\\n", 2); break;
      case '\t': sublimation_sink_append(j->sink, "\\t", 2); break;
      case '\r': sublimation_sink_append(j->sink, "\\r", 2); break;
      case '\b': sublimation_sink_append(j->sink, "\\b", 2); break;
      case '\f': sublimation_sink_append(j->sink, "\\f", 2); break;
      default:
        if (c < 0x20) {
          char buf[6] = { '\\', 'u', '0', '0', hex[(c >> 4) & 0xf], hex[c & 0xf] };
          sublimation_sink_append(j->sink, buf, 6);
        } else {
          sublimation_sink_appendc(j->sink, (char)c);  // printable ASCII or UTF-8 continuation
        }
    }
  }
  sublimation_sink_appendc(j->sink, '"');
}

// A key inside an object: comma if the object already has a member, then "key":.
static inline void sublimation_json_key(sublimation_json* j, const char* k) {
  int lvl = j->depth - 1;
  if (lvl >= 0 && lvl < SUBLIMATION_JSON_MAX_DEPTH) {
    if (j->has_member[lvl]) sublimation_sink_appendc(j->sink, ',');
    j->has_member[lvl] = 1;
  }
  sublimation_json_rawstr_(j, k);
  sublimation_sink_appendc(j->sink, ':');
  j->after_key = 1;
}

static inline void sublimation_json_obj_begin(sublimation_json* j) {
  sublimation_json_pre_(j);
  sublimation_sink_appendc(j->sink, '{');
  if (j->depth < SUBLIMATION_JSON_MAX_DEPTH) j->has_member[j->depth] = 0;
  j->depth++;
}
static inline void sublimation_json_obj_end(sublimation_json* j) {
  if (j->depth > 0) j->depth--;
  sublimation_sink_appendc(j->sink, '}');
}
static inline void sublimation_json_arr_begin(sublimation_json* j) {
  sublimation_json_pre_(j);
  sublimation_sink_appendc(j->sink, '[');
  if (j->depth < SUBLIMATION_JSON_MAX_DEPTH) j->has_member[j->depth] = 0;
  j->depth++;
}
static inline void sublimation_json_arr_end(sublimation_json* j) {
  if (j->depth > 0) j->depth--;
  sublimation_sink_appendc(j->sink, ']');
}

static inline void sublimation_json_str(sublimation_json* j, const char* s) { sublimation_json_pre_(j); sublimation_json_rawstr_(j, s); }
static inline void sublimation_json_u64(sublimation_json* j, uint64_t v)    { sublimation_json_pre_(j); sublimation_sink_append_u64(j->sink, v); }
static inline void sublimation_json_i64(sublimation_json* j, int64_t v)     { sublimation_json_pre_(j); sublimation_sink_append_i64(j->sink, v); }
static inline void sublimation_json_bool(sublimation_json* j, int b)        { sublimation_json_pre_(j); sublimation_sink_append(j->sink, b ? "true" : "false", b ? 4u : 5u); }
static inline void sublimation_json_null(sublimation_json* j)              { sublimation_json_pre_(j); sublimation_sink_append(j->sink, "null", 4); }
static inline void sublimation_json_num(sublimation_json* j, double v) {
  sublimation_json_pre_(j);
  // JSON has no NaN / Infinity -- the only valid encoding is null. Guard on the
  // true bounds (DBL_MAX), so a large-but-finite double still formats.
  if (v != v || v > DBL_MAX || v < -DBL_MAX) { sublimation_sink_append(j->sink, "null", 4); return; }
  // The one double formatter (sublimation_fmt.h), shortest round-trip and
  // locale-independent, so no face renders the same double two ways.
  char buf[32];
  int n = sublimation_fmt_double(buf, sizeof buf, v);
  if (n < 0) { sublimation_sink_append(j->sink, "null", 4); return; }
  sublimation_sink_append(j->sink, buf, (unsigned)n);
}

// key + value convenience pairs (the common case)
static inline void sublimation_json_kstr(sublimation_json* j, const char* k, const char* v) { sublimation_json_key(j, k); sublimation_json_str(j, v); }
static inline void sublimation_json_ku64(sublimation_json* j, const char* k, uint64_t v)    { sublimation_json_key(j, k); sublimation_json_u64(j, v); }
static inline void sublimation_json_ki64(sublimation_json* j, const char* k, int64_t v)     { sublimation_json_key(j, k); sublimation_json_i64(j, v); }
static inline void sublimation_json_knum(sublimation_json* j, const char* k, double v)      { sublimation_json_key(j, k); sublimation_json_num(j, v); }
static inline void sublimation_json_kbool(sublimation_json* j, const char* k, int b)        { sublimation_json_key(j, k); sublimation_json_bool(j, b); }

#ifdef __cplusplus
}
#endif

#endif  // SUBLIMATION_JSON_H
