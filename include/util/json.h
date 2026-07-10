// json.h -- write-only JSON serializer on the montauk sink.
//
// The JSON analog of the sink's text/appendf formatting: a thin state machine that
// emits well-formed JSON through montauk_sink, handling comma placement and string
// escaping. No DOM, no parsing, no third-party dependency -- montauk only ever WRITES
// JSON (an agent reads it). Header-only, static inline, like sink.h.
//
// Comma model: keys are the comma points in an object, elements are the comma points
// in an array. A value emitted right after a key (an object member's value) takes no
// comma; mj_pre_ suppresses it via after_key.
#pragma once
#include "util/sink.h"
#include <stdint.h>
#include <stdio.h>
#include <locale.h>
#include <float.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MONTAUK_JSON_MAX_DEPTH 32

typedef struct montauk_json {
  montauk_sink* sink;
  int depth;
  int after_key;                                   // next value is a key's value: no comma
  unsigned char has_member[MONTAUK_JSON_MAX_DEPTH]; // per level: has a member been written?
} montauk_json;

static inline void montauk_json_init(montauk_json* j, montauk_sink* s) {
  j->sink = s; j->depth = 0; j->after_key = 0;
}

// Comma-before-value for array elements and top-level; suppressed for a key's value.
static inline void mj_pre_(montauk_json* j) {
  if (j->after_key) { j->after_key = 0; return; }
  if (j->depth == 0) return;
  int lvl = j->depth - 1;
  if (lvl >= MONTAUK_JSON_MAX_DEPTH) return;  // past tracked depth: skip comma bookkeeping, never index OOB
  if (j->has_member[lvl]) montauk_sink_appendc(j->sink, ',');
  j->has_member[lvl] = 1;
}

// Escaped JSON string literal ("..."), UTF-8 bytes passed through verbatim.
static inline void mj_rawstr_(montauk_json* j, const char* s) {
  static const char hex[] = "0123456789abcdef";
  montauk_sink_appendc(j->sink, '"');
  for (const unsigned char* p = (const unsigned char*)s; *p; ++p) {
    unsigned char c = *p;
    switch (c) {
      case '"':  montauk_sink_append(j->sink, "\\\"", 2); break;
      case '\\': montauk_sink_append(j->sink, "\\\\", 2); break;
      case '\n': montauk_sink_append(j->sink, "\\n", 2); break;
      case '\t': montauk_sink_append(j->sink, "\\t", 2); break;
      case '\r': montauk_sink_append(j->sink, "\\r", 2); break;
      case '\b': montauk_sink_append(j->sink, "\\b", 2); break;
      case '\f': montauk_sink_append(j->sink, "\\f", 2); break;
      default:
        if (c < 0x20) {
          char buf[6] = { '\\', 'u', '0', '0', hex[(c >> 4) & 0xf], hex[c & 0xf] };
          montauk_sink_append(j->sink, buf, 6);
        } else {
          montauk_sink_appendc(j->sink, (char)c);  // printable ASCII or UTF-8 continuation
        }
    }
  }
  montauk_sink_appendc(j->sink, '"');
}

// A key inside an object: comma if the object already has a member, then "key":.
static inline void montauk_json_key(montauk_json* j, const char* k) {
  int lvl = j->depth - 1;
  if (lvl >= 0 && lvl < MONTAUK_JSON_MAX_DEPTH) {
    if (j->has_member[lvl]) montauk_sink_appendc(j->sink, ',');
    j->has_member[lvl] = 1;
  }
  mj_rawstr_(j, k);
  montauk_sink_appendc(j->sink, ':');
  j->after_key = 1;
}

static inline void montauk_json_obj_begin(montauk_json* j) {
  mj_pre_(j);
  montauk_sink_appendc(j->sink, '{');
  if (j->depth < MONTAUK_JSON_MAX_DEPTH) j->has_member[j->depth] = 0;
  j->depth++;
}
static inline void montauk_json_obj_end(montauk_json* j) {
  if (j->depth > 0) j->depth--;
  montauk_sink_appendc(j->sink, '}');
}
static inline void montauk_json_arr_begin(montauk_json* j) {
  mj_pre_(j);
  montauk_sink_appendc(j->sink, '[');
  if (j->depth < MONTAUK_JSON_MAX_DEPTH) j->has_member[j->depth] = 0;
  j->depth++;
}
static inline void montauk_json_arr_end(montauk_json* j) {
  if (j->depth > 0) j->depth--;
  montauk_sink_appendc(j->sink, ']');
}

static inline void montauk_json_str(montauk_json* j, const char* s) { mj_pre_(j); mj_rawstr_(j, s); }
static inline void montauk_json_u64(montauk_json* j, uint64_t v)    { mj_pre_(j); montauk_sink_append_u64(j->sink, v); }
static inline void montauk_json_i64(montauk_json* j, int64_t v)     { mj_pre_(j); montauk_sink_append_i64(j->sink, v); }
static inline void montauk_json_bool(montauk_json* j, int b)        { mj_pre_(j); montauk_sink_append(j->sink, b ? "true" : "false", b ? 4u : 5u); }
static inline void montauk_json_null(montauk_json* j)              { mj_pre_(j); montauk_sink_append(j->sink, "null", 4); }
static inline void montauk_json_num(montauk_json* j, double v) {
  mj_pre_(j);
  // JSON has no NaN / Infinity -- the only valid encoding is null. Guard on the
  // true bounds (DBL_MAX), so a large-but-finite double still formats.
  if (v != v || v > DBL_MAX || v < -DBL_MAX) { montauk_sink_append(j->sink, "null", 4); return; }
  // Format locale-independently. montauk calls setlocale(LC_ALL,"") at startup,
  // so under a comma-decimal LC_NUMERIC (de_DE, fr_FR, ...) "%g" would emit
  // "3,14" -- invalid JSON. Format, then normalize the locale radix char to '.'
  // (%g emits no thousands separators, so the radix is the only locale artifact;
  // in the C locale decimal_point is "." and this is a no-op).
  char buf[32];
  int n = snprintf(buf, sizeof buf, "%.12g", v);
  if (n < 0) { montauk_sink_append(j->sink, "null", 4); return; }
  if (n > (int)sizeof buf - 1) n = (int)sizeof buf - 1;
  const char* dp = localeconv()->decimal_point;
  if (dp && dp[0] && dp[0] != '.')
    for (int i = 0; i < n; ++i) if (buf[i] == dp[0]) { buf[i] = '.'; break; }
  montauk_sink_append(j->sink, buf, (unsigned)n);
}

// key + value convenience pairs (the common case)
static inline void montauk_json_kstr(montauk_json* j, const char* k, const char* v) { montauk_json_key(j, k); montauk_json_str(j, v); }
static inline void montauk_json_ku64(montauk_json* j, const char* k, uint64_t v)    { montauk_json_key(j, k); montauk_json_u64(j, v); }
static inline void montauk_json_ki64(montauk_json* j, const char* k, int64_t v)     { montauk_json_key(j, k); montauk_json_i64(j, v); }
static inline void montauk_json_knum(montauk_json* j, const char* k, double v)      { montauk_json_key(j, k); montauk_json_num(j, v); }
static inline void montauk_json_kbool(montauk_json* j, const char* k, int b)        { montauk_json_key(j, k); montauk_json_bool(j, b); }

#ifdef __cplusplus
}
#endif
