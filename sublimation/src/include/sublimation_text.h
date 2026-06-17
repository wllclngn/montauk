// sublimation_text.h -- text matching: substring (Boyer-Moore-Horspool) and
// regex (Thompson NFA). This is the order-free, membership side of search --
// the counterpart to the flow model's order/structure side. Both are ported
// 1:1 from montauk's C++ originals; ASCII case-insensitive throughout. Housing
// them here makes sublimation montauk's single search/match/order core: text
// and structure under one roof.
#ifndef SUBLIMATION_TEXT_H
#define SUBLIMATION_TEXT_H

#include <stddef.h>
#include <stdint.h>

#include "internal/c23_compat.h"

#ifdef __cplusplus
extern "C" {
#endif

// ── Boyer-Moore-Horspool literal substring search (ASCII case-insensitive) ──
// Compile a pattern once, search many times. O(1) extra space (a fixed 256-byte
// bad-character table). Average O(n/m) sublinear; worst O(n*m). A pattern longer
// than 256 bytes, or empty, compiles to the "empty pattern" that matches at 0 --
// 1:1 with the C++ original.
#define SUBLIMATION_BMH_MAX_PATTERN 256

typedef struct {
    int           bad_char[256];
    unsigned char pattern[SUBLIMATION_BMH_MAX_PATTERN];
    int           pattern_len;
} sublimation_bmh;

// Compile `pattern` (len bytes) into `out`. len == 0 or len > 256 leaves an
// empty pattern (search returns 0). No allocation; `out` is caller-owned.
SUB_API void sublimation_bmh_compile(sublimation_bmh *out, const char *pattern, size_t len);

// Offset of the first match of the compiled pattern in text[0..n), or -1.
SUB_API long sublimation_bmh_search(const sublimation_bmh *bmh, const char *text, size_t n);

// ── Thompson NFA regex engine (byte-level simulator, UTF-8-aware compiler) ──
// 1:1 C23 port of montauk's ThompsonNFA. Supports  . [] [^] [a-z] * + ? | () ^ $
// and \ (escape). Zero heap during simulation (a uint64_t[4] bitset). O(n*m)
// guaranteed -- no backtracking. The compiled machine is a value object; stack-
// or static-allocate one, compile once, match many.
#define SUBLIMATION_NFA_MAX_STATES 256

typedef struct {
    uint8_t op;         // 0 = CHAR, 1 = CLASS, 2 = SPLIT, 3 = MATCH
    uint8_t ch;         // CHAR: the byte to match
    uint8_t class_idx;  // CLASS: index into classes[]
    uint8_t negated;    // CLASS: negated?
    int16_t out;        // next state (-1 = none)
    int16_t out1;       // SPLIT: second epsilon target (-1 = none)
} sublimation_nfa_state;

typedef struct { uint8_t bits[32]; } sublimation_nfa_class;  // 256-bit set

typedef struct {
    sublimation_nfa_state states[SUBLIMATION_NFA_MAX_STATES];
    int  num_states;
    sublimation_nfa_class classes[SUBLIMATION_NFA_MAX_STATES];
    int  num_classes;
    int  start;
    int  anchored_start;
    int  anchored_end;
    int  valid;
} sublimation_nfa;

// Compile `pattern` (len bytes) into `out`. Check sublimation_nfa_valid() after.
SUB_API void sublimation_nfa_compile(sublimation_nfa *out, const char *pattern, size_t len);

// Did the pattern compile?
SUB_API int sublimation_nfa_valid(const sublimation_nfa *nfa);

// Whole-input match (implicitly anchored ^...$). 1 = match, 0 = not.
SUB_API int sublimation_nfa_full_match(const sublimation_nfa *nfa, const char *input, size_t n);

// First (leftmost-longest) match in input[0..n). Returns the start offset, and
// writes the end offset (exclusive) to *end_out when end_out != NULL. Returns
// -1 with no write on no match.
SUB_API long sublimation_nfa_find(const sublimation_nfa *nfa, const char *input, size_t n, long *end_out);

#ifdef __cplusplus
}
#endif

#endif // SUBLIMATION_TEXT_H
