// sublimation_text.h -- text search: the tri-face matcher (sublimation_search).
// One engine, three faces (exact/anchor, regex, fuzzy k-mismatch) under a
// classify-dispatch front end with a data-relative rare-byte prefilter. This is
// sublimation's text search/match side, the counterpart to the sort core's
// order/structure side; the two under one roof make sublimation montauk's single
// search/match/order core.
#ifndef SUBLIMATION_TEXT_H
#define SUBLIMATION_TEXT_H

#include <stddef.h>
#include <stdint.h>

#include "internal/c23_compat.h"

#ifdef __cplusplus
extern "C" {
#endif

// Flow-dual text matcher (sublimation_search). One compiled program covers three
// faces, selected at compile time: exact/anchor (FIXED), regex (Glushkov
// bit-parallel field, the default) and fuzzy k-mismatch (k > 0). The program is a
// value object -- stack- or static-allocate one, compile once, match/count many.
// Per-call scratch (the field's reach cache, the fuzzy dedup array) is allocated
// and freed inside find/count; the program itself never heap-allocates.
#define SUBLIMATION_SEARCH_MAX_PATTERN 1023
#define SUBLIMATION_SEARCH_MAX_POS     64    // Glushkov positions (bits in the field)

enum {
    SUBLIMATION_SEARCH_FIXED = 1u,   // literal/anchor face (default is regex)
    SUBLIMATION_SEARCH_ICASE = 2u    // ASCII case-fold at match time (A-Z == a-z)
};

// The compiled Glushkov position-NFA, simulated as a bit-vector field. Internal
// to the search program; exposed only so sublimation_search is a complete value
// type the caller can stack/static-allocate.
typedef struct {
    uint8_t  setb[SUBLIMATION_SEARCH_MAX_POS][32];  // byte-set per position
    uint64_t follow[SUBLIMATION_SEARCH_MAX_POS];    // positions that may follow i
    uint64_t first, last;                           // start / accept position sets
    int npos, nullable_all, ok;
    int anchored_start, anchored_end;               // leading ^ / trailing $
} sublimation_search_gnfa;

typedef struct {
    sublimation_search_gnfa g;                          // regex program (REGEX mode)
    char    pattern[SUBLIMATION_SEARCH_MAX_PATTERN + 1];// NUL-terminated source
    size_t  pattern_len;
    int     k;      // fuzzy Hamming threshold (0 = exact/regex)
    int     mode;   // 0 = exact, 1 = regex, 2 = fuzzy (internal)
    int     icase;
    int     valid;
} sublimation_search;

// Compile `pattern` (len bytes) into `out`. `flags` selects the face
// (SUBLIMATION_SEARCH_FIXED / _ICASE); default (0) is regex. k > 0 selects the
// fuzzy face (k == 0 is exact/regex). No allocation; `out` is caller-owned. Check
// sublimation_search_valid() afterward.
SUB_API void sublimation_search_compile(sublimation_search *out, const char *pattern,
                                        size_t len, unsigned flags, int k);

// Did the pattern compile?
SUB_API int sublimation_search_valid(const sublimation_search *s);

// Whole-input match (implicitly anchored ^...$). 1 = match, 0 = not.
SUB_API int sublimation_search_full_match(const sublimation_search *s, const char *input, size_t n);

// Leftmost match in input[0..n). Returns the start offset (or -1), and writes the
// end offset (exclusive) to *end_out when end_out != NULL.
SUB_API long sublimation_search_find(const sublimation_search *s, const char *input, size_t n,
                                     long *end_out);

// As sublimation_search_find, but only considers matches starting at or after
// `from`; anchors stay absolute (^ matches only at offset 0 of input, $ only at
// n). Continuation-safe. Returns absolute offsets.
SUB_API long sublimation_search_find_from(const sublimation_search *s, const char *input, size_t n,
                                          size_t from, long *end_out);

// Count all matches in input[0..n). Exact: overlapping occurrences. Regex: match-
// end positions. Fuzzy: windows within k mismatches. Optimizations (regex literal
// prefilter, fuzzy pigeonhole prefilter) are internal and never change the count.
SUB_API size_t sublimation_search_count(const sublimation_search *s, const char *input, size_t n);

#ifdef __cplusplus
}
#endif

#endif // SUBLIMATION_TEXT_H
