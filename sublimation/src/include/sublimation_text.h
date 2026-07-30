// sublimation_text.h -- text search: the tri-face matcher (sublimation_search).
// One engine, three faces (exact/anchor, regex, fuzzy k-mismatch), each with a
// rare-byte prefilter -- the exact face reads the byte rarity from the data, the
// regex and fuzzy faces from a fixed byte-frequency model. This is sublimation's
// text search/match side, the counterpart to the sort core's order/structure
// side; the two under one roof make sublimation montauk's single
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
// Per-call scratch (the field's reach-closure memo, the fuzzy dedup array) is
// allocated and freed inside find/count; the program itself never heap-allocates.
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
    int icase;                                      // fold ASCII case into setb[]
} sublimation_search_gnfa;

typedef struct {
    sublimation_search_gnfa g;                          // regex program (REGEX mode)
    uint64_t imap[256];  // per-byte position map, built once at compile time
                         // (REGEX mode; depends only on pattern + icase)
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

// Split PATTERN on its top-level '|' only -- never one inside a bracket
// expression, behind a backslash, or nested in a group. Returns the branch
// count when there are at least two, with *out set to that many malloc'd
// branches (caller frees each, then the array), or 0 when the pattern is a
// single branch and nothing should change. Exported because the bracket rule
// belongs to the matcher, not to whichever front end wants the split.
SUB_API int sublimation_search_split_alternation(const char *pattern,
                                                 char ***out, int *nout);

// sizeof(sublimation_search), exported so a foreign binding that mirrors the
// struct as an opaque buffer (vector's ffi.rs) can assert its mirror
// matches this library at runtime, not just at the mirror's writing.
SUB_API size_t sublimation_search_sizeof(void);

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

// LINE SELECTION over a pattern SET -- grep's semantics, as the library's own
// answer rather than a front-end's. `set`/`nset` is the -e/-f pattern set, which
// grep treats as one alternation. `regex_face` is 1 when the set was compiled to
// the regex face; it enables the shorter-end probe -w needs (find_from reports
// only the longest end per start, and grep -w admits any match length).
// `wword` is -w, `xline` is -x.

// Leftmost-longest next span across the whole set at or after `off`: ties at one
// start go to the longest match across all patterns. Returns the start offset
// (or -1) and writes the end offset (exclusive) to *end_out.
SUB_API long sublimation_search_next_any(const sublimation_search *set, int nset,
                                         int regex_face, const char *line, size_t n,
                                         size_t off, int wword, long *end_out);

// Does ANY pattern in the set accept this line? 1 = yes, 0 = no.
SUB_API int sublimation_search_selects(const sublimation_search *set, int nset,
                                       int regex_face, const char *line, size_t n,
                                       int xline, int wword);

// THE OCCURRENCE RECORD -- one selected line as a POSITION plus the bytes needed
// to render it, never as pre-rendered output. A scan decides WHICH lines are
// selected and where; rendering is a separate pass over these records, which is
// what lets one scan feed a text front-end, a parallel merge and (later) the
// analysis instruments without any of them re-running the matcher.
//
// line_no is the 1-based line within the source; off/len index the buffer's own
// arena, len excluding the trailing newline and raw_len including it. The match
// SPAN joins this record when a consumer needs it (-o, capture groups); the
// split between scanning and rendering is what keeps that a field addition
// rather than a rewrite.
typedef struct {
    uint32_t line_no;
    uint32_t off;       // byte offset into sublimation_occ_buf.raw
    uint32_t len;       // line length WITHOUT the trailing newline
    uint32_t raw_len;   // line length as read, newline included
} sublimation_search_occ;

// A growable pair of arrays: The records, and the arena their bytes live in.
typedef struct {
    sublimation_search_occ *occ; size_t n, cap;
    char                   *raw; size_t raw_n, raw_cap;
} sublimation_occ_buf;

SUB_API void sublimation_occ_buf_init(sublimation_occ_buf *b);
// Append one selected line. Best-effort: on allocation failure the record is
// dropped rather than aborting, matching the rest of this library's output path.
SUB_API void sublimation_occ_buf_push(sublimation_occ_buf *b, uint32_t line_no,
                                      const char *line, size_t len, size_t raw_len);
SUB_API void sublimation_occ_buf_free(sublimation_occ_buf *b);

// One distinct newline-separated record and its occurrence count, as an offset
// and length into the caller's buffer (no copy). Backs the tally/distinct/count
// verbs for a bounded FFI caller; the CLI keeps its own streaming interner for
// unbounded stdin.
typedef struct { size_t offset; size_t length; uint64_t count; } sub_tally_t;

// Tally distinct newline-separated records in data[0..n): fill out[] with up to
// out_cap distinct records (offset, length, count) sorted by count descending
// then first-seen. Returns the number of DISTINCT records (may exceed out_cap;
// out is filled only up to it). *total, if non-NULL, gets the total record
// count. A trailing record without a newline still counts.
SUB_API size_t sublimation_tally(const char *data, size_t n, sub_tally_t *out,
                                 size_t out_cap, uint64_t *total);

#ifdef __cplusplus
}
#endif

#endif // SUBLIMATION_TEXT_H
