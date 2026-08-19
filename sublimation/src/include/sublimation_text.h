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
// GLUSHKOV POSITIONS. The field is a bit-vector of these, so the budget is
// words x 64. It used to be one word, flat: a pattern needing a 65th position
// was rejected as "bad pattern", which reads as a syntax error and is not one.
//
// The engine is now specialized for BOTH widths and the pattern picks -- the
// same move the sort makes, routing an input to the pole its structure earns,
// except here the classifier is EXACT: the position count is known during
// compilation, before the field is built, so nothing is guessed.
//
// Storage is sized for the wide case always. A per-width struct would be a
// second public type every consumer had to learn, and the narrow path still
// reads only word 0, so the cost is memory rather than instructions.
#define SUBLIMATION_SEARCH_POS_WORDS   2
#define SUBLIMATION_SEARCH_MAX_POS     (64 * SUBLIMATION_SEARCH_POS_WORDS)
#define SUBLIMATION_SEARCH_NARROW_POS  64    // one word: the common path

enum {
    SUBLIMATION_SEARCH_FIXED = 1u,   // literal/anchor face (default is regex)
    SUBLIMATION_SEARCH_ICASE = 2u    // ASCII case-fold at match time (A-Z == a-z)
};

// The compiled Glushkov position-NFA, simulated as a bit-vector field. Internal
// to the search program; exposed only so sublimation_search is a complete value
// type the caller can stack/static-allocate.
typedef struct {
    uint8_t  setb[SUBLIMATION_SEARCH_MAX_POS][32];  // byte-set per position
    // Position SETS are words[SUBLIMATION_SEARCH_POS_WORDS]; the engine reads
    // only the first `nwords` of each, which is what makes the narrow path
    // scalar rather than a loop.
    uint64_t follow[SUBLIMATION_SEARCH_MAX_POS][SUBLIMATION_SEARCH_POS_WORDS];
    uint64_t first[SUBLIMATION_SEARCH_POS_WORDS];   // start position set
    uint64_t last[SUBLIMATION_SEARCH_POS_WORDS];    // accept position set
    int npos, nwords, nullable_all, ok;
    int anchored_start, anchored_end;               // leading ^ / trailing $
    int icase;                                      // fold ASCII case into setb[]
} sublimation_search_gnfa;

typedef struct {
    sublimation_search_gnfa g;                          // regex program (REGEX mode)
    uint64_t imap[256][SUBLIMATION_SEARCH_POS_WORDS];  // per-byte position map,
                         // built once at compile time
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

// How many characters in `pat` CANNOT be case-folded by the -i face: non-ASCII
// characters -i cannot fold. Returns 0 -- every cased character in a fold class
// is now covered, same-lead pairs by one position with two byte members and
// the rest by an alternation over the class, so -i no longer narrows.
//
// Exists so a caller can SAY when it does. An -i that quietly matches less
// than the user asked for is the failure this reports.
SUB_API size_t sublimation_search_fold_gaps(const char *pat, size_t len);

// THE OCCURRENCE FIELD -- every match in a range, as POSITIONS, at MATCH
// granularity rather than line granularity.
//
// This is the field the analysis instruments run over. The matcher still SKIPS
// (the Glushkov position-NFA already fires a match-end bit per input byte; this
// keeps that bit instead of collapsing it into a counter), and the instruments
// RELATE the few thousand positions it emits rather than the billions of bytes
// it scanned. That separation is load-bearing: it is why classify, Spectral
// Residual and Matrix Profile can sit ABOVE the matcher without ever touching
// the haystack.
//
// OPT-IN BY CONSTRUCTION. Deciding a line matched stops at the first hit;
// enumerating every occurrence gives that up. Nothing here is on the selection
// path -- a caller that only wants "did this line match" keeps calling
// sublimation_search_selects and pays nothing.
//
// `pat` is which pattern of the set fired, which next_any cannot report because
// it collapses the set to one leftmost-longest answer. A consumer that renders
// or substitutes per pattern needs it; -1 means no single pattern owns the span
// (whole-line -x, where the line is the match by definition).
typedef struct {
    uint32_t start;   // byte offset of the match within the scanned range
    uint32_t end;     // exclusive
    int32_t  pat;     // index into the pattern set, or -1
} sublimation_match_span;

// Fill `out` with up to `cap` spans and RETURN THE TOTAL FOUND, which may exceed
// `cap` -- count-then-fill, so the library allocates nothing and ownership never
// crosses the boundary. `out` may be NULL when cap is 0 to size a buffer first.
//
// Walk order and semantics are exactly the CLI's --color walk, because that walk
// is the definition every consumer has to agree with: leftmost-longest across
// the set, advance past the match end, and step ONE byte on a zero-width match
// (which records no span -- there is nothing to highlight or substitute).
SUB_API size_t sublimation_search_spans(const sublimation_search *set, int nset,
                                        int regex_face, const char *text, size_t n,
                                        int wword, int xline,
                                        sublimation_match_span *out, size_t cap);

// CAPTURE GROUPS for ONE match span. `text[0..n)` must be exactly a match of
// `pat` -- the fast engine isolates it first, and this only ever runs over those
// bytes, only when a substitution asks for a backreference. Fills `groups` with
// up to `max_groups` spans, 1-based left to right, and writes how many to
// `ngroups`. A group that did not participate has pat == -1.
//
// Returns 1 on a parse-and-match, 0 otherwise. Fails CLOSED: a pattern this
// subset cannot express yields no captures rather than a guess.
SUB_API int sublimation_search_captures(const char *pat, const char *text, size_t n,
                                        int icase, sublimation_match_span *groups,
                                        size_t max_groups, size_t *ngroups);

// THE DISPERSION FIELD -- what the occurrence field is FOR.
//
// The matcher skips billions of bytes; these instruments relate the few thousand
// positions it emits. That is the separation law resolved rather than bent: the
// RELATE-shaped primitives everyone keeps trying to force INTO the matcher
// (spectral, entropy, FFT) run ABOVE it, on the sparse output, never on the
// haystack. It is the same reason an O(n^3) method is affordable over a few
// hundred vectors and unthinkable over a log file.
//
// This is a SENSOR, not a leaf. "Where does this pattern cluster, and does its
// burst line up with something else that moved" is a question about a text
// stream that nothing else here could answer, because every other sensor reads
// structured telemetry.
//
// STATIC ONLY. "Did this pattern's match RATE shift, and where" is the temporal
// half and is deliberately absent: it needs an incremental per-key streaming
// changepoint, which is built once for processes and inherited here rather than
// written twice.
typedef struct {
    size_t matches;          // spans considered
    size_t span_bytes;       // first match start .. last match end
    double density_per_kb;   // matches per 1024 bytes of HAYSTACK, not of span

    // Stride = distance between consecutive match STARTS. Mean alone hides the
    // shape, so the spread ships with it.
    double stride_mean, stride_stdev;
    double stride_p50, stride_p90, stride_p99, stride_max;

    // Goh-Barabasi burstiness on the strides: (sd - mean) / (sd + mean).
    // -1 perfectly periodic, 0 Poisson (memoryless), +1 maximally bursty. It is
    // scale-free by construction, so a dense pattern and a rare one are directly
    // comparable -- which a raw variance is not.
    double burstiness;

    // Disorder class of the stride sequence, from the same classifier the sort
    // routes on. A pattern whose gaps are SORTED is thinning out or ramping up;
    // one whose gaps are RANDOM is memoryless. Values are sub_disorder_t.
    int    gap_class;

    // Peak Spectral-Residual saliency over the arrival series: how much one
    // burst stands out from the pattern's own background. 0 when the series is
    // too short for the transform.
    double saliency_max;
    size_t saliency_at;      // arrival index of that peak
    size_t saliency_window;  // gaps actually transformed (largest power-of-two
                             // prefix); 0 when the series was too short

    // Matrix-profile DISCORD: the most anomalous window of arrivals (highest
    // distance to its nearest neighbour), and MOTIF: the most repeated one.
    // 0/absent when the series is shorter than a usable window.
    double discord;
    size_t discord_at;
    double motif;
    size_t motif_at;
} sublimation_dispersion;

// Compute the field from a span array. `haystack_len` is what density is
// relative to. Returns 1 on success, 0 when there is nothing to describe
// (fewer than 2 spans -- a single match has no stride and no shape).
// Allocates internally and frees before returning; nothing is owed to the caller.
SUB_API int sublimation_dispersion_field(const sublimation_match_span *spans,
                                         size_t n, size_t haystack_len,
                                         sublimation_dispersion *out);

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
