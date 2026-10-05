// match.c -- tri-face text matcher (sublimation_locate.h face of sublimation_text.h).
// Ported from the proven research prototype (sublimation/tests/search/search_research.c):
// the data-relative anchor scan (exact face), the Glushkov bit-parallel position-NFA
// with its reach-closure memo and literal prefilter (regex face) and the brute plus
// pigeonhole-prefiltered k-mismatch scans (fuzzy face). Byte-parity with the reference
// oracles is the gate: every count here is byte-identical to the un-prefiltered path.
#include "sublimation_text.h"
#include "case_fold_table.h"   // generated: same-length, last-byte-only fold pairs
#include "sublimation.h"          // sublimation_classify_u64, for the gap disorder class
#include "sublimation_stats.h"    // mean/stdev/max/quantile over the strides
#include "sublimation_signal.h"   // spectral residual + matrix profile, on the SPARSE series
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

enum { MODE_EXACT = 0, MODE_REGEX = 1, MODE_FUZZY = 2 };

// ASCII case fold (A-Z -> a-z), non-letters passthrough. UTF-8 not folded.
static inline unsigned char fold(unsigned char c, int icase) {
    return (icase && c >= 'A' && c <= 'Z') ? (unsigned char)(c + 32) : c;
}

// Input size at or above which find_from's exact face pays for a data-relative
// rare-byte anchor; below it the histogram costs more than the better anchor
// returns. Measured, see sublimation_search_find_from.
#define SEARCH_ANCHOR_HIST_MIN (1u << 20)

// Sample the first <=256 KiB into a byte histogram (sublinear, the online sample).
static void byte_hist(const uint8_t *hay, size_t n, uint32_t hist[256]) {
    memset(hist, 0, 256 * sizeof(uint32_t));
    size_t s = n < (1u << 18) ? n : (1u << 18);
    for (size_t i = 0; i < s; i++) hist[hay[i]]++;
}

typedef struct { uint8_t byte; size_t off; } anchor_t;

// memchr to each occurrence of the anchor byte, derive the candidate start, verify.
static size_t scan_anchor(const uint8_t *hay, size_t n, const uint8_t *pat,
                          size_t m, anchor_t a) {
    size_t count = 0;
    if (m == 0 || m > n) return 0;
    const uint8_t *end = hay + n;
    for (const uint8_t *p = hay + a.off; p < end;) {
        const uint8_t *hit = memchr(p, a.byte, (size_t)(end - p));
        if (!hit) break;
        size_t j = (size_t)(hit - hay);
        if (j >= a.off && j - a.off + m <= n &&
            memcmp(hay + (j - a.off), pat, m) == 0)
            count++;
        p = hit + 1;
    }
    return count;
}

// Two-anchor scan: probe the rarer anchor, reject with a second decorrelated one
// before the full verify (a negative-dependence AND filter).
static size_t scan_anchor2(const uint8_t *hay, size_t n, const uint8_t *pat,
                           size_t m, anchor_t a, anchor_t b) {
    size_t count = 0;
    if (m == 0 || m > n) return 0;
    const uint8_t *end = hay + n;
    for (const uint8_t *p = hay + a.off; p < end;) {
        const uint8_t *hit = memchr(p, a.byte, (size_t)(end - p));
        if (!hit) break;
        size_t j = (size_t)(hit - hay);
        if (j >= a.off && j - a.off + m <= n) {
            size_t start = j - a.off;
            if (hay[start + b.off] == b.byte &&
                memcmp(hay + start, pat, m) == 0)
                count++;
        }
        p = hit + 1;
    }
    return count;
}

// Classic Boyer-Moore-Horspool: pattern-only bad-character skip, data-agnostic.
static size_t scan_bmh(const uint8_t *hay, size_t n, const uint8_t *pat, size_t m) {
    if (m == 0 || m > n) return 0;
    size_t skip[256];
    for (int i = 0; i < 256; i++) skip[i] = m;
    for (size_t i = 0; i + 1 < m; i++) skip[pat[i]] = m - 1 - i;
    size_t count = 0, i = 0;
    while (i + m <= n) {
        if (memcmp(hay + i, pat, m) == 0) count++;
        i += skip[hay[i + m - 1]];
    }
    return count;
}

static size_t off_min_by_data(const uint8_t *pat, size_t m, const uint32_t hist[256]) {
    size_t best = 0; uint32_t bc = hist[pat[0]];
    for (size_t i = 1; i < m; i++) if (hist[pat[i]] < bc) { bc = hist[pat[i]]; best = i; }
    return best;
}

static size_t off_second_by_data(const uint8_t *pat, size_t m, size_t avoid,
                                 const uint32_t hist[256]) {
    size_t best = avoid; uint32_t bc = 0xffffffffu;
    for (size_t i = 0; i < m; i++) {
        size_t d = i > avoid ? i - avoid : avoid - i;
        if (d < 2) continue;
        if (hist[pat[i]] < bc) { bc = hist[pat[i]]; best = i; }
    }
    return best;
}

// Exact face: rare-byte regime pick (a byte-frequency read, NOT the disorder
// classifier). Read the sampled histogram, name the regime, pick the scan. No
// rare byte -> bmh; one rare byte -> data-relative anchor; two decorrelated rare
// bytes -> two-anchor. Every path yields the same overlapping count (the parity
// gate proves this); the choice is speed only.
static size_t exact_count(const uint8_t *hay, size_t n, const uint8_t *pat, size_t m) {
    if (m == 0 || m > n) return 0;
    uint32_t hist[256]; byte_hist(hay, n, hist);
    size_t ssz = n < (1u << 18) ? n : (1u << 18);
    uint32_t rare = (uint32_t)(ssz / 32);
    size_t o1 = off_min_by_data(pat, m, hist);
    if (hist[pat[o1]] > rare)
        return scan_bmh(hay, n, pat, m);
    size_t o2 = off_second_by_data(pat, m, o1, hist);
    if (o2 != o1 && hist[pat[o2]] <= rare)
        return scan_anchor2(hay, n, pat, m, (anchor_t){pat[o1], o1}, (anchor_t){pat[o2], o2});
    return scan_anchor(hay, n, pat, m, (anchor_t){pat[o1], o1});
}

// icase / general exact overlapping count (folded compare). Used when case folding
// is on, where the memchr-anchor probe cannot be a single byte.
static size_t exact_count_folded(const uint8_t *hay, size_t n, const uint8_t *pat,
                                 size_t m, int icase) {
    if (m == 0 || m > n) return 0;
    size_t count = 0;
    for (size_t i = 0; i + m <= n; i++) {
        size_t j = 0;
        for (; j < m; j++) if (fold(hay[i + j], icase) != fold(pat[j], icase)) break;
        if (j == m) count++;
    }
    return count;
}

// FUZZY k-mismatch, correctness baseline: count windows within Hamming <= k.
static size_t scan_kmismatch(const uint8_t *hay, size_t n, const uint8_t *pat,
                             size_t m, int k, int icase) {
    if (m == 0 || m > n) return 0;
    size_t count = 0;
    for (size_t i = 0; i + m <= n; i++) {
        int mism = 0;
        for (size_t j = 0; j < m; j++)
            if (fold(hay[i + j], icase) != fold(pat[j], icase)) { if (++mism > k) break; }
        if (mism <= k) count++;
    }
    return count;
}

// E3: pigeonhole prefilter for k-mismatch. Split the pattern into k+1 pieces; any
// k-mismatch occurrence leaves at least one piece exact. Anchor on each piece's
// rarest byte and verify at candidates, deduping so the result is byte-identical
// to the brute scan. Returns (size_t)-1 on allocation failure (caller falls back).
static size_t scan_kmismatch_pre(const uint8_t *hay, size_t n, const uint8_t *pat,
                                 size_t m, int k) {
    if (m == 0 || m > n) return 0;
    if ((size_t)k >= m) return n - m + 1;
    int pieces = k + 1;
    unsigned char *seen = calloc(n, 1);
    if (!seen) return (size_t)-1;
    size_t count = 0;
    const uint8_t *end = hay + n;
    // Data-relative rarest byte per piece, same live histogram exact_count reads
    // -- was the static english_freq table, unified 2026-07-27.
    uint32_t hist[256]; byte_hist(hay, n, hist);
    for (int pc = 0; pc < pieces; pc++) {
        size_t ps = (size_t)pc * m / (size_t)pieces;
        size_t pe = (size_t)(pc + 1) * m / (size_t)pieces;
        if (pe == ps) continue;
        size_t roff = ps; uint32_t bf = hist[pat[ps]];
        for (size_t i = ps + 1; i < pe; i++) {
            uint32_t f = hist[pat[i]];
            if (f < bf) { bf = f; roff = i; }
        }
        unsigned char probe = pat[roff];
        for (const uint8_t *q = hay; ; ) {
            const uint8_t *hit = memchr(q, probe, (size_t)(end - q));
            if (!hit) break;
            size_t hp = (size_t)(hit - hay);
            if (hp >= roff && hp - roff + m <= n) {
                size_t p = hp - roff;
                if (!seen[p]) {
                    seen[p] = 1;
                    int mism = 0;
                    for (size_t j = 0; j < m; j++)
                        if (hay[p + j] != pat[j]) { if (++mism > k) break; }
                    if (mism <= k) count++;
                }
            }
            q = hit + 1;
        }
    }
    free(seen);
    return count;
}

// UTF-8 decode of one character. Returns its byte length, or 0 when the bytes
// are not a well-formed sequence (in which case the caller treats the lead byte
// as a plain literal, which is what the engine did before folding existed).
static int u8_decode(const unsigned char *p, size_t avail, uint32_t *cp) {
    if (avail == 0) return 0;
    unsigned char c = p[0];
    int n; uint32_t v;
    if (c < 0x80) { *cp = c; return 1; }
    else if ((c & 0xE0) == 0xC0) { n = 2; v = c & 0x1F; }
    else if ((c & 0xF0) == 0xE0) { n = 3; v = c & 0x0F; }
    else if ((c & 0xF8) == 0xF0) { n = 4; v = c & 0x07; }
    else return 0;
    if (avail < (size_t)n) return 0;
    for (int i = 1; i < n; i++) {
        if ((p[i] & 0xC0) != 0x80) return 0;
        v = (v << 6) | (uint32_t)(p[i] & 0x3F);
    }
    *cp = v;
    return n;
}

// The counterpart's LAST byte for `cp`, or 0 when it has no same-length,
// last-byte-only fold partner. Binary search over the generated table.
static uint8_t fold_alt_last(uint32_t cp) {
    size_t lo = 0, hi = SUB_FOLD_PAIRS;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (sub_fold_table[mid].cp == cp) return sub_fold_table[mid].alt_last;
        if (sub_fold_table[mid].cp < cp) lo = mid + 1; else hi = mid;
    }
    return 0;
}

// The other members of `cp`'s case-fold class, when the class needs an
// ALTERNATION rather than a single position with two byte members. Returns how
// many were written (0 when the cheap path covers it).
static int fold_alt_members(uint32_t cp, uint32_t *out) {
    size_t lo = 0, hi = SUB_FOLD_ALT_PAIRS;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (sub_fold_alt_table[mid].cp == cp) {
            int n = 0;
            for (int i = 0; i < 3; i++)
                if (sub_fold_alt_table[mid].alt[i]) out[n++] = sub_fold_alt_table[mid].alt[i];
            return n;
        }
        if (sub_fold_alt_table[mid].cp < cp) lo = mid + 1; else hi = mid;
    }
    return 0;
}

// Encode `cp` as UTF-8 into buf (<= 4 bytes). Returns the length, 0 if invalid.
static int u8_encode(uint32_t cp, unsigned char *buf) {
    if (cp < 0x80)      { buf[0] = (unsigned char)cp; return 1; }
    if (cp < 0x800)     { buf[0] = (unsigned char)(0xC0 | (cp >> 6));
                          buf[1] = (unsigned char)(0x80 | (cp & 0x3F)); return 2; }
    if (cp < 0x10000)   { buf[0] = (unsigned char)(0xE0 | (cp >> 12));
                          buf[1] = (unsigned char)(0x80 | ((cp >> 6) & 0x3F));
                          buf[2] = (unsigned char)(0x80 | (cp & 0x3F)); return 3; }
    if (cp < 0x110000)  { buf[0] = (unsigned char)(0xF0 | (cp >> 18));
                          buf[1] = (unsigned char)(0x80 | ((cp >> 12) & 0x3F));
                          buf[2] = (unsigned char)(0x80 | ((cp >> 6) & 0x3F));
                          buf[3] = (unsigned char)(0x80 | (cp & 0x3F)); return 4; }
    return 0;
}

// Set byte b in the position set, plus its ASCII case-swap under icase. Case is
// folded into the class SET at compile time (before any negation), so a negated
// class like (?i)[^a] correctly excludes both 'a' and 'A' -- folding at match
// time instead would leave 'A' matching, since it is present in the negated set.
static inline void gset_byte(uint8_t *S, unsigned char b, int icase) {
    S[b>>3] |= (uint8_t)(1u<<(b&7));
    if (icase) {
        unsigned char sw = b;
        if (b >= 'a' && b <= 'z') sw = (unsigned char)(b - 32);
        else if (b >= 'A' && b <= 'Z') sw = (unsigned char)(b + 32);
        if (sw != b) S[sw>>3] |= (uint8_t)(1u<<(sw&7));
    }
}

// THE one definition of a bracket expression, for every consumer here and for
// the CLI's alternation splitter. POSIX ERE: a '^' immediately after '['
// negates; a ']' in the FIRST content position is a literal member, not the
// close; backslash is NOT special inside the brackets. `i` indexes the '['.
// Returns the index just past the closing ']', or 0 when unterminated (0 is
// never a valid return, since a terminated class ends at i+2 or later).
// When S is non-NULL the members are written into it as a 32-byte set, folded
// per member under icase and negated last.
// Perl-style shorthand byte sets, for `\w \W \s \S` OUTSIDE a bracket
// expression. Returns 1 and fills S when `c` names one, 0 otherwise.
//
// SCOPE MEASURED AGAINST grep -E UNDER LC_ALL=C, not assumed:
//   \w \W \s \S  GNU ERE supports these; implemented here.
//   \d \D        GNU ERE does NOT. `grep -E '\d'` matches a literal 'd'.
//                Adding them would create a NEW divergence from the oracle in
//                the opposite direction, which is worse than the gap it closes.
//                Deliberately absent.
//   [\w]         Inside brackets GNU treats the backslash as a LITERAL member,
//                so `[\w]` is the set {'\\','w'}. class_span already does
//                exactly that, so shorthands are correctly NOT expanded there.
// \w is [[:alnum:]_] and \s is [[:space:]], which is what GNU means by them.
static int shorthand_set(char c, uint8_t *S) {
    int negate = 0;
    switch (c) {
        case 'W': negate = 1; /* fall through */
        case 'w':
            memset(S, 0, 32);
            for (unsigned b = '0'; b <= '9'; b++) S[b>>3] |= (uint8_t)(1u<<(b&7));
            for (unsigned b = 'A'; b <= 'Z'; b++) S[b>>3] |= (uint8_t)(1u<<(b&7));
            for (unsigned b = 'a'; b <= 'z'; b++) S[b>>3] |= (uint8_t)(1u<<(b&7));
            S['_'>>3] |= (uint8_t)(1u<<('_'&7));
            break;
        case 'S': negate = 1; /* fall through */
        case 's': {
            memset(S, 0, 32);
            static const unsigned char ws[] = {' ', '\t', '\n', '\v', '\f', '\r'};
            for (size_t k = 0; k < sizeof ws; k++)
                S[ws[k]>>3] |= (uint8_t)(1u<<(ws[k]&7));
            break;
        }
        default: return 0;
    }
    if (negate) for (int k = 0; k < 32; k++) S[k] = (uint8_t)~S[k];
    return 1;
}

// POSIX character classes INSIDE a bracket expression: [[:alpha:]], [[:digit:]]
// and kin. `search '[[:alpha:]]+'` used to match nothing at all, because
// class_span read "[[:alpha:]]" as the literal member set {'[',':','a','l','p','h'}
// and stopped at the first ']' -- a silently wrong answer rather than a refusal.
//
// Membership is ASCII / LC_ALL=C, the same basis the \w and \s shorthands
// already use (this file documents \w as [[:alnum:]_] and \s as [[:space:]]),
// so the two spellings agree by construction.
//
// Returns the index just past the closing ":]", or 0 when `p+i` does not open a
// class. An UNKNOWN name is reported through *bad so the caller can reject the
// whole pattern: POSIX says an unrecognized class is an error, and guessing at
// it would reintroduce exactly the quiet mismatch this closes.
static size_t posix_class_span(const char *p, size_t len, size_t i,
                               uint8_t *S, int icase, int *bad) {
    if (i + 1 >= len || p[i] != '[' || p[i+1] != ':') return 0;
    size_t j = i + 2;
    while (j + 1 < len && !(p[j] == ':' && p[j+1] == ']')) j++;
    if (j + 1 >= len) return 0;              // no ":]" -- not a class, treat literally
    size_t n = j - (i + 2);
    const char *nm = p + i + 2;

    #define NAME_IS(lit) (n == sizeof(lit) - 1 && memcmp(nm, lit, n) == 0)
    for (unsigned b = 0; b < 256; b++) {
        int in = 0;
        if      (NAME_IS("alpha"))  in = (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z');
        else if (NAME_IS("digit"))  in = (b >= '0' && b <= '9');
        else if (NAME_IS("alnum"))  in = (b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z');
        else if (NAME_IS("upper"))  in = (b >= 'A' && b <= 'Z');
        else if (NAME_IS("lower"))  in = (b >= 'a' && b <= 'z');
        else if (NAME_IS("space"))  in = (b == ' ' || b == '\t' || b == '\n' || b == '\v' || b == '\f' || b == '\r');
        else if (NAME_IS("blank"))  in = (b == ' ' || b == '\t');
        else if (NAME_IS("print"))  in = (b >= 0x20 && b <= 0x7E);
        else if (NAME_IS("graph"))  in = (b >= 0x21 && b <= 0x7E);
        else if (NAME_IS("cntrl"))  in = (b <= 0x1F || b == 0x7F);
        else if (NAME_IS("punct"))  in = (b >= 0x21 && b <= 0x7E)
                                      && !((b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z'));
        else if (NAME_IS("xdigit")) in = (b >= '0' && b <= '9') || (b >= 'A' && b <= 'F') || (b >= 'a' && b <= 'f');
        else { *bad = 1; return 0; }
        if (in && S) gset_byte(S, (unsigned char)b, icase);
    }
    #undef NAME_IS
    return j + 2;
}

static size_t class_span(const char *p, size_t len, size_t i, uint8_t *S, int icase) {
    i++;
    int neg = 0;
    if (i < len && p[i] == '^') { neg = 1; i++; }
    for (int first = 1; i < len && (first || p[i] != ']'); first = 0) {
        int bad = 0;
        size_t after = posix_class_span(p, len, i, S, icase, &bad);
        if (bad) return 0;                   // unknown [:name:] -- reject the pattern
        if (after) { i = after; continue; }
        unsigned char lo = (unsigned char)p[i];
        if (i + 2 < len && p[i+1] == '-' && p[i+2] != ']') {
            unsigned char hi = (unsigned char)p[i+2];
            if (S) for (unsigned v = lo; v <= hi; v++) gset_byte(S, (unsigned char)v, icase);
            i += 3;
        } else { if (S) gset_byte(S, lo, icase); i++; }
    }
    if (i >= len) return 0;
    if (S && neg) for (int k = 0; k < 32; k++) S[k] = (uint8_t)~S[k];
    return i + 1;
}

// Fixed-length class field (fast path): each atom is a per-position byte-set. The
// Shift-And field matches classes and wildcards. Returns -1 on an unsupported
// construct (anchors, quantifiers, alternation, grouping, braces).
static int parse_classes(const char *p, uint8_t sets[][32], int maxL) {
    int L = 0; size_t i = 0, len = strlen(p);
    if (len > 0 && (p[0] == '^' || p[len - 1] == '$')) return -1;
    while (i < len) {
        if (L >= maxL) return -1;
        uint8_t *S = sets[L]; memset(S, 0, 32);
        char c = p[i];
        if (c=='*'||c=='+'||c=='?'||c=='|'||c=='('||c==')'||c=='{') return -1;
        if (c == '.') { memset(S, 0xff, 32); i++; }
        // icase is 0 unconditionally: regex_count routes every icase pattern to
        // the full field before reaching this fast path.
        else if (c == '[') {
            size_t e = class_span(p, len, i, S, 0);
            if (e == 0) return -1;
            i = e;
        }
        else {
            if (c == '\\' && i + 1 < len) {
                i++; c = p[i];
                // Must expand the same shorthands as g_atom, or the fast path
                // and the full field disagree on what the pattern means.
                if (shorthand_set(c, S)) { i++; L++; continue; }
            }
            unsigned char b = (unsigned char)c;
            S[b>>3] |= (uint8_t)(1u << (b&7)); i++;
        }
        L++;
    }
    return L;
}

static size_t scan_classfield(const uint8_t *hay, size_t n, uint8_t sets[][32], int L) {
    if (L <= 0 || L > 64) return (size_t)-1;
    uint64_t B[256];
    for (int c = 0; c < 256; c++) {
        uint64_t mm = 0;
        for (int i = 0; i < L; i++) if (sets[i][c>>3] & (1u << (c&7))) mm |= (1ull << i);
        B[c] = mm;
    }
    uint64_t D = 0, top = 1ull << (L - 1); size_t count = 0;
    for (size_t j = 0; j < n; j++) {
        D = ((D << 1) | 1ull) & B[(unsigned char)hay[j]];
        if (D & top) count++;
    }
    return count;
}

typedef sublimation_search_gnfa gnfa_t;

// WHEN AN EXPRESSION MATCHES EMPTY. Bit i is a requirement set: bit 0 needs
// nothing, bit 1 needs offset 0 (a ^ on the path), bit 2 needs the end (a $),
// bit 3 needs both, which only an empty input satisfies. Alternatives OR; a
// concatenation's requirements union, which is nul_cat.
enum { NUL_ANY = 1, NUL_BOL = 2, NUL_EOL = 4, NUL_BOTH = 8 };

static int nul_cat(int a, int b) {
    int out = 0;
    for (int i = 0; i < 4; i++)
        if ((a >> i) & 1)
            for (int j = 0; j < 4; j++)
                if ((b >> j) & 1) out |= 1 << (i | j);
    return out;
}

// Can an empty match end (and start) at offset e of an input of length n?
static inline int nul_at(int mask, size_t e, size_t n) {
    return (mask & NUL_ANY) || ((mask & NUL_BOL) && e == 0) ||
           ((mask & NUL_EOL) && e == n) || ((mask & NUL_BOTH) && n == 0);
}

typedef struct {
    int nul;                                        // NUL_* alternatives, 0 = never empty
    uint64_t first[SUBLIMATION_SEARCH_POS_WORDS];
    uint64_t first_bol[SUBLIMATION_SEARCH_POS_WORDS];
    uint64_t last[SUBLIMATION_SEARCH_POS_WORDS];
    uint64_t last_eol[SUBLIMATION_SEARCH_POS_WORDS];
} gattr_t;
// RE_DUP_MAX as GNU sets it. A repeat bound past this is refused rather than
// parsed, by both parsers, so a typo'd count cannot spin either copy loop.
#define FIELD_DUP_MAX 32767

// A predicate over a candidate span [s, e) of hay[0..n); -w's word boundary is
// the one caller.
typedef int (*span_ok_fn)(const uint8_t *hay, size_t n, long s, long e);

// fold_left counts bytes until the one that differs under icase; fold_byte is
// the counterpart to admit there. Only the LAST byte of a folded character
// ever differs (see case_fold_table.h), so one pending byte is enough.
typedef struct { const char *p; gnfa_t *g; int fold_left; unsigned char fold_byte; } gpar_t;

// Reach-closure memo. reach(D) = first | union(follow[i], i in D), memoized --
// the position-NFA's transition closure cached on the fly, keyed by state set.
typedef struct {
    uint64_t key[SUBLIMATION_SEARCH_POS_WORDS];
    uint64_t reach[SUBLIMATION_SEARCH_POS_WORDS];
    int used;
} reach_ent;
#define REACH_BITS 13
#define REACH_CAP  (1u << REACH_BITS)

// THE MEMO IS REUSED, NOT REALLOCATED. It was calloc'd per non-anchored count
// call -- 128 KB then, and 320 KB since the position set widened to two words,
// because reach_ent grew from 16 bytes to 40. A `search` over many files paid
// that per file.
//
// One thread-local block instead, cleared per use. Clearing is the whole cost
// and calloc paid it anyway; what goes away is the allocation, the page faults
// on first touch, and the free. Thread-local because the parallel search path
// scans files concurrently, and the memo is scratch that must not be shared.
static reach_ent *reach_cache_get(void) {
    static _Thread_local reach_ent *cache = NULL;
    if (!cache) {
        cache = (reach_ent *)malloc((size_t)REACH_CAP * sizeof(reach_ent));
        if (!cache) return NULL;
    }
    memset(cache, 0, (size_t)REACH_CAP * sizeof(reach_ent));
    return cache;
}

// Width-independent helpers the instantiated engine calls. Declared here so the
// two includes below can precede their definitions.
static int regex_maxlen(const char *p);
static int extract_literal(const char *p, uint8_t *out, int maxout);

// TWO ENGINES, ONE SOURCE. field.inc is instantiated once per field width; the
// pattern picks which at compile time (see the dispatchers below). The narrow
// engine is the common path and is bit-for-bit what it was when the field was a
// single uint64_t.
#define FW(name) name##_w1
#define PW 1
static gattr_t FW(g_alt)(gpar_t *x);
#include "field.inc"
#undef PW
#undef FW

#define FW(name) name##_w2
#define PW 2
static gattr_t FW(g_alt)(gpar_t *x);
#include "field.inc"
#undef PW
#undef FW

// WIDTH SELECTION, exact rather than heuristic. Build narrow first; a pattern
// that overruns 64 positions fails with ok = 0 and is rebuilt wide. The position
// count is not estimated -- the parser IS the counter, so retrying is both the
// simplest correct classifier and the cheapest one for the common case, which
// never retries.
static int build_gnfa(const char *pat, gnfa_t *g, int icase) {
    if (build_gnfa_w1(pat, g, icase)) return 1;
    // Only a position-cap overrun is worth a second pass; a syntax error fails
    // identically at either width. npos stops exactly AT the cap when the
    // pattern outgrew it, which is what distinguishes the two -- here and in
    // the error the compile reports.
    if (g->npos < SUBLIMATION_SEARCH_NARROW_POS) return 0;
    return build_gnfa_w2(pat, g, icase);
}

static void build_imap(const gnfa_t *g, uint64_t I[256][SUBLIMATION_SEARCH_POS_WORDS]) {
    if (g->nwords == 2) build_imap_w2(g, I); else build_imap_w1(g, I);
}
static size_t regex_count(const sublimation_search *s, const uint8_t *hay, size_t n) {
    return s->g.nwords == 2 ? regex_count_w2(s, hay, n) : regex_count_w1(s, hay, n);
}
static int gnfa_full(const gnfa_t *g, const uint64_t I[256][SUBLIMATION_SEARCH_POS_WORDS],
                     const uint8_t *hay, size_t n) {
    return g->nwords == 2 ? gnfa_full_w2(g, I, hay, n) : gnfa_full_w1(g, I, hay, n);
}
static long gnfa_start_longest(const gnfa_t *g,
                               const uint64_t I[256][SUBLIMATION_SEARCH_POS_WORDS],
                               const uint8_t *hay, size_t n, size_t start, span_ok_fn ok) {
    return g->nwords == 2 ? gnfa_start_longest_w2(g, I, hay, n, start, ok)
                          : gnfa_start_longest_w1(g, I, hay, n, start, ok);
}
static long gnfa_find(const gnfa_t *g, const uint64_t I[256][SUBLIMATION_SEARCH_POS_WORDS],
                      const uint8_t *hay, size_t n, size_t from, long *end_out) {
    return g->nwords == 2 ? gnfa_find_w2(g, I, hay, n, from, end_out)
                          : gnfa_find_w1(g, I, hay, n, from, end_out);
}




















static int regex_maxlen(const char *p) {
    size_t i = 0, plen = strlen(p); int len = 0;
    while (i < plen) {
        char c = p[i];
        if (c == '^' || c == '$') { i++; continue; }
        if (c == '(' || c == ')' || c == '|') return -1;
        size_t atom_end;
        if (c == '\\' && i + 1 < plen) atom_end = i + 2;
        else if (c == '[') { atom_end = class_span(p, plen, i, NULL, 0); if (!atom_end) atom_end = plen; }
        else atom_end = i + 1;
        int atomlen = 1;
        if (atom_end < plen) {
            char q = p[atom_end];
            if (q == '*' || q == '+') return -1;
            if (q == '?') { atomlen = 1; atom_end++; }
            else if (q == '{') {
                atom_end++; int lo = 0, hi = -2, has = 0;
                while (atom_end < plen && p[atom_end] >= '0' && p[atom_end] <= '9') { lo = lo*10 + (p[atom_end]-'0'); atom_end++; has = 1; }
                if (atom_end < plen && p[atom_end] == ',') { atom_end++; hi = -1; if (atom_end < plen && p[atom_end] >= '0' && p[atom_end] <= '9') { hi = 0; while (atom_end < plen && p[atom_end] >= '0' && p[atom_end] <= '9') { hi = hi*10 + (p[atom_end]-'0'); atom_end++; } } }
                else hi = lo;
                if (atom_end < plen && p[atom_end] == '}') atom_end++;
                if (!has || hi == -1) return -1;
                atomlen = hi;
            }
        }
        len += atomlen; i = atom_end;
    }
    return len;
}

// Longest run of consecutive plain literal bytes (alnum or space), none quantified.
static int extract_literal(const char *p, uint8_t *out, int maxout) {
    size_t plen = strlen(p);
    int bl = 0, bs = -1, cl = 0, cs = -1;
    for (size_t i = 0; i < plen; ) {
        char c = p[i];
        if (c == '[') {
            size_t e = class_span(p, plen, i, NULL, 0);
            i = e ? e : plen;
            cs = -1; cl = 0; continue;
        }
        if (c == '\\') { i += 2; cs = -1; cl = 0; continue; }
        unsigned char uc = (unsigned char)c;
        int plain = (isalnum(uc) || uc == ' ');
        int nextq = (i + 1 < plen && (p[i+1] == '*' || p[i+1] == '+' || p[i+1] == '?' || p[i+1] == '{'));
        if (plain && !nextq) {
            if (cs < 0) { cs = (int)i; cl = 0; }
            cl++;
            if (cl > bl) { bl = cl; bs = cs; }
        } else { cs = -1; cl = 0; }
        i++;
    }
    if (bl < 2 || bl > maxout) return 0;
    for (int kk = 0; kk < bl; kk++) out[kk] = (unsigned char)p[bs + kk];
    return bl;
}











// Public API

// The needle, wherever it lives. A borrowed pattern is the caller's bytes; a
// copied one is the regex source.
static inline const uint8_t *sub_needle(const sublimation_search *s) {
    return (const uint8_t *)(s->borrowed ? s->borrowed : s->pattern);
}

void sublimation_search_compile(sublimation_search *out, const char *pattern,
                                size_t len, unsigned flags, int k) {
    memset(out, 0, sizeof(*out));
    out->icase = (flags & SUBLIMATION_SEARCH_ICASE) ? 1 : 0;
    out->k = k > 0 ? k : 0;
    out->pattern_len = len;

    // An empty REGEX is legal and matches every line, which is grep's answer
    // and what `search --lines A,B` relies on to select a range with no
    // pattern. Only the literal and fuzzy faces have nothing to match on.
    if (len == 0 && (k > 0 || (flags & SUBLIMATION_SEARCH_FIXED))) {
        out->valid = 0;
        out->error = SUBLIMATION_SEARCH_ERR_EMPTY;
        return;
    }

    if (k > 0) {
        // Pigeonhole scan over the caller's bytes; no copy, no ceiling.
        out->mode = MODE_FUZZY;
        out->borrowed = pattern;
        out->valid = 1;
    } else if (flags & SUBLIMATION_SEARCH_FIXED) {
        // Boyer-Moore-Horspool over the caller's bytes; no copy, no ceiling.
        out->mode = MODE_EXACT;
        out->borrowed = pattern;
        out->valid = 1;
    } else {
        // Only the regex face copies, because build_gnfa re-reads a
        // NUL-terminated string, and only it is bounded by the position budget.
        if (len > SUBLIMATION_SEARCH_MAX_PATTERN) {
            out->valid = 0;
            out->error = SUBLIMATION_SEARCH_ERR_TOO_LONG;
            return;
        }
        memcpy(out->pattern, pattern, len);
        out->pattern[len] = '\0';
        out->mode = MODE_REGEX;
        // Regex compiles from the NUL-terminated pattern copy, so an embedded NUL
        // truncates the expression there -- unlike the literal/fuzzy paths above,
        // which honor `len` byte-for-byte. Threading `len` through the whole regex
        // parser is deferred; regex patterns are C strings in every current caller.
        out->valid = build_gnfa(out->pattern, &out->g, out->icase);
        if (!out->valid)
            out->error = out->g.npos >= SUBLIMATION_SEARCH_MAX_POS
                       ? SUBLIMATION_SEARCH_ERR_TOO_LONG : SUBLIMATION_SEARCH_ERR_SYNTAX;
        // The per-byte position map depends only on (pattern, icase): build it
        // once here so match/count calls never rebuild it.
        if (out->valid) build_imap(&out->g, out->imap);
    }
}

int sublimation_search_valid(const sublimation_search *s) { return s->valid; }

const char *sublimation_search_error(const sublimation_search *s) {
    if (!s || s->valid) return NULL;
    switch (s->error) {
        case SUBLIMATION_SEARCH_ERR_EMPTY:
            return "empty pattern";
        case SUBLIMATION_SEARCH_ERR_TOO_LONG:
            return "regex is too long: the bit-parallel field holds "
                   "SUBLIMATION_SEARCH_MAX_POS positions, counting literals, "
                   "classes and metacharacters across all branches. Split it "
                   "across several patterns, or use the literal face, which "
                   "has no such limit";
        case SUBLIMATION_SEARCH_ERR_SYNTAX:
            return "the expression does not parse";
        default:
            return "invalid pattern";
    }
}

// Split a pattern on its TOP-LEVEL '|' only -- not one inside a bracket
// expression, behind a backslash, or nested in a group. Lives here, beside the
// parser that DEFINES those three exclusions, rather than in the front end that
// happens to want it; the class exclusion is class_span, so the splitter and
// the matcher cannot drift on what a bracket expression is.
int sublimation_search_split_alternation(const char *pattern, char ***out, int *nout) {
    size_t len = strlen(pattern);
    char **br = NULL; int n = 0, cap = 0;
    int depth = 0;
    size_t start = 0;
    for (size_t i = 0; i <= len; i++) {
        int cut = (i == len) || (pattern[i] == '|' && depth == 0);
        if (!cut) {
            if (pattern[i] == '\\' && i + 1 < len) { i++; continue; }
            if (pattern[i] == '[') {
                size_t e = class_span(pattern, len, i, NULL, 0);
                i = (e ? e : len) - 1;
                continue;
            }
            if (pattern[i] == '(') depth++;
            else if (pattern[i] == ')' && depth) depth--;
            continue;
        }
        if (n == cap) {
            int nc = cap ? cap * 2 : 4;
            char **nb = realloc(br, (size_t)nc * sizeof *nb);
            if (!nb) { for (int k = 0; k < n; k++) free(br[k]); free(br); return 0; }
            br = nb; cap = nc;
        }
        size_t seglen = i - start;
        char *seg = malloc(seglen + 1);
        if (!seg) { for (int k = 0; k < n; k++) free(br[k]); free(br); return 0; }
        memcpy(seg, pattern + start, seglen); seg[seglen] = '\0';
        br[n++] = seg;
        start = i + 1;
    }
    if (n < 2) { for (int k = 0; k < n; k++) free(br[k]); free(br); return 0; }
    *out = br; *nout = n;
    return n;
}

// The opaque-buffer contract with foreign callers (vector mirrors this
// struct as a byte buffer in Rust). The static assert pins the size the
// mirror was written against; growth breaks THIS build, never a caller's
// stack. The sizeof export lets a binding assert the contract at runtime.
// The struct is sized for the WIDE field: the engine is specialized for one- and
// two-word position sets and the pattern picks, but a single public layout keeps
// sublimation_search one value type a caller can still stack-allocate.
//
// The last foreign mirror of this struct went with the MCP server; the assert
// stays because the property it guards -- growth is a deliberate act, never a
// silent one -- outlives any particular consumer.
// 11352 -> 11368: a borrowed-needle pointer and an error code. The literal and
// fuzzy faces stopped copying the pattern, which is what removed their length
// ceiling; the error code is what lets a front end say WHICH refusal happened
// rather than only that one did. Sixteen bytes against a 1023-byte ceiling on
// the two faces that never needed one.
// 11368 -> 11392: ^ and $ became assertions wherever they appear, which needs
// the start positions enterable only at offset 0 and the accepts valid only at
// the end as two more position sets. The two leading/trailing anchor flags they
// replace went with them.
static_assert(sizeof(sublimation_search) == 11392,
              "sublimation_search changed size: that is a deliberate decision, "
              "not an accident -- update this assert with the reason");

size_t sublimation_search_sizeof(void) { return sizeof(sublimation_search); }

int sublimation_search_full_match(const sublimation_search *s, const char *input, size_t n) {
    if (!s->valid) return 0;
    const uint8_t *hay = (const uint8_t *)input;
    size_t m = s->pattern_len;
    const uint8_t *pat = sub_needle(s);
    if (s->mode == MODE_REGEX) {
        return gnfa_full(&s->g, s->imap, hay, n);
    }
    if (s->mode == MODE_FUZZY) {
        if (n != m) return 0;
        int mism = 0;
        for (size_t j = 0; j < m; j++)
            if (fold(hay[j], s->icase) != fold(pat[j], s->icase)) if (++mism > s->k) return 0;
        return 1;
    }
    if (n != m) return 0;
    for (size_t j = 0; j < m; j++)
        if (fold(hay[j], s->icase) != fold(pat[j], s->icase)) return 0;
    return 1;
}

long sublimation_search_find_from(const sublimation_search *s, const char *input, size_t n,
                                  size_t from, long *end_out) {
    if (!s->valid || from > n) return -1;
    const uint8_t *hay = (const uint8_t *)input;
    size_t m = s->pattern_len;
    const uint8_t *pat = sub_needle(s);

    if (s->mode == MODE_REGEX) return gnfa_find(&s->g, s->imap, hay, n, from, end_out);

    if (m == 0) { if (end_out) *end_out = (long)from; return (long)from; }
    if (m > n) return -1;

    if (s->mode == MODE_FUZZY) {
        for (size_t i = from; i + m <= n; i++) {
            int mism = 0; size_t j = 0;
            for (; j < m; j++)
                if (fold(hay[i + j], s->icase) != fold(pat[j], s->icase)) { if (++mism > s->k) break; }
            if (mism <= s->k) { if (end_out) *end_out = (long)(i + m); return (long)i; }
        }
        return -1;
    }

    // Exact: leftmost occurrence at or after `from`. The rare-byte anchor is
    // DATA-relative, so choosing it costs a byte_hist pass over the input on
    // every call -- and this is the line-oriented path the CLI grep loop rides
    // once per line. Measured on this box (one find_from per buffer, a pattern
    // with a common first byte and a rare interior byte, no match so both scan
    // the whole input): the histogram LOSES at every size through 256KB (1.9x
    // slower at 1-16KB, 1.5x at 64KB, parity at 256KB) and first WINS at 1MB
    // (3.6x), widening to 11x by 4MB, because byte_hist samples at most 256KB
    // so past that its cost is fixed while the scan it shortens keeps growing.
    // Gate at the first MEASURED win rather than an interpolated crossover;
    // below it the plain first-byte memchr is never worse. The histogram cannot
    // be cached on `s` instead: the parallel file fan-out shares one const
    // sublimation_search read-only across workers, so a lazily filled cache
    // would be a write into a structure other threads are reading.
    if (!s->icase) {
        size_t aoff = 0;   // 0 == anchor on pat[0], the plain memchr scan
        if (n >= SEARCH_ANCHOR_HIST_MIN) {
            uint32_t hist[256]; byte_hist(hay, n, hist);
            aoff = off_min_by_data(pat, m, hist);
        }
        unsigned char abyte = pat[aoff];
        if (from + m > n) return -1;   // no room for a match at or after `from`
        // The last anchor position that can still begin a whole match: a match
        // starting at s needs s + m <= n, and the anchor sits at s + aoff, so
        // the scan stops at n - m + aoff and never walks the final m-1 bytes.
        const uint8_t *end = hay + (n - m) + aoff + 1;
        for (const uint8_t *p = hay + from + aoff; p < end;) {
            const uint8_t *hit = memchr(p, abyte, (size_t)(end - p));
            if (!hit) break;
            size_t start = (size_t)(hit - hay) - aoff;
            if (memcmp(hay + start, pat, m) == 0) {
                if (end_out) *end_out = (long)(start + m);
                return (long)start;
            }
            p = hit + 1;
        }
        return -1;
    }
    for (size_t i = from; i + m <= n; i++) {
        size_t j = 0;
        for (; j < m; j++) if (fold(hay[i + j], 1) != fold(pat[j], 1)) break;
        if (j == m) { if (end_out) *end_out = (long)(i + m); return (long)i; }
    }
    return -1;
}

long sublimation_search_find(const sublimation_search *s, const char *input, size_t n, long *end_out) {
    return sublimation_search_find_from(s, input, n, 0, end_out);
}

// LINE SELECTION SEMANTICS. These were the CLI's private helpers until 2026-07-27
// and moved here unchanged: They decide what counts as a match for a whole line
// and for a pattern SET, which has to be one answer the library gives, not one
// the CLI keeps to itself. vector reaching the matcher over FFI has to agree
// with `sublimation search` on -w and -x, and the occurrence field is built on
// exactly these spans. Every behavioral comment below was verified against
// /usr/bin/grep and the corpus gate holds them to it.

// [A-Za-z0-9_], grep -w's word alphabet -- explicit ranges, not isalnum(), so
// the locale can never shift the boundary set.
static int word_byte(unsigned char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '_';
}

// -w boundary test: span [s,e) of line[0..n) counts only when neither
// neighbor is a word byte (a line edge counts as non-word).
static int word_bounded(const uint8_t *line, size_t n, long s, long e) {
    if (s > 0 && word_byte(line[s - 1])) return 0;
    if ((size_t)e < n && word_byte(line[e])) return 0;
    return 1;
}

// Next candidate span for ONE pattern at or after `from`, with the -w word
// filter applied. A rejected candidate at start X resumes the scan at X + 1
// (grep's rule -- skipping the rest of the line would drop later words).
// regex_face: find_from reports only the LONGEST end per start, but grep -w
// admits any match length ('a-|a' on "a-b" must still hit the word "a",
// verified against /usr/bin/grep), so on rejection the field is walked again
// from the same start for the longest end that IS word-bounded. The walk runs
// over the whole line, so ^ and $ keep their meaning; probing a sub-slice
// would have let both fire at the slice's own edges.
static long search_next_match(const sublimation_search *s, int regex_face,
                              const char *line, size_t n, size_t from,
                              int wword, long *end_out) {
    const uint8_t *hay = (const uint8_t *)line;
    size_t off = from;
    while (off <= n) {
        long e = -1;
        long st = sublimation_search_find_from(s, line, n, off, &e);
        if (st < 0) return -1;
        if (!wword || word_bounded(hay, n, st, e)) { *end_out = e; return st; }
        if (regex_face) {
            long e2 = gnfa_start_longest(&s->g, s->imap, hay, n, (size_t)st, word_bounded);
            if (e2 >= 0) { *end_out = e2; return st; }
        }
        off = (size_t)st + 1;
    }
    return -1;
}

// Leftmost-longest across the set, additionally reporting WHICH pattern won.
// next_any is this with the pattern discarded -- one tie-break rule, not two.
static long next_any_pat(const sublimation_search *set, int nset, int regex_face,
                         const char *line, size_t n, size_t off, int wword,
                         long *end_out, int *pat_out) {
    long bs = -1, be = -1;
    int bp = -1;
    for (int p = 0; p < nset; p++) {
        long e = -1;
        long st = search_next_match(&set[p], regex_face, line, n, off, wword, &e);
        if (st < 0) continue;
        if (bs < 0 || st < bs || (st == bs && e > be)) { bs = st; be = e; bp = p; }
    }
    if (bs >= 0) {
        if (end_out) *end_out = be;
        if (pat_out) *pat_out = bp;
    }
    return bs;
}

long sublimation_search_next_any(const sublimation_search *set, int nset, int regex_face,
                                 const char *line, size_t n, size_t off,
                                 int wword, long *end_out) {
    return next_any_pat(set, nset, regex_face, line, n, off, wword, end_out, NULL);
}

size_t sublimation_search_spans(const sublimation_search *set, int nset, int regex_face,
                                const char *text, size_t n, int wword, int xline,
                                sublimation_match_span *out, size_t cap) {
    size_t found = 0, off = 0;
    while (off <= n) {
        long s, e = -1;
        int pat = -1;
        if (xline) { s = 0; e = (long)n; }   // -x: the line IS the match
        else s = next_any_pat(set, nset, regex_face, text, n, off, wword, &e, &pat);
        if (s < 0) break;
        if (e > s) {
            if (found < cap && out) {
                out[found].start = (uint32_t)s;
                out[found].end   = (uint32_t)e;
                out[found].pat   = xline ? -1 : pat;
            }
            ++found;
            off = (size_t)e;
        } else {
            // Zero-width: no span to record, but the scan must still advance or
            // it spins on the same position forever.
            off = (size_t)s + 1;
        }
        if (xline) break;
    }
    return found;
}

int sublimation_search_selects(const sublimation_search *set, int nset, int regex_face,
                               const char *line, size_t n, int xline, int wword) {
    for (int p = 0; p < nset; p++) {
        if (xline) {
            if (sublimation_search_full_match(&set[p], line, n)) return 1;
        } else {
            long e = -1;
            if (search_next_match(&set[p], regex_face, line, n, 0, wword, &e) >= 0) return 1;
        }
    }
    return 0;
}

void sublimation_occ_buf_init(sublimation_occ_buf *b) {
    b->occ = NULL; b->n = b->cap = 0;
    b->raw = NULL; b->raw_n = b->raw_cap = 0;
}

void sublimation_occ_buf_push(sublimation_occ_buf *b, uint32_t line_no,
                              const char *line, size_t len, size_t raw_len) {
    if (b->raw_n + raw_len > b->raw_cap) {
        size_t ncap = b->raw_cap ? b->raw_cap * 2 : 4096;
        while (ncap < b->raw_n + raw_len) ncap *= 2;
        char *nd = (char *)realloc(b->raw, ncap);
        if (!nd) return;
        b->raw = nd; b->raw_cap = ncap;
    }
    if (b->n == b->cap) {
        size_t ncap = b->cap ? b->cap * 2 : 64;
        sublimation_search_occ *no =
            (sublimation_search_occ *)realloc(b->occ, ncap * sizeof(*no));
        if (!no) return;
        b->occ = no; b->cap = ncap;
    }
    memcpy(b->raw + b->raw_n, line, raw_len);
    b->occ[b->n++] = (sublimation_search_occ){ .line_no = line_no,
                                               .off = (uint32_t)b->raw_n,
                                               .len = (uint32_t)len,
                                               .raw_len = (uint32_t)raw_len };
    b->raw_n += raw_len;
}

void sublimation_occ_buf_free(sublimation_occ_buf *b) {
    free(b->occ); free(b->raw);
    sublimation_occ_buf_init(b);
}

size_t sublimation_search_count(const sublimation_search *s, const char *input, size_t n) {
    if (!s->valid) return 0;
    const uint8_t *hay = (const uint8_t *)input;
    size_t m = s->pattern_len;
    const uint8_t *pat = sub_needle(s);

    if (s->mode == MODE_REGEX) return regex_count(s, hay, n);

    if (s->mode == MODE_FUZZY) {
        if (s->icase) return scan_kmismatch(hay, n, pat, m, s->k, 1);
        size_t r = scan_kmismatch_pre(hay, n, pat, m, s->k);
        if (r == (size_t)-1) return scan_kmismatch(hay, n, pat, m, s->k, 0);
        return r;
    }

    if (s->icase) return exact_count_folded(hay, n, pat, m, 1);
    return exact_count(hay, n, pat, m);
}

// THE DISPERSION FIELD. Everything here runs over the SPARSE span array; the
// haystack is never touched again. See sublimation_text.h for why that is the
// point rather than an optimisation.
int sublimation_dispersion_field(const sublimation_match_span *spans, size_t n,
                                 size_t haystack_len, sublimation_dispersion *out) {
    if (!spans || !out || n < 2) return 0;
    memset(out, 0, sizeof *out);
    out->matches = n;
    out->span_bytes = (size_t)(spans[n - 1].end - spans[0].start);
    out->density_per_kb = haystack_len
        ? (double)n * 1024.0 / (double)haystack_len : 0.0;

    const size_t ng = n - 1;
    double *gaps = (double *)malloc(ng * sizeof *gaps);
    uint64_t *gapu = (uint64_t *)malloc(ng * sizeof *gapu);
    if (!gaps || !gapu) { free(gaps); free(gapu); return 0; }
    for (size_t i = 0; i < ng; i++) {
        // Starts, not ends: the question is how often the pattern ARRIVES, which
        // an end-to-start gap would confound with how long each match is.
        double g = (double)spans[i + 1].start - (double)spans[i].start;
        gaps[i] = g;
        gapu[i] = (uint64_t)(g < 0 ? 0 : g);
    }

    out->stride_mean  = sublimation_mean_f64(gaps, ng);
    out->stride_stdev = ng > 1 ? sublimation_stdev_f64(gaps, ng) : 0.0;
    out->stride_max   = sublimation_max_f64(gaps, ng);
    {
        double denom = out->stride_stdev + out->stride_mean;
        out->burstiness = denom > 0.0
            ? (out->stride_stdev - out->stride_mean) / denom : 0.0;
    }
    // classify BEFORE the quantile calls: those sort in place, and a sorted copy
    // would report every pattern's gaps as SORTED, which is the classifier
    // answering a question about our scratch buffer instead of the data.
    out->gap_class = (int)sublimation_classify_u64(gapu, ng).disorder;
    {
        double *q = (double *)malloc(ng * sizeof *q);
        if (q) {
            memcpy(q, gaps, ng * sizeof *q);
            out->stride_p50 = sublimation_quantile_f64(q, ng, 0.50, 0);
            memcpy(q, gaps, ng * sizeof *q);
            out->stride_p90 = sublimation_quantile_f64(q, ng, 0.90, 0);
            memcpy(q, gaps, ng * sizeof *q);
            out->stride_p99 = sublimation_quantile_f64(q, ng, 0.99, 0);
            free(q);
        }
    }

    // Spectral Residual over the gap series: a burst is a run of short gaps, so
    // saliency on this series is exactly "here the pattern suddenly clustered".
    // The transform needs a POWER-OF-TWO length, so it runs over the largest
    // such prefix of the gap series. saliency_window reports what that was:
    // a peak index means nothing without knowing how much was looked at, and
    // silently scanning 512 of 900 arrivals while reporting as if for all of
    // them is the kind of quiet truncation this project treats as a defect.
    if (ng >= 8) {
        size_t n2 = 1;
        while ((n2 << 1) <= ng) n2 <<= 1;
        double *sal = (double *)calloc(n2, sizeof *sal);
        uint8_t *flg = (uint8_t *)calloc(n2, 1);
        // Returns 0 on SUCCESS.
        if (sal && flg &&
            sublimation_spectral_residual(gaps, n2, 3, 3.0, 3, sal, flg) == 0) {
            out->saliency_window = n2;
            for (size_t i = 0; i < n2; i++)
                if (sal[i] > out->saliency_max) { out->saliency_max = sal[i]; out->saliency_at = i; }
        }
        free(sal); free(flg);
    }

    // Matrix profile: discord is the least-like-anything window, motif the
    // most-repeated. Window of 8 needs a series several times longer to have a
    // non-trivial neighbour at all.
    if (ng >= 32) {
        const size_t m = 8;
        size_t nprof = ng - m + 1;
        double *mp = (double *)malloc(nprof * sizeof *mp);
        int64_t *mpi = (int64_t *)malloc(nprof * sizeof *mpi);
        if (mp && mpi && sublimation_matrix_profile(gaps, ng, m, mp, mpi) == 0) {
            double best = -1.0, worst = -1.0;
            size_t bi = 0, wi = 0;
            for (size_t i = 0; i < nprof; i++) {
                if (mp[i] > worst) { worst = mp[i]; wi = i; }
                if (best < 0.0 || mp[i] < best) { best = mp[i]; bi = i; }
            }
            if (worst >= 0.0) { out->discord = worst; out->discord_at = wi; }
            if (best  >= 0.0) { out->motif   = best;  out->motif_at   = bi; }
        }
        free(mp); free(mpi);
    }

    free(gaps); free(gapu);
    return 1;
}

size_t sublimation_search_fold_gaps(const char *pat, size_t len) {
    // ALWAYS 0 NOW, and the API stays so a caller need not care why. Every cased
    // character in a fold class is covered: same-lead pairs by a single position
    // with two byte members, the rest by an alternation over the class. -i no
    // longer narrows, so there is nothing to warn about.
    //
    // Kept rather than deleted because the PROPERTY is worth asserting: if a
    // future table ever fails to cover something, this is where that is said.
    (void)pat; (void)len;
    return 0;
}

// CAPTURE GROUPS, as a post-pass over ONE match span.
//
// The Glushkov field tracks a position SET with no submatch notion, and the
// compiler builds those positions in a single pass keeping no AST -- so group
// boundaries cannot be recovered from it at all. The occurrence field inverts
// that: the fast engine has already isolated the span, so this runs only over
// those bytes, and only when a substitution actually asks for a backreference.
//
// A PIKE VM, NOT A BACKTRACKER. The backtracker this replaced argued that a
// bounded span made its worst case harmless, and the bound was the line:
// `(a?){n}a{n}` doubled its cost per n, and `(a*)` over a 100k-byte line
// recursed once per repetition and took the stack. Here every thread advances
// in lockstep, one per program counter per byte, so the cost is span x program
// with no recursion on the input -- the same reason the field is linear.
//
// SUBGROUPS FOLLOW PERL'S RULES, not POSIX's. Threads run in priority order
// (greedy before lazy, left alternative before right) and the first thread to
// reach the span's end wins, so a group reports the parse a backtracker would
// find first, and a repeated group reports its last iteration. Python's re and
// PCRE agree; glibc's regexec does not on nested and repeated groups, where
// POSIX asks for the leftmost-longest SUBexpression instead. The WHOLE-match
// span is still POSIX's leftmost-longest -- that comes from the field, and this
// only divides it up.
//
// It accepts the same ERE subset the Glushkov face does, ^ and $ included:
// both are judged against the whole line, not the span, which is why the line
// is passed in.

typedef struct cap_node cap_node;
struct cap_node {
    enum { CN_CHAR, CN_ANY, CN_CLASS, CN_CONCAT, CN_ALT, CN_REP, CN_GROUP,
           CN_BOL, CN_EOL } k;
    unsigned char ch;
    uint8_t set[32];
    cap_node *a, *b;      // CONCAT/ALT children; REP/GROUP child in `a`
    int lo, hi;           // REP bounds; hi < 0 = unbounded
    int gidx;             // GROUP: 1-based capture index
    cap_node *next;       // arena chain
};

typedef struct {
    const char *p;
    cap_node   *arena;    // every node, for one free() walk
    int         ngroups;
    int         ok;
    int         icase;
} cap_parser;

static cap_node *cn_new(cap_parser *cp, int k) {
    cap_node *n = (cap_node *)calloc(1, sizeof *n);
    if (!n) { cp->ok = 0; return NULL; }
    n->k = k; n->next = cp->arena; cp->arena = n;
    return n;
}

static cap_node *cap_alt(cap_parser *cp);

static cap_node *cap_atom(cap_parser *cp) {
    if (!cp->ok) return NULL;
    char c = *cp->p;
    if (c == '(') {
        cp->p++;
        cap_node *g = cn_new(cp, CN_GROUP);
        if (!g) return NULL;
        g->gidx = ++cp->ngroups;
        g->a = cap_alt(cp);
        if (*cp->p == ')') cp->p++; else cp->ok = 0;
        return g;
    }
    if (c == '^' || c == '$') { cp->p++; return cn_new(cp, c == '^' ? CN_BOL : CN_EOL); }
    if (c == '.') { cp->p++; return cn_new(cp, CN_ANY); }
    if (c == '[') {
        cap_node *n = cn_new(cp, CN_CLASS);
        if (!n) return NULL;
        size_t rem = strlen(cp->p);
        size_t e = class_span(cp->p, rem, 0, n->set, cp->icase);
        if (!e) { cp->ok = 0; return n; }
        cp->p += e;
        return n;
    }
    if (c == '\\' && cp->p[1]) {
        cp->p++;
        cap_node *n = cn_new(cp, CN_CLASS);
        if (!n) return NULL;
        if (shorthand_set(*cp->p, n->set)) { cp->p++; return n; }
        // Any other escape is the next byte, literally -- same rule the
        // Glushkov parser uses, so the two agree on what a pattern means.
        n->k = CN_CHAR; n->ch = (unsigned char)*cp->p; cp->p++;
        return n;
    }
    if (c == '\0' || c == '|' || c == ')') { cp->ok = 0; return NULL; }
    cap_node *n = cn_new(cp, CN_CHAR);
    if (!n) return NULL;
    n->ch = (unsigned char)c; cp->p++;
    return n;
}

// One quantifier per atom, with the field parser's grammar and refusals:
// {n} {n,} {n,m} {,m}, nothing past FIELD_DUP_MAX, no m below n.
static cap_node *cap_repeat(cap_parser *cp) {
    cap_node *a = cap_atom(cp);
    if (!cp->ok || !a) return a;
    char c = *cp->p;
    int lo, hi;
    if (c == '*') { lo = 0; hi = -1; cp->p++; }
    else if (c == '+') { lo = 1; hi = -1; cp->p++; }
    else if (c == '?') { lo = 0; hi = 1; cp->p++; }
    else if (c == '{') {
        cp->p++;
        int l = 0, h = -2, hasl = 0, hash = 0;
        while (*cp->p >= '0' && *cp->p <= '9' && l <= FIELD_DUP_MAX) { l = l * 10 + (*cp->p - '0'); cp->p++; hasl = 1; }
        if (*cp->p == ',') {
            cp->p++; h = -1;
            if (*cp->p >= '0' && *cp->p <= '9') { h = 0; hash = 1; while (*cp->p >= '0' && *cp->p <= '9' && h <= FIELD_DUP_MAX) { h = h * 10 + (*cp->p - '0'); cp->p++; } }
        } else h = l;
        if ((!hasl && !hash) || *cp->p != '}' || l > FIELD_DUP_MAX || h > FIELD_DUP_MAX ||
            (h >= 0 && h < l)) { cp->ok = 0; return a; }
        cp->p++; lo = l; hi = h;
    }
    else return a;
    cap_node *r = cn_new(cp, CN_REP);
    if (!r) return NULL;
    r->a = a; r->lo = lo; r->hi = hi;
    return r;
}

static cap_node *cap_concat(cap_parser *cp) {
    cap_node *head = NULL;
    while (cp->ok && *cp->p && *cp->p != '|' && *cp->p != ')') {
        cap_node *r = cap_repeat(cp);
        if (!cp->ok || !r) break;
        if (!head) { head = r; continue; }
        cap_node *c = cn_new(cp, CN_CONCAT);
        if (!c) return NULL;
        c->a = head; c->b = r; head = c;
    }
    return head;
}

static cap_node *cap_alt(cap_parser *cp) {
    cap_node *l = cap_concat(cp);
    while (cp->ok && *cp->p == '|') {
        cp->p++;
        cap_node *r = cap_concat(cp);
        cap_node *n = cn_new(cp, CN_ALT);
        if (!n) return NULL;
        n->a = l; n->b = r; l = n;
    }
    return l;
}

// The program. SPLIT tries x before y, which is the whole of the priority rule.
// LOOP is the back edge of an unbounded repeat: x is the loop head, y its exit.
enum { PK_CHAR, PK_ANY, PK_CLASS, PK_SPLIT, PK_JMP, PK_LOOP, PK_SAVE, PK_BOL, PK_EOL, PK_MATCH };
typedef struct { int op, x, y; unsigned char ch; const uint8_t *set; } pk_ins;
typedef struct { pk_ins *ins; int n, cap; int ok; int depth, max_depth; } pk_prog;

// The program grows with every unrolled copy of a bounded repeat; past this it
// is refused rather than built. A pattern that compiled for the field is far
// inside it (the field holds 128 positions).
#define PK_MAX_PROG (1 << 16)

static int pk_emit(pk_prog *pg, int op) {
    if (!pg->ok) return 0;
    if (pg->n == pg->cap) {
        int nc = pg->cap ? pg->cap * 2 : 64;
        pk_ins *ni = nc <= PK_MAX_PROG ? (pk_ins *)realloc(pg->ins, (size_t)nc * sizeof *ni) : NULL;
        if (!ni) { pg->ok = 0; return 0; }
        pg->ins = ni; pg->cap = nc;
    }
    pg->ins[pg->n] = (pk_ins){ .op = op };
    return pg->n++;
}

static void pk_compile(pk_prog *pg, const cap_node *n) {
    if (!n || !pg->ok) return;
    int at, j;
    switch (n->k) {
    case CN_CHAR:  at = pk_emit(pg, PK_CHAR); if (pg->ok) pg->ins[at].ch = n->ch; break;
    case CN_ANY:   pk_emit(pg, PK_ANY); break;
    case CN_CLASS: at = pk_emit(pg, PK_CLASS); if (pg->ok) pg->ins[at].set = n->set; break;
    case CN_BOL:   pk_emit(pg, PK_BOL); break;
    case CN_EOL:   pk_emit(pg, PK_EOL); break;
    case CN_CONCAT: pk_compile(pg, n->a); pk_compile(pg, n->b); break;
    case CN_ALT:
        at = pk_emit(pg, PK_SPLIT);
        if (pg->ok) pg->ins[at].x = pg->n;
        pk_compile(pg, n->a);
        j = pk_emit(pg, PK_JMP);
        if (pg->ok) pg->ins[at].y = pg->n;
        pk_compile(pg, n->b);
        if (pg->ok) pg->ins[j].x = pg->n;
        break;
    case CN_GROUP:
        at = pk_emit(pg, PK_SAVE); if (pg->ok) pg->ins[at].x = 2 * n->gidx;
        pk_compile(pg, n->a);
        at = pk_emit(pg, PK_SAVE); if (pg->ok) pg->ins[at].x = 2 * n->gidx + 1;
        break;
    case CN_REP: {
        // Required copies, then either a greedy loop on one more or the
        // optional copies, each skipping to the common end when declined.
        for (int i = 0; i < n->lo && pg->ok; i++) pk_compile(pg, n->a);
        if (n->hi < 0) {
            int loop = pk_emit(pg, PK_SPLIT);
            if (pg->ok) pg->ins[loop].x = pg->n;
            if (++pg->depth > pg->max_depth) pg->max_depth = pg->depth;
            pk_compile(pg, n->a);
            pg->depth--;
            j = pk_emit(pg, PK_LOOP);
            if (pg->ok) { pg->ins[j].x = loop; pg->ins[loop].y = pg->ins[j].y = pg->n; }
        } else {
            int opt = n->hi - n->lo, *splits = opt > 0 ? (int *)malloc((size_t)opt * sizeof *splits) : NULL;
            if (opt > 0 && !splits) { pg->ok = 0; break; }
            for (int i = 0; i < opt && pg->ok; i++) {
                splits[i] = pk_emit(pg, PK_SPLIT);
                if (pg->ok) pg->ins[splits[i]].x = pg->n;
                pk_compile(pg, n->a);
            }
            for (int i = 0; i < opt && pg->ok; i++) pg->ins[splits[i]].y = pg->n;
            free(splits);
        }
        break;
    }
    }
}

typedef struct { int pc; uint32_t *caps; } pk_thread;
typedef struct { pk_thread *t; uint32_t *store; int n; } pk_list;
typedef struct {
    const pk_prog *pg;
    const uint8_t *line; size_t n;
    int icase, nslots, passes;
    int *mark, *enq, gen;   // mark: per (pass, pc); enq: per consuming pc
    int *stk, *stk_pass;    // explicit stack: pc, or ~slot with the value to restore
    uint32_t *stk_val;
} pk_vm;

// Follow every epsilon edge from pc at offset i in priority order and enqueue
// the byte-consuming (or matching) instructions reached. Iterative: a restore
// entry undoes a SAVE once everything behind it has been explored, so the
// depth is the program's, never the input's.
//
// PASSES. An iteration that consumed bytes ends by walking the rest of its body
// (a group's closing SAVE, say) and then taking the back edge, and the empty
// iteration Perl takes next walks those SAME instructions again at the same
// offset. One mark per instruction per step would kill it. So a back edge into
// a loop head not yet seen at this pass starts the new iteration one pass up;
// a back edge into a head already seen at its pass is the zero-width iteration,
// and leaves. Passes are bounded by loop nesting, and enqueueing still dedups
// by instruction alone, so the list stays one thread per instruction.
static void pk_add(pk_vm *vm, pk_list *l, int pc0, uint32_t *caps, size_t i) {
    const int np = vm->pg->n;
    int sp = 0;
    vm->stk[sp] = pc0; vm->stk_pass[sp++] = 0;
    while (sp > 0) {
        --sp;
        int e = vm->stk[sp], pass = vm->stk_pass[sp];
        if (e < 0) { caps[~e] = vm->stk_val[sp]; continue; }
        int *mk = &vm->mark[(size_t)pass * (size_t)np + (size_t)e];
        if (*mk == vm->gen) continue;
        *mk = vm->gen;
        const pk_ins *in = &vm->pg->ins[e];
#define PK_PUSH(pc, ps) do { vm->stk[sp] = (pc); vm->stk_pass[sp++] = (ps); } while (0)
        switch (in->op) {
        case PK_JMP:  PK_PUSH(in->x, pass); break;
        // Back at a loop head already seen at this pass means the iteration
        // consumed nothing. Perl takes that iteration and then leaves the
        // loop, so the thread continues at the exit carrying its captures --
        // ahead of the path that declined the iteration, which is the
        // priority Perl gives it.
        case PK_LOOP:
            if (vm->mark[(size_t)pass * (size_t)np + (size_t)in->x] == vm->gen) PK_PUSH(in->y, pass);
            else if (pass + 1 < vm->passes) PK_PUSH(in->x, pass + 1);
            break;
        case PK_SPLIT: PK_PUSH(in->y, pass); PK_PUSH(in->x, pass); break;
        case PK_SAVE:
            vm->stk_val[sp] = caps[in->x]; PK_PUSH(~in->x, pass);
            caps[in->x] = (uint32_t)i;
            PK_PUSH(e + 1, pass);
            break;
        case PK_BOL: if (i == 0) PK_PUSH(e + 1, pass); break;
        case PK_EOL: if (i == vm->n) PK_PUSH(e + 1, pass); break;
        default: {
            if (vm->enq[e] == vm->gen) break;
            vm->enq[e] = vm->gen;
            pk_thread *t = &l->t[l->n];
            t->pc = e;
            t->caps = l->store + (size_t)l->n * (size_t)vm->nslots;
            memcpy(t->caps, caps, (size_t)vm->nslots * sizeof *caps);
            l->n++;
        }
        }
#undef PK_PUSH
    }
}

static int pk_byte_ok(const pk_vm *vm, const pk_ins *in, unsigned char c) {
    switch (in->op) {
    case PK_ANY:   return 1;
    case PK_CLASS: return (in->set[c >> 3] >> (c & 7)) & 1;
    case PK_CHAR:  return vm->icase ? fold(c, 1) == fold(in->ch, 1) : c == in->ch;
    default:       return 0;
    }
}

int sublimation_search_captures_at(const char *pat, const char *line, size_t n,
                                   size_t start, size_t end, int icase,
                                   sublimation_match_span *groups,
                                   size_t max_groups, size_t *ngroups) {
    if (ngroups) *ngroups = 0;
    if (!pat || !line || !groups || max_groups == 0 || start > end || end > n) return 0;
    cap_parser cp = { pat, NULL, 0, 1, icase };
    cap_node *root = cap_alt(&cp);
    int rc = 0;
    pk_prog pg = { NULL, 0, 0, 1, 0, 0 };
    if (cp.ok && *cp.p == '\0' && cp.ngroups > 0) {
        pk_compile(&pg, root);
        pk_emit(&pg, PK_MATCH);
    } else pg.ok = 0;

    const int nslots = 2 * (cp.ngroups + 1);
    const int passes = pg.max_depth + 2;
    const size_t np = (size_t)pg.n, ns = (size_t)nslots, npp = np * (size_t)passes;
    pk_vm vm = { &pg, (const uint8_t *)line, n, icase, nslots, passes,
                 NULL, NULL, 0, NULL, NULL, NULL };
    pk_list a = { NULL, NULL, 0 }, b = { NULL, NULL, 0 };
    uint32_t *caps = NULL;
    if (pg.ok) {
        // Every pc enters a list at most once per step, and each visited
        // (pass, pc) pushes at most two stack entries, plus the seed.
        vm.mark = (int *)calloc(npp, sizeof *vm.mark);
        vm.enq = (int *)calloc(np, sizeof *vm.enq);
        vm.stk = (int *)malloc((2 * npp + 1) * sizeof *vm.stk);
        vm.stk_pass = (int *)malloc((2 * npp + 1) * sizeof *vm.stk_pass);
        vm.stk_val = (uint32_t *)malloc((2 * npp + 1) * sizeof *vm.stk_val);
        a.t = (pk_thread *)malloc(np * sizeof *a.t);
        b.t = (pk_thread *)malloc(np * sizeof *b.t);
        a.store = (uint32_t *)malloc(np * ns * sizeof *a.store);
        b.store = (uint32_t *)malloc(np * ns * sizeof *b.store);
        caps = (uint32_t *)malloc(ns * sizeof *caps);
    }
    if (pg.ok && vm.mark && vm.enq && vm.stk && vm.stk_pass && vm.stk_val &&
        a.t && b.t && a.store && b.store && caps) {
        for (size_t s = 0; s < ns; s++) caps[s] = UINT32_MAX;
        pk_list *cur = &a, *nxt = &b;
        vm.gen = 1;
        pk_add(&vm, cur, 0, caps, start);
        for (size_t i = start; cur->n > 0; i++) {
            if (i == end) {
                // The first thread at MATCH, in priority order, is the parse.
                for (int k = 0; k < cur->n; k++) {
                    if (pg.ins[cur->t[k].pc].op != PK_MATCH) continue;
                    const uint32_t *c = cur->t[k].caps;
                    size_t out = 0;
                    for (int g = 1; g <= cp.ngroups && out < max_groups; g++, out++) {
                        int set = c[2 * g] != UINT32_MAX && c[2 * g + 1] != UINT32_MAX;
                        groups[out].start = set ? c[2 * g] : 0;
                        groups[out].end   = set ? c[2 * g + 1] : 0;
                        groups[out].pat   = set ? g : -1;   // -1: group did not participate
                    }
                    if (ngroups) *ngroups = out;
                    rc = 1;
                    break;
                }
                break;
            }
            nxt->n = 0;
            vm.gen++;
            const unsigned char ch = (unsigned char)line[i];
            for (int k = 0; k < cur->n; k++) {
                const pk_ins *in = &pg.ins[cur->t[k].pc];
                if (pk_byte_ok(&vm, in, ch)) pk_add(&vm, nxt, cur->t[k].pc + 1, cur->t[k].caps, i + 1);
            }
            pk_list *t = cur; cur = nxt; nxt = t;
        }
    }
    free(vm.mark); free(vm.enq); free(vm.stk); free(vm.stk_pass); free(vm.stk_val);
    free(a.t); free(b.t); free(a.store); free(b.store); free(caps);
    free(pg.ins);
    for (cap_node *q = cp.arena; q; ) { cap_node *nx = q->next; free(q); q = nx; }
    return rc;
}
