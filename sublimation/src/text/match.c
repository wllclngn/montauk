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

static size_t class_span(const char *p, size_t len, size_t i, uint8_t *S, int icase) {
    i++;
    int neg = 0;
    if (i < len && p[i] == '^') { neg = 1; i++; }
    for (int first = 1; i < len && (first || p[i] != ']'); first = 0) {
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
typedef struct { int nullable; uint64_t first, last; } gattr_t;
// fold_left counts bytes until the one that differs under icase; fold_byte is
// the counterpart to admit there. Only the LAST byte of a folded character
// ever differs (see case_fold_table.h), so one pending byte is enough.
typedef struct { const char *p; gnfa_t *g; int fold_left; unsigned char fold_byte; } gpar_t;

static gattr_t g_alt(gpar_t *x);

static gattr_t g_atom(gpar_t *x) {
    gattr_t a = {0, 0, 0};
    char c = *x->p;
    int icase = x->g->icase;
    if (c == '(') {
        x->p++; a = g_alt(x);
        if (*x->p == ')') x->p++; else x->g->ok = 0;
        return a;
    }
    if (x->g->npos >= 64) { x->g->ok = 0; return a; }
    int pos = x->g->npos++;
    uint8_t *S = x->g->setb[pos]; memset(S, 0, 32);
    if (c == '.') { memset(S, 0xff, 32); x->p++; }
    else if (c == '[') {
        // strlen of the REMAINING pattern, not the whole one: x->p is the
        // parser's cursor. Patterns are capped at 64 positions, so this is a
        // few tens of bytes at compile time, never in a scan.
        size_t rem = strlen(x->p);
        size_t e = class_span(x->p, rem, 0, S, icase);
        // On an unterminated class the cursor still advances to the end: the
        // enclosing concat loop only stops on NUL, '|' or ')', not on ok.
        x->p += e ? e : rem;
        if (!e) x->g->ok = 0;
    } else {
        if (c == '\\' && x->p[1]) {
            x->p++; c = *x->p;
            // \w \W \s \S fill the whole position set; every other escape is
            // still "the next byte, literally".
            if (shorthand_set(c, S)) { x->p++; goto atom_done; }
        }
        unsigned char b = (unsigned char)c;
        gset_byte(S, b, icase);
        if (icase) {
            if (x->fold_left > 0 && --x->fold_left == 0) {
                // The differing byte of a character whose fold was resolved at
                // its lead: admit the counterpart here, in this position's set.
                gset_byte(S, x->fold_byte, 0);
            } else if (x->fold_left == 0 && b >= 0xC0) {
                uint32_t cp = 0;
                int n = u8_decode((const unsigned char *)x->p, strlen(x->p), &cp);
                uint8_t alt = n >= 2 ? fold_alt_last(cp) : 0;
                if (alt) { x->fold_left = n - 1; x->fold_byte = alt; }
            }
        }
        x->p++;
    }
atom_done:
    a.nullable = 0; a.first = (1ull<<pos); a.last = (1ull<<pos);
    return a;
}

static gattr_t g_repeat(gpar_t *x) {
    int pos_before = x->g->npos;
    gattr_t a = g_atom(x);
    char c = *x->p;
    if (c == '*' || c == '+') {
        x->p++;
        uint64_t t = a.last; while (t) { int i = __builtin_ctzll(t); x->g->follow[i] |= a.first; t &= t-1; }
        if (c == '*') a.nullable = 1;
    } else if (c == '?') { x->p++; a.nullable = 1; }
    else if (c == '{') {
        // Bounded repeat on a single-position atom: lo required plus (hi-lo)
        // optional copies. {m,} unbounded is not supported here.
        if (x->g->npos != pos_before + 1) { x->g->ok = 0; return a; }
        x->p++;
        int lo = 0, hi = -2, haslo = 0;
        while (*x->p >= '0' && *x->p <= '9') { lo = lo*10 + (*x->p - '0'); x->p++; haslo = 1; }
        if (*x->p == ',') {
            x->p++; hi = -1;
            if (*x->p >= '0' && *x->p <= '9') { hi = 0; while (*x->p >= '0' && *x->p <= '9') { hi = hi*10 + (*x->p - '0'); x->p++; } }
        } else hi = lo;
        if (!haslo || *x->p != '}' || hi == -1 || hi > 60) { x->g->ok = 0; return a; }
        x->p++;
        if (hi == 0) {
            // {0} / {0,0}: zero copies. Reclaim the atom's single position so it
            // contributes nothing -- leaving it nullable-but-present let it still
            // match one copy.
            x->g->npos = pos_before;
            a.first = 0; a.last = 0; a.nullable = 1;
            return a;
        }
        uint8_t setcopy[32]; memcpy(setcopy, x->g->setb[pos_before], 32);
        if (lo == 0) a.nullable = 1;
        for (int ci = 1; ci < hi; ci++) {
            if (x->g->npos >= 64) { x->g->ok = 0; return a; }
            int p = x->g->npos++;
            memcpy(x->g->setb[p], setcopy, 32);
            gattr_t b = { (ci >= lo) ? 1 : 0, (1ull<<p), (1ull<<p) };
            uint64_t t = a.last; while (t) { int i = __builtin_ctzll(t); x->g->follow[i] |= b.first; t &= t-1; }
            uint64_t nf = a.first | (a.nullable ? b.first : 0);
            uint64_t nl = b.last | (b.nullable ? a.last : 0);
            a.first = nf; a.last = nl; a.nullable = a.nullable && b.nullable;
        }
    }
    return a;
}

static gattr_t g_concat(gpar_t *x) {
    gattr_t a = {1, 0, 0}; int any = 0;
    // `&& x->g->ok`: once a position-cap or syntax error trips ok, g_atom stops
    // consuming input, so without this guard the loop spins forever on an
    // over-64-position pattern instead of returning invalid.
    while (*x->p && *x->p != '|' && *x->p != ')' && x->g->ok) {
        gattr_t b = g_repeat(x);
        if (!any) { a = b; any = 1; }
        else {
            uint64_t t = a.last; while (t) { int i = __builtin_ctzll(t); x->g->follow[i] |= b.first; t &= t-1; }
            uint64_t nf = a.first | (a.nullable ? b.first : 0);
            uint64_t nl = b.last | (b.nullable ? a.last : 0);
            a.first = nf; a.last = nl; a.nullable = a.nullable && b.nullable;
        }
    }
    return a;
}

static gattr_t g_alt(gpar_t *x) {
    gattr_t a = g_concat(x);
    while (*x->p == '|' && x->g->ok) {
        x->p++; gattr_t b = g_concat(x);
        a.first |= b.first; a.last |= b.last; a.nullable = a.nullable || b.nullable;
    }
    return a;
}

static int build_gnfa(const char *pat, gnfa_t *g, int icase) {
    memset(g, 0, sizeof(*g)); g->ok = 1; g->icase = icase;
    char buf[1024];
    size_t len = strlen(pat), s = 0, e = len;
    if (e > 0 && pat[0] == '^') { g->anchored_start = 1; s = 1; }
    if (e > s && pat[e - 1] == '$') { g->anchored_end = 1; e--; }
    if (e - s >= sizeof(buf)) return 0;
    // Anchor-only / empty body ("^", "$", "^$", ""): a legal zero-width,
    // nullable pattern with no positions. sed's own insertion idioms
    // (s/^/P /, s/$/ S/) depend on it; the Thompson engine this replaced
    // accepted it, so rejecting it was a v8.0.0 parity regression.
    if (e == s) {
        g->npos = 0; g->first = 0; g->last = 0; g->nullable_all = 1;
        return 1;
    }
    memcpy(buf, pat + s, e - s); buf[e - s] = '\0';
    gpar_t x = { buf, g, 0, 0 };
    gattr_t a = g_alt(&x);
    if (!g->ok || *x.p != '\0' || g->npos == 0) return 0;
    g->first = a.first; g->last = a.last; g->nullable_all = a.nullable;
    return 1;
}

// Build the per-byte position map. Case-insensitivity is already folded into
// each position's set at compile time (see gset_byte), so this is a plain map.
static void build_imap(const gnfa_t *g, uint64_t I[256]) {
    for (int c = 0; c < 256; c++) {
        uint64_t m = 0;
        for (int i = 0; i < g->npos; i++) {
            if ((g->setb[i][c>>3] >> (c&7)) & 1) m |= (1ull << i);
        }
        I[c] = m;
    }
}

// Reach-closure memo. reach(D) = first | union(follow[i], i in D), memoized --
// the position-NFA's transition closure cached on the fly, keyed by state set.
typedef struct { uint64_t key, reach; } reach_ent;
#define REACH_BITS 13
#define REACH_CAP  (1u << REACH_BITS)

static inline uint64_t reach_of(uint64_t D, const gnfa_t *g, reach_ent *cache) {
    if (D == 0) return g->first;
    size_t h = (size_t)((D * 0x9E3779B97F4A7C15ull) >> (64 - REACH_BITS));
    size_t probes = 0;
    while (cache[h].key && cache[h].key != D) {
        h = (h + 1) & (REACH_CAP - 1);
        // A pathological pattern can produce more than REACH_CAP distinct state
        // sets and fill the table; compute the reach without memoizing rather
        // than probe forever.
        if (++probes >= REACH_CAP) {
            uint64_t r = g->first, tt = D;
            while (tt) { int i = __builtin_ctzll(tt); r |= g->follow[i]; tt &= tt - 1; }
            return r;
        }
    }
    if (cache[h].key == D) return cache[h].reach;
    uint64_t reach = g->first, t = D;
    while (t) { int i = __builtin_ctzll(t); reach |= g->follow[i]; t &= t - 1; }
    cache[h].key = D; cache[h].reach = reach;
    return reach;
}

// Full-field match-end count over hay[0..n). Byte-parity reference for the regex
// face; the prefilter and class fast path must reproduce this exactly. `I` is
// the compile-time per-byte position map (sublimation_search.imap).
static size_t scan_gnfa(const uint8_t *hay, size_t n, const gnfa_t *g,
                        const uint64_t I[256]) {
    if (g->nullable_all && !g->anchored_start && !g->anchored_end) return n + 1;
    // Anchor-only pattern (npos == 0): exactly one zero-width match, at the
    // start for ^ or the end for $; ^$ only matches the empty field.
    if (g->npos == 0) {
        if (g->anchored_start && g->anchored_end) return n == 0 ? 1 : 0;
        return 1;
    }
    uint64_t D = 0; size_t count = 0;
    if (g->anchored_start || g->anchored_end) {
        for (size_t j = 0; j < n; j++) {
            uint64_t seed = (!g->anchored_start || j == 0) ? g->first : 0;
            uint64_t reach = seed, t = D;
            while (t) { int i = __builtin_ctzll(t); reach |= g->follow[i]; t &= t-1; }
            D = reach & I[(unsigned char)hay[j]];
            if ((D & g->last) && (!g->anchored_end || j + 1 == n)) count++;
        }
        return count;
    }
    reach_ent *cache = calloc(REACH_CAP, sizeof(reach_ent));
    if (!cache) {
        // Allocation failure: no-cache scan (same fallback convention as the
        // fuzzy face). Recomputes reach per step; byte-identical count.
        for (size_t j = 0; j < n; j++) {
            uint64_t reach = g->first, t = D;
            while (t) { int i = __builtin_ctzll(t); reach |= g->follow[i]; t &= t - 1; }
            D = reach & I[(unsigned char)hay[j]];
            if (D & g->last) count++;
        }
        return count;
    }
    for (size_t j = 0; j < n; j++) {
        D = reach_of(D, g, cache) & I[(unsigned char)hay[j]];
        if (D & g->last) count++;
    }
    free(cache);
    return count;
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

static size_t gnfa_range(const uint8_t *hay, size_t a, size_t b, const uint64_t I[256],
                         const gnfa_t *g, reach_ent *cache) {
    uint64_t D = 0; size_t count = 0;
    for (size_t j = a; j < b; j++) {
        D = reach_of(D, g, cache) & I[hay[j]];
        if (D & g->last) count++;
    }
    return count;
}

// Prefiltered regex count: anchor on a required literal, run the field only over
// coalesced regions around its occurrences. *used stays 0 (result meaningless) when
// the pattern is outside the sound subset, so the caller falls back. Provably byte-
// identical to the full field on the subset.
static size_t regex_prefiltered(const uint8_t *hay, size_t n, const char *pat,
                                const gnfa_t *g, const uint64_t I[256], int *used) {
    *used = 0;
    if (g->anchored_start || g->anchored_end || g->nullable_all) return 0;
    int ml = regex_maxlen(pat);
    if (ml < 1 || ml > 60) return 0;
    uint8_t lit[64];
    int litlen = extract_literal(pat, lit, 64);
    if (litlen < 2) return 0;
    // Data-relative rarest byte in the literal, same live histogram exact_count
    // reads -- was the static english_freq table, unified 2026-07-27.
    uint32_t hist[256]; byte_hist(hay, n, hist);
    int probe_off = 0; uint32_t bestf = hist[lit[0]];
    for (int i = 1; i < litlen; i++) {
        uint32_t f = hist[lit[i]];
        if (f < bestf) { bestf = f; probe_off = i; }
    }
    if (probe_off != 0 && bestf * 2 >= hist[lit[0]]) probe_off = 0;
    unsigned char probe = lit[probe_off];
    reach_ent *cache = calloc(REACH_CAP, sizeof(reach_ent));
    if (!cache) return 0;
    size_t count = 0, reg_start = 0, reg_end = 0; int have = 0;
    const uint8_t *end = hay + n;
    for (const uint8_t *q = hay; ; ) {
        const uint8_t *hit = memchr(q, probe, (size_t)(end - q));
        if (!hit) break;
        size_t h = (size_t)(hit - hay);
        if (h >= (size_t)probe_off && h - (size_t)probe_off + (size_t)litlen <= n
            && memcmp(hay + h - probe_off, lit, (size_t)litlen) == 0) {
            size_t p = h - (size_t)probe_off;
            size_t ws = (p >= (size_t)(ml - 1)) ? p - (size_t)(ml - 1) : 0;
            size_t we = (p + (size_t)ml < n) ? p + (size_t)ml : n;
            if (!have) { reg_start = ws; reg_end = we; have = 1; }
            else if (ws <= reg_end) { if (we > reg_end) reg_end = we; }
            else { count += gnfa_range(hay, reg_start, reg_end, I, g, cache); reg_start = ws; reg_end = we; }
        }
        q = hit + 1;
    }
    if (have) count += gnfa_range(hay, reg_start, reg_end, I, g, cache);
    free(cache);
    *used = 1;
    return count;
}

// Regex count dispatch. Prefilter where applicable, else the class fast path, else
// the full field -- all byte-identical to the full field.
static size_t regex_count(const sublimation_search *s, const uint8_t *hay, size_t n) {
    // Anchor-only patterns have no positions for the prefilter or class field
    // to anchor on; the full field handles their zero-width semantics directly.
    if (s->g.npos == 0) return scan_gnfa(hay, n, &s->g, s->imap);
    if (s->icase) return scan_gnfa(hay, n, &s->g, s->imap);
    int used = 0;
    size_t r = regex_prefiltered(hay, n, s->pattern, &s->g, s->imap, &used);
    if (used) return r;
    uint8_t sets[64][32];
    int L = parse_classes(s->pattern, sets, 64);
    if (L > 0) { size_t c = scan_classfield(hay, n, sets, L); if (c != (size_t)-1) return c; }
    return scan_gnfa(hay, n, &s->g, s->imap);
}

// Fixed-start Glushkov walk: longest match-end for a match starting exactly at
// `start`, or -1. No restart when the field goes empty (fixed start, not a scan).
static long gnfa_start_longest(const gnfa_t *g, const uint64_t I[256],
                               const uint8_t *hay, size_t n, size_t start) {
    long best = -1;
    if (g->nullable_all && (!g->anchored_end || start == n)) best = (long)start;
    uint64_t D = 0; int consumed = 0;
    for (size_t j = start; j < n; j++) {
        uint64_t cand;
        if (!consumed) cand = g->first;
        else { cand = 0; uint64_t t = D; while (t) { int i = __builtin_ctzll(t); cand |= g->follow[i]; t &= t-1; } }
        D = cand & I[hay[j]];
        consumed = 1;
        if (D == 0) break;
        if (D & g->last) { if (!g->anchored_end || j + 1 == n) best = (long)(j + 1); }
    }
    return best;
}

// Whole-input match: does the regex match hay[0..n) end to end?
static int gnfa_full(const gnfa_t *g, const uint64_t I[256], const uint8_t *hay, size_t n) {
    if (n == 0) return g->nullable_all;
    uint64_t D = g->first & I[hay[0]];
    if (D == 0) return 0;
    for (size_t j = 1; j < n; j++) {
        uint64_t reach = 0, t = D;
        while (t) { int i = __builtin_ctzll(t); reach |= g->follow[i]; t &= t-1; }
        D = reach & I[hay[j]];
        if (D == 0) return 0;
    }
    return (D & g->last) != 0;
}

// Public API

void sublimation_search_compile(sublimation_search *out, const char *pattern,
                                size_t len, unsigned flags, int k) {
    memset(out, 0, sizeof(*out));
    out->icase = (flags & SUBLIMATION_SEARCH_ICASE) ? 1 : 0;
    out->k = k > 0 ? k : 0;
    if (len > SUBLIMATION_SEARCH_MAX_PATTERN) { out->valid = 0; return; }
    memcpy(out->pattern, pattern, len);
    out->pattern[len] = '\0';
    out->pattern_len = len;

    if (k > 0) {
        out->mode = MODE_FUZZY;
        out->valid = (len > 0);
    } else if (flags & SUBLIMATION_SEARCH_FIXED) {
        out->mode = MODE_EXACT;
        out->valid = (len > 0);
    } else {
        out->mode = MODE_REGEX;
        // Regex compiles from the NUL-terminated pattern copy, so an embedded NUL
        // truncates the expression there -- unlike the literal/fuzzy paths above,
        // which honor `len` byte-for-byte. Threading `len` through the whole regex
        // parser is deferred; regex patterns are C strings in every current caller.
        out->valid = build_gnfa(out->pattern, &out->g, out->icase);
        // The per-byte position map depends only on (pattern, icase): build it
        // once here so match/count calls never rebuild it.
        if (out->valid) build_imap(&out->g, out->imap);
    }
}

int sublimation_search_valid(const sublimation_search *s) { return s->valid; }

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
static_assert(sizeof(sublimation_search) == 5696,
              "sublimation_search grew: update every foreign mirror "
              "(components/vector/src/ffi.rs) and this assert together");

size_t sublimation_search_sizeof(void) { return sizeof(sublimation_search); }

int sublimation_search_full_match(const sublimation_search *s, const char *input, size_t n) {
    if (!s->valid) return 0;
    const uint8_t *hay = (const uint8_t *)input;
    size_t m = s->pattern_len;
    const uint8_t *pat = (const uint8_t *)s->pattern;
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
    const uint8_t *pat = (const uint8_t *)s->pattern;

    if (s->mode == MODE_REGEX) {
        // size_t, not int: a multi-GB haystack (montauk analyzes them) overflows
        // an int start/limit and breaks the scan.
        size_t start_limit = s->g.anchored_start ? 1 : n + 1;
        for (size_t start = from; start < start_limit; ++start) {
            long e = gnfa_start_longest(&s->g, s->imap, hay, n, start);
            if (e >= 0) { if (end_out) *end_out = e; return (long)start; }
        }
        return -1;
    }

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
static int word_bounded(const char *line, size_t n, long s, long e) {
    if (s > 0 && word_byte((unsigned char)line[s - 1])) return 0;
    if ((size_t)e < n && word_byte((unsigned char)line[e])) return 0;
    return 1;
}

// Next candidate span for ONE pattern at or after `from`, with the -w word
// filter applied. A rejected candidate at start X resumes the scan at X + 1
// (grep's rule -- skipping the rest of the line would drop later words).
// regex_face: find_from reports only the LONGEST end per start, but grep -w
// admits any match length ('a-|a' on "a-b" must still hit the word "a",
// verified against /usr/bin/grep), so on rejection the shorter ends at the
// same start are probed through full_match. ^ is already satisfied (the
// start came from find_from); $-anchored patterns skip the probe since their
// matches may only end at n.
static long search_next_match(const sublimation_search *s, int regex_face,
                              const char *line, size_t n, size_t from,
                              int wword, long *end_out) {
    size_t off = from;
    while (off <= n) {
        long e = -1;
        long st = sublimation_search_find_from(s, line, n, off, &e);
        if (st < 0) return -1;
        if (!wword || word_bounded(line, n, st, e)) { *end_out = e; return st; }
        if (regex_face && !s->g.anchored_end) {
            for (long e2 = e - 1; e2 >= st; e2--) {
                if (!word_bounded(line, n, st, e2)) continue;
                if (sublimation_search_full_match(s, line + st, (size_t)(e2 - st))) {
                    *end_out = e2;
                    return st;
                }
            }
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
    const uint8_t *pat = (const uint8_t *)s->pattern;

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
    size_t gaps = 0;
    for (size_t i = 0; i < len; ) {
        uint32_t cp = 0;
        int n = u8_decode((const unsigned char *)pat + i, len - i, &cp);
        if (n <= 0) { i++; continue; }
        i += (size_t)n;
        if (n == 1) continue;                       // ASCII already folds
        // Only CASED characters count. A caseless one (CJK, punctuation, emoji)
        // is not a gap -- -i was never going to change it.
        size_t lo = 0, hi = SUB_FOLD_EXCLUDED;
        while (lo < hi) {
            size_t mid = lo + (hi - lo) / 2;
            if (sub_fold_excluded[mid] == cp) { gaps++; break; }
            if (sub_fold_excluded[mid] < cp) lo = mid + 1; else hi = mid;
        }
    }
    return gaps;
}

// CAPTURE GROUPS, as a bounded post-pass over ONE match span.
//
// The Glushkov field tracks a position SET with no submatch notion, and the
// compiler builds those positions in a single pass keeping no AST -- so group
// boundaries cannot be recovered from it at all. On its own that makes captures
// a second engine over the haystack, which is why they were deferred for so
// long.
//
// The occurrence field inverts it. The match SPAN is already isolated by the
// fast engine, so this only ever runs over those few bytes, only when a
// substitution actually asks for a backreference. It is a backtracking matcher
// -- normally the wrong choice for a scanner -- and that is acceptable precisely
// because it never sees a scan: worst-case backtracking over a span the fast
// path already bounded is a different risk from backtracking over a file.
//
// It accepts the same ERE subset the Glushkov face does. Anything it cannot
// parse fails closed (no captures), and the caller substitutes empty rather than
// guessing.

typedef struct cap_node cap_node;
struct cap_node {
    enum { CN_CHAR, CN_ANY, CN_CLASS, CN_CONCAT, CN_ALT, CN_REP, CN_GROUP } k;
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
    if (c == '.') { cp->p++; cap_node *n = cn_new(cp, CN_ANY); return n; }
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

static cap_node *cap_repeat(cap_parser *cp) {
    cap_node *a = cap_atom(cp);
    if (!cp->ok || !a) return a;
    for (;;) {
        char c = *cp->p;
        int lo, hi;
        if (c == '*') { lo = 0; hi = -1; cp->p++; }
        else if (c == '+') { lo = 1; hi = -1; cp->p++; }
        else if (c == '?') { lo = 0; hi = 1; cp->p++; }
        else if (c == '{') {
            const char *save = cp->p;
            cp->p++;
            int l = 0, h = -2, hasl = 0;
            while (*cp->p >= '0' && *cp->p <= '9') { l = l * 10 + (*cp->p - '0'); cp->p++; hasl = 1; }
            if (*cp->p == ',') {
                cp->p++; h = -1;
                if (*cp->p >= '0' && *cp->p <= '9') { h = 0; while (*cp->p >= '0' && *cp->p <= '9') { h = h * 10 + (*cp->p - '0'); cp->p++; } }
            } else h = l;
            if (!hasl || *cp->p != '}') { cp->p = save; break; }
            cp->p++; lo = l; hi = h;
        }
        else break;
        cap_node *r = cn_new(cp, CN_REP);
        if (!r) return NULL;
        r->a = a; r->lo = lo; r->hi = hi;
        a = r;
    }
    return a;
}

static cap_node *cap_concat(cap_parser *cp) {
    cap_node *head = NULL, *tail = NULL;
    while (cp->ok && *cp->p && *cp->p != '|' && *cp->p != ')') {
        cap_node *r = cap_repeat(cp);
        if (!cp->ok || !r) break;
        if (!head) { head = r; tail = r; continue; }
        cap_node *c = cn_new(cp, CN_CONCAT);
        if (!c) return NULL;
        c->a = head; c->b = r; head = c; tail = r;
    }
    (void)tail;
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

// Continuation-passing backtracker: match `n` at text[i..len), then `k`.
typedef struct { const char *t; size_t len; uint32_t *gs; uint32_t *ge; int icase; } cap_run;
typedef struct cap_cont cap_cont;
struct cap_cont { cap_node *n; cap_cont *next; };

static int cap_m(cap_run *r, cap_node *n, size_t i, cap_cont *k);

static int cap_k(cap_run *r, cap_cont *k, size_t i) {
    if (!k) return i == r->len;          // EXACT consumption: the span is known
    return cap_m(r, k->n, i, k->next);
}

static int cap_m(cap_run *r, cap_node *n, size_t i, cap_cont *k) {
    if (!n) return cap_k(r, k, i);
    switch (n->k) {
    case CN_CHAR: {
        if (i >= r->len) return 0;
        unsigned char a = (unsigned char)r->t[i], b = n->ch;
        if (r->icase) { a = fold(a, 1); b = fold(b, 1); }
        return a == b ? cap_k(r, k, i + 1) : 0;
    }
    case CN_ANY:
        return i < r->len ? cap_k(r, k, i + 1) : 0;
    case CN_CLASS: {
        if (i >= r->len) return 0;
        unsigned char c = (unsigned char)r->t[i];
        return (n->set[c >> 3] & (uint8_t)(1u << (c & 7))) ? cap_k(r, k, i + 1) : 0;
    }
    case CN_CONCAT: {
        cap_cont c = { n->b, k };
        return cap_m(r, n->a, i, &c);
    }
    case CN_ALT:
        return cap_m(r, n->a, i, k) || cap_m(r, n->b, i, k);
    case CN_GROUP: {
        // Record on the way in; a failed branch overwrites on the retry, and the
        // final accepted parse is the one whose writes survive.
        uint32_t save_s = r->gs[n->gidx], save_e = r->ge[n->gidx];
        r->gs[n->gidx] = (uint32_t)i;
        // The group's end is stamped by a marker continuation so it reflects
        // where the group ACTUALLY stopped, not where the parser guessed.
        cap_node marker;
        memset(&marker, 0, sizeof marker);
        marker.k = CN_REP; marker.lo = 0; marker.hi = 0; marker.gidx = n->gidx;
        cap_cont c = { &marker, k };
        if (cap_m(r, n->a, i, &c)) return 1;
        r->gs[n->gidx] = save_s; r->ge[n->gidx] = save_e;
        return 0;
    }
    case CN_REP: {
        if (n->hi == 0) {           // the group-end marker (lo 0, hi 0, gidx set)
            if (n->gidx) r->ge[n->gidx] = (uint32_t)i;
            return cap_k(r, k, i);
        }
        // GREEDY: try the longest first, which is POSIX's rule and the one the
        // fast engine's leftmost-longest span already committed to.
        int maxrep = n->hi < 0 ? (int)(r->len - i) + 1 : n->hi;
        for (int cnt = maxrep; cnt >= n->lo; --cnt) {
            // Build a chain of `cnt` copies ahead of k, then match it.
            int okrun = 1;
            size_t j = i;
            // Fast path: match cnt copies greedily left to right, then the tail.
            // A copy that itself backtracks is handled by recursion below.
            if (cnt == 0) { if (cap_k(r, k, j)) return 1; continue; }
            // Recursive form: one copy, then (cnt-1) more, then k.
            cap_node rest;
            memset(&rest, 0, sizeof rest);
            rest.k = CN_REP; rest.a = n->a; rest.lo = cnt - 1;
            rest.hi = cnt - 1 ? cnt - 1 : 0;
            if (cnt - 1 == 0) {
                cap_cont c = { NULL, k };
                if (cap_m(r, n->a, j, &c)) return 1;
            } else {
                cap_cont c = { &rest, k };
                if (cap_m(r, n->a, j, &c)) return 1;
            }
            (void)okrun;
        }
        return 0;
    }
    default: return 0;
    }
}

int sublimation_search_captures(const char *pat, const char *text, size_t n,
                                int icase, sublimation_match_span *groups,
                                size_t max_groups, size_t *ngroups) {
    if (ngroups) *ngroups = 0;
    if (!pat || !text || !groups || max_groups == 0) return 0;
    cap_parser cp = { pat, NULL, 0, 1, icase };
    cap_node *root = cap_alt(&cp);
    int ok = cp.ok && root && *cp.p == '\0' && cp.ngroups > 0;
    int rc = 0;
    if (ok) {
        int ng = cp.ngroups;
        uint32_t *gs = (uint32_t *)calloc((size_t)ng + 1, sizeof *gs);
        uint32_t *ge = (uint32_t *)calloc((size_t)ng + 1, sizeof *ge);
        if (gs && ge) {
            for (int g = 0; g <= ng; g++) { gs[g] = UINT32_MAX; ge[g] = UINT32_MAX; }
            cap_run r = { text, n, gs, ge, icase };
            if (cap_m(&r, root, 0, NULL)) {
                size_t out = 0;
                for (int g = 1; g <= ng && out < max_groups; g++, out++) {
                    int set = gs[g] != UINT32_MAX && ge[g] != UINT32_MAX;
                    groups[out].start = set ? gs[g] : 0;
                    groups[out].end   = set ? ge[g] : 0;
                    groups[out].pat   = set ? g : -1;   // -1: group did not participate
                }
                if (ngroups) *ngroups = out;
                rc = 1;
            }
        }
        free(gs); free(ge);
    }
    for (cap_node *q = cp.arena; q; ) { cap_node *nx = q->next; free(q); q = nx; }
    return rc;
}
