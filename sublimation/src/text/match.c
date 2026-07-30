// match.c -- tri-face text matcher (sublimation_search.h face of sublimation_text.h).
// Ported from the proven research prototype (sublimation/tests/search/search_research.c):
// the data-relative anchor scan (exact face), the Glushkov bit-parallel position-NFA
// with its reach-closure memo and literal prefilter (regex face) and the brute plus
// pigeonhole-prefiltered k-mismatch scans (fuzzy face). Byte-parity with the reference
// oracles is the gate: every count here is byte-identical to the un-prefiltered path.
#include "sublimation_text.h"
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
typedef struct { const char *p; gnfa_t *g; } gpar_t;

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
        gset_byte(S, b, icase); x->p++;
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
    gpar_t x = { buf, g };
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

long sublimation_search_next_any(const sublimation_search *set, int nset, int regex_face,
                                 const char *line, size_t n, size_t off,
                                 int wword, long *end_out) {
    long bs = -1, be = -1;
    for (int p = 0; p < nset; p++) {
        long e = -1;
        long st = search_next_match(&set[p], regex_face, line, n, off, wword, &e);
        if (st < 0) continue;
        if (bs < 0 || st < bs || (st == bs && e > be)) { bs = st; be = e; }
    }
    if (bs >= 0 && end_out) *end_out = be;
    return bs;
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
