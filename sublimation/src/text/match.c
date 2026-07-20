// match.c -- tri-face text matcher (sublimation_search.h face of sublimation_text.h).
// Ported from the proven research prototype (sublimation/tests/search/search_research.c):
// the data-relative anchor scan (exact face), the Glushkov bit-parallel position-NFA
// with its lazy-DFA reach cache and literal prefilter (regex face) and the brute plus
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

// Fixed English byte-frequency model, HIGHER = more common. Used only to choose
// WHICH byte to anchor on; the choice never affects correctness, only skip.
static uint32_t english_freq(uint8_t b) {
    static const uint8_t f[26] = {
        82, 15, 28, 43, 127, 22, 20, 61, 70, 2, 8, 40, 24,
        67, 75, 19, 1, 60, 63, 91, 28, 10, 24, 2, 20, 1 };
    uint8_t c = b | 0x20;
    if (c >= 'a' && c <= 'z') return f[c - 'a'] + 1u;
    if (b == ' ') return 200;
    return 1;
}

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

// Exact face: the classify dispatcher's winning path. Read the sampled histogram,
// name the regime, dispatch. No rare byte -> bmh; one rare byte -> data-relative
// anchor; two decorrelated rare bytes -> two-anchor. Every path yields the same
// overlapping count (the parity gate proves this); the choice is speed only.
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
    for (int pc = 0; pc < pieces; pc++) {
        size_t ps = (size_t)pc * m / (size_t)pieces;
        size_t pe = (size_t)(pc + 1) * m / (size_t)pieces;
        if (pe == ps) continue;
        size_t roff = ps; uint32_t bf = english_freq(pat[ps]);
        for (size_t i = ps + 1; i < pe; i++) {
            uint32_t f = english_freq(pat[i]);
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
        else if (c == '[') {
            i++; int neg = 0;
            if (i < len && p[i] == '^') { neg = 1; i++; }
            while (i < len && p[i] != ']') {
                unsigned char lo = (unsigned char)p[i];
                if (i + 2 < len && p[i+1] == '-' && p[i+2] != ']') {
                    unsigned char hi = (unsigned char)p[i+2];
                    for (unsigned x = lo; x <= hi; x++) S[x>>3] |= (uint8_t)(1u << (x&7));
                    i += 3;
                } else { S[lo>>3] |= (uint8_t)(1u << (lo&7)); i++; }
            }
            if (i >= len) return -1;
            i++;
            if (neg) for (int kk = 0; kk < 32; kk++) S[kk] = (uint8_t)~S[kk];
        }
        else {
            if (c == '\\' && i + 1 < len) { i++; c = p[i]; }
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
        x->p++; int neg = 0;
        if (*x->p == '^') { neg = 1; x->p++; }
        while (*x->p && *x->p != ']') {
            unsigned char lo = (unsigned char)*x->p;
            if (x->p[1] == '-' && x->p[2] && x->p[2] != ']') {
                unsigned char hi = (unsigned char)x->p[2];
                for (unsigned v = lo; v <= hi; v++) S[v>>3] |= (uint8_t)(1u<<(v&7));
                x->p += 3;
            } else { S[lo>>3] |= (uint8_t)(1u<<(lo&7)); x->p++; }
        }
        if (*x->p == ']') x->p++; else x->g->ok = 0;
        if (neg) for (int kk = 0; kk < 32; kk++) S[kk] = (uint8_t)~S[kk];
    } else {
        if (c == '\\' && x->p[1]) { x->p++; c = *x->p; }
        unsigned char b = (unsigned char)c;
        S[b>>3] |= (uint8_t)(1u<<(b&7)); x->p++;
    }
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

static int build_gnfa(const char *pat, gnfa_t *g) {
    memset(g, 0, sizeof(*g)); g->ok = 1;
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

// Build the per-byte position map. Under icase, a byte matches a position if the
// byte OR its ASCII case-swap is in that position's set.
static void build_imap(const gnfa_t *g, int icase, uint64_t I[256]) {
    for (int c = 0; c < 256; c++) {
        uint64_t m = 0;
        int sw = -1;
        if (icase) {
            if (c >= 'a' && c <= 'z') sw = c - 32;
            else if (c >= 'A' && c <= 'Z') sw = c + 32;
        }
        for (int i = 0; i < g->npos; i++) {
            int in = (g->setb[i][c>>3] >> (c&7)) & 1;
            if (!in && sw >= 0) in = (g->setb[i][sw>>3] >> (sw&7)) & 1;
            if (in) m |= (1ull << i);
        }
        I[c] = m;
    }
}

// Lazy-DFA reach cache. reach(D) = first | union(follow[i], i in D), memoized.
typedef struct { uint64_t key, reach; } reach_ent;
#define REACH_BITS 13
#define REACH_CAP  (1u << REACH_BITS)

static inline uint64_t reach_of(uint64_t D, const gnfa_t *g, reach_ent *cache) {
    if (D == 0) return g->first;
    size_t h = (size_t)((D * 0x9E3779B97F4A7C15ull) >> (64 - REACH_BITS));
    while (cache[h].key && cache[h].key != D) h = (h + 1) & (REACH_CAP - 1);
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
        else if (c == '[') { atom_end = i + 1; while (atom_end < plen && p[atom_end] != ']') { if (p[atom_end] == '\\') atom_end++; atom_end++; } if (atom_end < plen) atom_end++; }
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
            i++; while (i < plen && p[i] != ']') { if (p[i] == '\\') i++; i++; }
            if (i < plen) i++;
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
    int probe_off = 0; uint32_t bestf = english_freq(lit[0]);
    for (int i = 1; i < litlen; i++) {
        uint32_t f = english_freq(lit[i]);
        if (f < bestf) { bestf = f; probe_off = i; }
    }
    if (probe_off != 0 && bestf * 2 >= english_freq(lit[0])) probe_off = 0;
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
        out->valid = build_gnfa(out->pattern, &out->g);
        // The per-byte position map depends only on (pattern, icase): build it
        // once here so match/count calls never rebuild it.
        if (out->valid) build_imap(&out->g, out->icase, out->imap);
    }
}

int sublimation_search_valid(const sublimation_search *s) { return s->valid; }

// The opaque-buffer contract with foreign callers (montauk-mcp mirrors this
// struct as a byte buffer in Rust). The static assert pins the size the
// mirror was written against; growth breaks THIS build, never a caller's
// stack. The sizeof export lets a binding assert the contract at runtime.
static_assert(sizeof(sublimation_search) == 5696,
              "sublimation_search grew: update every foreign mirror "
              "(components/mcp/src/ffi.rs) and this assert together");

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
        int start_limit = s->g.anchored_start ? 1 : (int)n + 1;
        for (int start = (int)from; start < start_limit; ++start) {
            long e = gnfa_start_longest(&s->g, s->imap, hay, n, (size_t)start);
            if (e >= 0) { if (end_out) *end_out = e; return start; }
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

    // Exact: leftmost occurrence at or after `from`.
    if (!s->icase) {
        const uint8_t *base = hay + from, *end = hay + n;
        while (base + m <= end) {
            const uint8_t *hit = memchr(base, pat[0], (size_t)(end - base) - m + 1);
            if (!hit) break;
            if (memcmp(hit, pat, m) == 0) {
                if (end_out) *end_out = (long)((hit - hay) + m);
                return (long)(hit - hay);
            }
            base = hit + 1;
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
