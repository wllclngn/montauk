// search_research.c -- prototyping ground for sublimation search's native
// matchers. This is a research scaffold, not the shipped engine: one shared
// scan-and-verify loop with a PLUGGABLE ANCHOR SELECTOR, so every strategy is
// measured on equal footing and only the choice of WHERE to probe differs.
//
// The thesis under test (2026-07-15): measuring the data's own structure to
// choose the anchor beats assuming a frozen English model. See
// silica/tests/research/SUBLIMATION_SEARCH.md.
//
// Modes:
//   search_research count <strategy> <pattern>   read stdin, print match count
//   search_research bench <strategy> <pattern>   read stdin, print MB/s
// Strategies: bmh frozen data_relative qgram leverage
//
// Build: clang -O2 -march=native -std=c23 search_research.c -o search_research
#define _POSIX_C_SOURCE 200809L   // clock_gettime under strict -std=c23
#include <ctype.h>
#include <math.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Position-checksum accumulator: when g_pmode is set, each match folds its START
// position into g_pchk, so parity can verify WHERE matches land, not just how
// many (an off-by-one anchor could pass a count check but not this).
static uint64_t g_pchk = 0;
static int g_pmode = 0;
static inline void pmark(size_t pos) { if (g_pmode) g_pchk = g_pchk * 1000003ull + (uint64_t)pos; }

// Whole-of-stdin slurp. The haystack is one contiguous buffer; matching is
// byte-exact and newline-agnostic (a match may span lines -- parity is against
// a substring count, not a line count).
static uint8_t *slurp_stdin(size_t *out_len) {
    size_t cap = 1u << 20, len = 0;
    uint8_t *buf = malloc(cap);
    if (!buf) { perror("malloc"); exit(2); }
    for (;;) {
        if (len == cap) { cap *= 2; buf = realloc(buf, cap); if (!buf) { perror("realloc"); exit(2); } }
        size_t got = fread(buf + len, 1, cap - len, stdin);
        len += got;
        if (got == 0) break;
    }
    *out_len = len;
    return buf;
}

// Sample the first sample_len bytes into a 256-bin byte histogram. Sublinear:
// a bounded prefix, not the whole corpus (the LODESTONE online-sample idea).
static void byte_hist(const uint8_t *hay, size_t n, uint32_t hist[256]) {
    memset(hist, 0, 256 * sizeof(uint32_t));
    size_t s = n < (1u << 18) ? n : (1u << 18);   // 256 KiB sample
    for (size_t i = 0; i < s; i++) hist[hay[i]]++;
}

// Fixed English byte-frequency model: HIGHER = more common in English prose,
// so the frozen strategy anchors on the byte of MINIMUM frequency (rarest, best
// skip). This is the frozen model the data-relative strategies beat when the
// data is not English -- it anchors on whatever English thinks is rare (z, q,
// j, x, punctuation) regardless of what is actually rare in THIS corpus.
static uint32_t english_freq(uint8_t b) {
    static const uint8_t f[26] = {  // a..z, relative frequency x10
        82, 15, 28, 43, 127, 22, 20, 61, 70, 2, 8, 40, 24,
        67, 75, 19, 1, 60, 63, 91, 28, 10, 24, 2, 20, 1 };
    uint8_t c = b | 0x20;
    if (c >= 'a' && c <= 'z') return f[c - 'a'] + 1u;  // 2..128
    if (b == ' ') return 200;                          // space: very common
    return 1;                                          // non-letters: rare in prose
}

// Anchor: a byte value to scan for, and its offset within the pattern.
typedef struct { uint8_t byte; size_t off; } anchor_t;

// The shared scan: memchr to each occurrence of anchor.byte, derive the
// candidate start (j - off), full-verify. memchr is everyone's SIMD floor, so
// strategies differ only by WHICH byte/offset they anchor on, never by the
// scan primitive. Returns match count.
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
            { count++; pmark(j - a.off); }
        p = hit + 1;
    }
    return count;
}

// Two-anchor scan (the leverage strategy): scan on the rarer anchor, and reject
// with the second, decorrelated anchor before the full verify -- a
// negative-dependence AND filter that cuts candidate density multiplicatively.
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
                { count++; pmark(start); }
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
        if (memcmp(hay + i, pat, m) == 0) { count++; pmark(i); }
        i += skip[hay[i + m - 1]];
    }
    return count;
}

// Shift-And exact bit-parallel FIELD (Phase 1): the field primitive at its
// simplest. Pattern (m <= 64) becomes per-byte masks B[c] (bit i set if
// pat[i]==c). State D is a bit-vector: bit i set means pat[0..i] matches ending
// here. Every input byte advances the WHOLE field at once, D = ((D<<1)|1) & B[c];
// accept when the top bit sets. Field not automaton: one vector, advanced in
// parallel, no walking. Exact, regex and fuzzy are widenings of exactly this.
static size_t scan_shiftand(const uint8_t *hay, size_t n, const uint8_t *pat, size_t m) {
    if (m == 0 || m > 64) return (size_t)-1;      // sentinel: caller falls back
    uint64_t B[256] = {0};
    for (size_t i = 0; i < m; i++) B[pat[i]] |= (1ull << i);
    uint64_t D = 0, top = 1ull << (m - 1);
    size_t count = 0;
    for (size_t j = 0; j < n; j++) {
        D = ((D << 1) | 1ull) & B[hay[j]];
        if (D & top) { count++; pmark(j - m + 1); }
    }
    return count;
}

// FUZZY k-mismatch (Phase 3), correctness baseline: count windows differing from
// the pattern in at most k positions (Hamming <= k), early-exit past k. The
// bit-parallel survivor field and the pigeonhole prefilter (split into k+1 exact
// pieces, at least one must match, anchor on them) are the next gated optimization.
static size_t scan_kmismatch(const uint8_t *hay, size_t n, const uint8_t *pat,
                             size_t m, int k) {
    if (m == 0 || m > n) return 0;
    size_t count = 0;
    for (size_t i = 0; i + m <= n; i++) {
        int mism = 0;
        for (size_t j = 0; j < m; j++)
            if (hay[i + j] != pat[j]) { if (++mism > k) break; }
        if (mism <= k) count++;
    }
    return count;
}

// E3: pigeonhole prefilter for k-mismatch. Split the pattern into k+1 contiguous
// pieces; any k-mismatch occurrence leaves at least one piece with zero mismatches
// (k errors cannot touch all k+1 pieces), so anchoring on each piece's rarest byte
// (E1's selector) and verifying only at candidates finds every match. A dedup
// array counts each matching position once, so the result is byte-identical to the
// brute scan. Turns O(n*m)-everywhere into skip-to-candidates.
static size_t scan_kmismatch_pre(const uint8_t *hay, size_t n, const uint8_t *pat,
                                 size_t m, int k) {
    if (m == 0 || m > n) return 0;
    if ((size_t)k >= m) return n - m + 1;   // every window is within k mismatches
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

// REGEX, first widening (Phase 2): a FIXED-LENGTH class field. Each pattern atom
// is a per-position BYTE-SET, not a single byte. A literal is a singleton set, a
// class [abc]/[a-z]/[^..] its set, '.' the full set. The same Shift-And field then
// matches classes and wildcards, because the field never cared that a position
// accepted only one byte. Quantifiers and alternation are later gated sub-steps.
// Returns L (number of atoms) or -1 on an unsupported construct.
static int parse_classes(const char *p, uint8_t sets[][32], int maxL) {
    int L = 0; size_t i = 0, len = strlen(p);
    if (len > 0 && (p[0] == '^' || p[len - 1] == '$')) return -1;  // anchors -> NFA path
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
            if (i >= len) return -1;    // unterminated class
            i++;
            if (neg) for (int k = 0; k < 32; k++) S[k] = (uint8_t)~S[k];
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

// REGEX, full field (Phase 2): a Glushkov position-NFA simulated as a bit-vector
// field. Positions (character atoms, <= 64) are bits; follow[i] is the set that
// can follow position i, first/last the start/accept sets. Per input byte the
// WHOLE field advances: reach = first | union(follow[i] for i active), then
// D = reach & (positions matching this byte). A match ends wherever D meets last.
// Field not automaton, widened from Shift-And to handle * + ? | and grouping.
// Non-nullable patterns only (empty-match semantics deliberately out of scope).
typedef struct {
    uint8_t setb[64][32];   // byte-set per position
    uint64_t follow[64];    // positions that may follow position i
    uint64_t first, last;   // start / accept position sets
    int npos, nullable_all, ok;
    int anchored_start, anchored_end;   // leading ^ / trailing $ (text boundaries)
} gnfa_t;

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
        if (neg) for (int k = 0; k < 32; k++) S[k] = (uint8_t)~S[k];
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
        // A3: bounded repeat on a SINGLE-position atom, expanded to lo required
        // plus (hi-lo) optional copies. {m,} unbounded is not supported here.
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
    while (*x->p && *x->p != '|' && *x->p != ')') {
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
    while (*x->p == '|') {
        x->p++; gattr_t b = g_concat(x);
        a.first |= b.first; a.last |= b.last; a.nullable = a.nullable || b.nullable;
    }
    return a;
}

static int build_gnfa(const char *pat, gnfa_t *g) {
    memset(g, 0, sizeof(*g)); g->ok = 1;
    char buf[1024];
    size_t len = strlen(pat), s = 0, e = len;
    if (e > 0 && pat[0] == '^') { g->anchored_start = 1; s = 1; }   // A1: anchors
    if (e > s && pat[e - 1] == '$') { g->anchored_end = 1; e--; }
    if (e - s >= sizeof(buf)) return 0;
    memcpy(buf, pat + s, e - s); buf[e - s] = '\0';
    gpar_t x = { buf, g };
    gattr_t a = g_alt(&x);
    if (!g->ok || *x.p != '\0' || g->npos == 0) return 0;
    g->first = a.first; g->last = a.last; g->nullable_all = a.nullable;
    return 1;
}

// E2: lazy-DFA transition cache. reach(D) = first | union(follow[i], i in D) is a
// pure function of the active-position set D, so memoize it: each distinct state's
// follow-union is computed once, not every byte. Exact (no approximation), so
// byte-parity is preserved by construction. D==0 is special-cased (reach = first)
// and never stored, so key==0 is a safe empty sentinel.
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

static size_t scan_gnfa(const uint8_t *hay, size_t n, gnfa_t *g) {
    uint64_t I[256];
    for (int c = 0; c < 256; c++) {
        uint64_t m = 0;
        for (int i = 0; i < g->npos; i++) if (g->setb[i][c>>3] & (1u<<(c&7))) m |= (1ull<<i);
        I[c] = m;
    }
    // A2: an unanchored nullable regex matches the empty string at every one of
    // the n+1 positions, so every position is a match-end.
    if (g->nullable_all && !g->anchored_start && !g->anchored_end) return n + 1;
    uint64_t D = 0; size_t count = 0;
    if (g->anchored_start || g->anchored_end) {
        // Anchored: the seed varies by position, so reach is not a pure function
        // of D alone. Keep the direct loop (anchored patterns are rare).
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
    if (!cache) return (size_t)-1;
    for (size_t j = 0; j < n; j++) {
        D = reach_of(D, g, cache) & I[(unsigned char)hay[j]];
        if (D & g->last) count++;
    }
    free(cache);
    return count;
}

// PHASE B prefilter wiring. Three helpers plus the prefiltered scan.

// Max match length of a top-level bounded pattern; -1 if unbounded (`*`, `+`,
// `{m,}`) or if it uses a group / alternation (conservatively given up on).
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

// Longest run of consecutive plain literal bytes (alnum or space), none of them
// quantified. Conservative but sound: any run it returns is verbatim in every
// match. Returns the run length (0 if none of length >= 2).
static int extract_literal(const char *p, uint8_t *out, int maxout) {
    size_t plen = strlen(p);
    int bl = 0, bs = -1, cl = 0, cs = -1;
    for (size_t i = 0; i < plen; ) {
        char c = p[i];
        if (c == '[') {                          // class: contents are NOT literal
            i++; while (i < plen && p[i] != ']') { if (p[i] == '\\') i++; i++; }
            if (i < plen) i++;
            cs = -1; cl = 0; continue;
        }
        if (c == '\\') { i += 2; cs = -1; cl = 0; continue; }   // escape: break run
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
    for (int k = 0; k < bl; k++) out[k] = (unsigned char)p[bs + k];
    return bl;
}

// Count match-ends of the field over hay[a..b) with fresh state. The caller
// guarantees a full max-length of runway before any countable match-end.
static size_t gnfa_range(const uint8_t *hay, size_t a, size_t b, const uint64_t I[256],
                         const gnfa_t *g, reach_ent *cache) {
    uint64_t D = 0; size_t count = 0;
    for (size_t j = a; j < b; j++) {
        D = reach_of(D, g, cache) & I[hay[j]];
        if (D & g->last) count++;
    }
    return count;
}

// Prefiltered regex scan: anchor on a required literal, run the field only over
// coalesced non-overlapping regions around its occurrences. *used stays 0 (and
// the result is meaningless) when the pattern is outside the sound subset, so the
// caller must fall back to the full field. Provably byte-identical to the full
// field on the subset: unanchored, non-nullable, bounded, group-free, with a
// literal factor of length >= 2.
static size_t regex_prefiltered(const uint8_t *hay, size_t n, const char *pat, const gnfa_t *g, int *used) {
    *used = 0;
    if (g->anchored_start || g->anchored_end || g->nullable_all) return 0;
    int ml = regex_maxlen(pat);
    if (ml < 1 || ml > 60) return 0;
    uint8_t lit[64];
    int litlen = extract_literal(pat, lit, 64);
    if (litlen < 2) return 0;
    uint64_t I[256];
    for (int c = 0; c < 256; c++) {
        uint64_t m = 0;
        for (int i = 0; i < g->npos; i++) if (g->setb[i][c>>3] & (1u<<(c&7))) m |= (1ull<<i);
        I[c] = m;
    }
    // E1: probe on the byte of the literal that is rarest in typical data, chosen
    // from a static frequency rank at ZERO runtime cost. Sampling the haystack to
    // pick this byte does not amortize: for a rare literal the whole scan is
    // shorter than the sample would be, so we assume here, exactly as fast
    // substring engines do. The probe choice never affects correctness, only skip.
    int probe_off = 0; uint32_t bestf = english_freq(lit[0]);
    for (int i = 1; i < litlen; i++) {
        uint32_t f = english_freq(lit[i]);
        if (f < bestf) { bestf = f; probe_off = i; }
    }
    // Only switch away from the first byte when the win is CLEAR (candidate at
    // most half as common). A static table that mispredicts this data (r vs s in
    // C, or z/q common in an adversarial corpus) then cannot regress below the
    // naive first-byte probe; a genuinely rare byte (X vs E) still wins.
    if (probe_off != 0 && bestf * 2 >= english_freq(lit[0])) probe_off = 0;
    unsigned char probe = lit[probe_off];
    reach_ent *cache = calloc(REACH_CAP, sizeof(reach_ent));   // E2: shared across regions
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

// Anchor selectors: choose the pattern offset to probe on.
static size_t off_min_by_english(const uint8_t *pat, size_t m) {
    size_t best = 0; uint32_t bf = english_freq(pat[0]);
    for (size_t i = 1; i < m; i++) { uint32_t f = english_freq(pat[i]); if (f < bf) { bf = f; best = i; } }
    return best;
}
static size_t off_min_by_data(const uint8_t *pat, size_t m, const uint32_t hist[256]) {
    size_t best = 0; uint32_t bc = hist[pat[0]];
    for (size_t i = 1; i < m; i++) if (hist[pat[i]] < bc) { bc = hist[pat[i]]; best = i; }
    return best;
}
// q-gram rarity approximated by the product of its bytes' data frequencies
// (log-sum to avoid overflow): the rarest length-q window in the pattern.
static size_t off_min_qgram_by_data(const uint8_t *pat, size_t m, size_t q,
                                    const uint32_t hist[256]) {
    if (m < q) return off_min_by_data(pat, m, hist);
    size_t best = 0; double bs = 1e300;
    for (size_t i = 0; i + q <= m; i++) {
        double s = 0;
        for (size_t k = 0; k < q; k++) s += (double)(hist[pat[i + k]] + 1);
        if (s < bs) { bs = s; best = i; }
    }
    return best;
}
// Second decorrelated anchor: the next-rarest byte at least `sep` away from a.
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

// EFFECTIVE RESISTANCE (the flow-dual leverage primitive, real form).
// R_eff(i,j) on a connected weighted graph with Laplacian L = D - W is a true
// metric: how far apart two nodes are once every parallel path is accounted for.
// leverage(i,j) = w(i,j) * R_eff(i,j) in [0,1] is the probability the edge lies
// in a weight-proportional random spanning tree -- the principled quantity the
// frequency proxy only approximates. Computed at small n off the hot path,
// exactly as silica computes it over CPU topology. min-cut shares this Laplacian.

// Dense n x n inverse, Gauss-Jordan with partial pivoting (n small). A is
// row-major, overwritten with its inverse. Returns -1 if singular.
static int mat_inverse(double *A, int n) {
    double *inv = calloc((size_t)n * n, sizeof(double));
    if (!inv) return -1;
    for (int i = 0; i < n; i++) inv[i * n + i] = 1.0;
    for (int c = 0; c < n; c++) {
        int piv = c; double best = fabs(A[c * n + c]);
        for (int r = c + 1; r < n; r++) { double v = fabs(A[r * n + c]); if (v > best) { best = v; piv = r; } }
        if (best < 1e-12) { free(inv); return -1; }
        if (piv != c)
            for (int k = 0; k < n; k++) {
                double t = A[c * n + k]; A[c * n + k] = A[piv * n + k]; A[piv * n + k] = t;
                t = inv[c * n + k]; inv[c * n + k] = inv[piv * n + k]; inv[piv * n + k] = t;
            }
        double d = A[c * n + c];
        for (int k = 0; k < n; k++) { A[c * n + k] /= d; inv[c * n + k] /= d; }
        for (int r = 0; r < n; r++) {
            if (r == c) continue;
            double f = A[r * n + c];
            for (int k = 0; k < n; k++) { A[r * n + k] -= f * A[c * n + k]; inv[r * n + k] -= f * inv[c * n + k]; }
        }
    }
    memcpy(A, inv, (size_t)n * n * sizeof(double));
    free(inv);
    return 0;
}

// Fill Reff (n x n) for a connected symmetric weight matrix W (zero diagonal),
// via the closed form for the Laplacian pseudoinverse of a connected graph:
// L+ = inv(L + J/n) - J/n, with L = D - W and J all-ones. Then
// R_eff(i,j) = L+[i,i] + L+[j,j] - 2 L+[i,j].
static int effective_resistance(const double *W, int n, double *Reff) {
    double *M = malloc((size_t)n * n * sizeof(double));
    if (!M) return -1;
    double jn = 1.0 / (double)n;
    for (int i = 0; i < n; i++) {
        double deg = 0; for (int j = 0; j < n; j++) deg += W[i * n + j];
        for (int j = 0; j < n; j++) {
            double L = (i == j) ? deg : -W[i * n + j];
            M[i * n + j] = L + jn;
        }
    }
    if (mat_inverse(M, n) != 0) { free(M); return -1; }
    for (int i = 0; i < n; i++)
        for (int j = 0; j < n; j++) {
            double pii = M[i * n + i] - jn, pjj = M[j * n + j] - jn, pij = M[i * n + j] - jn;
            Reff[i * n + j] = pii + pjj - 2.0 * pij;
        }
    free(M);
    return 0;
}

static void reff_case(const char *name, const double *W, int n, int i, int j, double want) {
    double *R = malloc((size_t)n * n * sizeof(double));
    if (!R) { printf("%s got=OOM want=%.6f\n", name, want); return; }
    if (effective_resistance(W, n, R) != 0) printf("%s got=SINGULAR want=%.6f\n", name, want);
    else printf("%s got=%.6f want=%.6f\n", name, R[i * n + j], want);
    free(R);
}

// Local (banded) pattern-position graph. Nodes are positions; an edge (i,j) with
// |i-j| <= band is weighted by how often pat[i] and pat[j] co-match at their
// relative offset across a data sample -- their REDUNDANCY (high weight = they
// predict each other = low R_eff). A tiny chain backbone keeps it connected so
// the pseudoinverse closed form holds. Cheap: one bounded-sample pass, off the
// hot path, exactly the "measure this corpus" discipline the anchors already use.
static void build_pattern_graph(const uint8_t *hay, size_t n, const uint8_t *pat,
                                size_t m, size_t band, double *W) {
    for (size_t k = 0; k < m * m; k++) W[k] = 0.0;
    size_t S = n < (1u << 17) ? n : (1u << 17);      // 128 KiB of alignments
    if (S >= m)
        for (size_t p = 0; p + m <= S; p++)
            for (size_t i = 0; i < m; i++) {
                if (hay[p + i] != pat[i]) continue;
                for (size_t j = i + 1; j <= i + band && j < m; j++)
                    if (hay[p + j] == pat[j]) { W[i * m + j] += 1.0; W[j * m + i] += 1.0; }
            }
    for (size_t i = 0; i + 1 < m; i++) { W[i * m + (i + 1)] += 1e-3; W[(i + 1) * m + i] += 1e-3; }
}

// Smallest period P in [1, cap] such that a W-byte window recurs at offset P
// (hay[0..W] == hay[P..P+W]). 0 if none. The seam a single-scale recurrence
// matcher would exploit.
static size_t detect_period(const uint8_t *hay, size_t n, size_t cap, size_t W) {
    if (n < W + 1) return 0;
    size_t maxP = cap < n - W ? cap : n - W;
    for (size_t P = 1; P <= maxP; P++)
        if (memcmp(hay, hay + P, W) == 0) return P;
    return 0;
}

// REPETITION DETECTOR (Phase 1): fraction of DISTINCT 16-grams in a sample.
// ~1.0 = every window unique (diverse/random), low = windows recur (repetitive).
// q=16 keeps random small-alphabet data near 1.0 (4^16 possible windows swamp the
// sample), so it reads REPETITION, not merely a small alphabet. Cheap: one
// bounded sample pass, FNV-1a hash into an open-addressing table. The signal the
// classifier dispatches the recurrence matcher on, the fractal edge read.
static double repetition_score(const uint8_t *hay, size_t n) {
    const size_t q = 16;
    if (n < q + 1) return 1.0;
    size_t S = n < (1u << 16) ? n : (1u << 16);      // 64 KiB sample (cheap enough
                                                     // to run inside classify)
    size_t slots = 1u << 18;                          // 256K slots (load <= 0.25)
    uint64_t *tab = calloc(slots, sizeof(uint64_t));
    if (!tab) return 1.0;
    size_t total = 0, distinct = 0;
    for (size_t p = 0; p + q <= S; p++) {
        uint64_t h = 1469598103934665603ULL;
        for (size_t k = 0; k < q; k++) { h ^= hay[p + k]; h *= 1099511628211ULL; }
        uint64_t key = h ? h : 1;
        size_t idx = (size_t)(h & (slots - 1));
        int found = 0;
        for (size_t probe = 0; probe < slots; probe++) {
            size_t s = (idx + probe) & (slots - 1);
            if (tab[s] == 0) { tab[s] = key; break; }
            if (tab[s] == key) { found = 1; break; }
        }
        total++;
        if (!found) distinct++;
    }
    free(tab);
    return total ? (double)distinct / (double)total : 1.0;
}

static size_t run(const char *strat, const uint8_t *hay, size_t n,
                  const uint8_t *pat, size_t m) {
    if (strcmp(strat, "bmh") == 0) return scan_bmh(hay, n, pat, m);
    if (strcmp(strat, "shiftand") == 0) {
        size_t r = scan_shiftand(hay, n, pat, m);
        if (r != (size_t)-1) return r;
        uint32_t h2[256]; byte_hist(hay, n, h2);        // m > 64: fall back
        size_t o = off_min_by_data(pat, m, h2);
        return scan_anchor(hay, n, pat, m, (anchor_t){pat[o], o});
    }
    uint32_t hist[256]; byte_hist(hay, n, hist);
    if (strcmp(strat, "frozen") == 0) {
        size_t o = off_min_by_english(pat, m);
        return scan_anchor(hay, n, pat, m, (anchor_t){pat[o], o});
    }
    if (strcmp(strat, "data_relative") == 0) {
        size_t o = off_min_by_data(pat, m, hist);
        return scan_anchor(hay, n, pat, m, (anchor_t){pat[o], o});
    }
    if (strcmp(strat, "qgram") == 0) {
        // Rarest length-4 window, then anchor on the rarest BYTE within it (not
        // the window's first byte, which need not be rare -- the earlier bug).
        size_t w = off_min_qgram_by_data(pat, m, 4, hist);
        size_t q = (m - w < 4) ? m - w : 4;
        size_t o = w; uint32_t bc = hist[pat[w]];
        for (size_t k = 1; k < q; k++) if (hist[pat[w + k]] < bc) { bc = hist[pat[w + k]]; o = w + k; }
        return scan_anchor(hay, n, pat, m, (anchor_t){pat[o], o});
    }
    if (strcmp(strat, "leverage") == 0) {
        size_t o1 = off_min_by_data(pat, m, hist);
        size_t o2 = off_second_by_data(pat, m, o1, hist);
        if (o2 == o1) { return scan_anchor(hay, n, pat, m, (anchor_t){pat[o1], o1}); }
        return scan_anchor2(hay, n, pat, m, (anchor_t){pat[o1], o1}, (anchor_t){pat[o2], o2});
    }
    if (strcmp(strat, "leverage_g") == 0) {
        // Real graph leverage: rarest anchor o1, then the position maximally
        // R_eff-INDEPENDENT of o1 (and rare) as the second, decorrelated anchor.
        // Where the proxy spaces by 2, this decorrelates by measured structure.
        if (m < 3) { size_t o = off_min_by_data(pat, m, hist);
                     return scan_anchor(hay, n, pat, m, (anchor_t){pat[o], o}); }
        double *W = malloc(m * m * sizeof(double));
        double *R = malloc(m * m * sizeof(double));
        size_t o1 = off_min_by_data(pat, m, hist), o2 = o1;
        if (W && R) {
            build_pattern_graph(hay, n, pat, m, 3, W);
            if (effective_resistance(W, (int)m, R) == 0) {
                double best = -1.0;
                for (size_t i = 0; i < m; i++) {
                    if (i == o1) continue;
                    double s = R[o1 * m + i] / (double)(hist[pat[i]] + 1);
                    if (s > best) { best = s; o2 = i; }
                }
            } else {
                o2 = off_second_by_data(pat, m, o1, hist);
            }
        }
        free(W); free(R);
        if (o2 == o1) return scan_anchor(hay, n, pat, m, (anchor_t){pat[o1], o1});
        return scan_anchor2(hay, n, pat, m, (anchor_t){pat[o1], o1}, (anchor_t){pat[o2], o2});
    }
    if (strcmp(strat, "recur") == 0) {
        // Single-scale recurrence exploit: detect a period P, count occurrences
        // in one period, extrapolate over n/P periods, then scan only the tail.
        // Work is O(P + tail), not O(n) -- the delta-proportional win.
        // UNSOUND, and NOT in the parity gate: extrapolation is correct only when
        // the MATCHES are periodic, which needs the data exactly periodic AND the
        // pattern part of the period. Planted patterns or any edit break it (it
        // returns the wrong count because it never reads most of the data). The
        // Phase 2 finding: no SOUND single-query recurrence win exists, the prize
        // is a repeated-query index. See PHASE_PLAN.md.
        size_t P = detect_period(hay, n, 1u << 16, 256);
        if (P == 0 || P < m) {
            size_t o = off_min_by_data(pat, m, hist);
            return scan_anchor(hay, n, pat, m, (anchor_t){pat[o], o});
        }
        size_t per = 0;
        for (size_t i = 0; i < P && i + m <= n; i++)
            if (memcmp(hay + i, pat, m) == 0) per++;
        size_t periods = n / P;
        size_t total = per * periods;
        for (size_t i = periods * P; i + m <= n; i++)
            if (memcmp(hay + i, pat, m) == 0) total++;
        return total;
    }
    if (strcmp(strat, "classify") == 0) {
        // NOTE: recurrence dispatch was tried here and REVERTED. recur is unsound
        // (it extrapolates the match count from one period, wrong whenever the
        // MATCHES are not periodic -- planted patterns, edits, real data), so it
        // cannot join a byte-exact dispatcher. The repetition prize is a
        // repeated-query capability, not a single-query one. See PHASE_PLAN.md.
        // The entropy-regime primitive: read the sampled histogram, name the
        // regime, dispatch. No rare byte -> uniform regime -> bmh skip (no anchor
        // to exploit). One rare byte -> data_relative. Two decorrelated rare
        // bytes -> leverage. The dispatcher, not any one matcher.
        size_t ssz = n < (1u << 18) ? n : (1u << 18);
        uint32_t rare = (uint32_t)(ssz / 32);   // rare enough = under ~3% of sample
        size_t o1 = off_min_by_data(pat, m, hist);
        if (hist[pat[o1]] > rare)
            return scan_bmh(hay, n, pat, m);
        size_t o2 = off_second_by_data(pat, m, o1, hist);
        if (o2 != o1 && hist[pat[o2]] <= rare)
            return scan_anchor2(hay, n, pat, m, (anchor_t){pat[o1], o1}, (anchor_t){pat[o2], o2});
        return scan_anchor(hay, n, pat, m, (anchor_t){pat[o1], o1});
    }
    fprintf(stderr, "unknown strategy: %s\n", strat);
    exit(2);
}

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "reff_selftest") == 0) {
        // Closed-form effective resistances a resistor network gives by hand.
        double e2[4] = {0, 2, 2, 0};                       // one edge, weight 2
        reff_case("single_edge_w2", e2, 2, 0, 1, 0.5);     // 1/w
        double p4[16] = {0};                               // path 0-1-2-3, unit
        p4[0*4+1]=p4[1*4+0]=1; p4[1*4+2]=p4[2*4+1]=1; p4[2*4+3]=p4[3*4+2]=1;
        reff_case("path4_endpoints", p4, 4, 0, 3, 3.0);    // three in series
        reff_case("path4_adjacent", p4, 4, 0, 1, 1.0);     // one unit resistor
        double t3[9] = {0,1,1, 1,0,1, 1,1,0};              // triangle, unit
        reff_case("triangle_unit", t3, 3, 0, 1, 2.0/3.0);  // 1 parallel with 2
        double k4[16]; for (int a=0;a<4;a++) for (int b=0;b<4;b++) k4[a*4+b]=(a==b)?0:1;
        reff_case("k4_unit", k4, 4, 0, 1, 0.5);            // 2/n for K_n
        return 0;
    }
    if (argc >= 3 && strcmp(argv[1], "search") == 0) {
        // PHASE 4 dispatch: one entry, route by pattern class. A plain literal
        // goes to classify (the adaptive anchor face); anything with regex
        // metacharacters goes to the field (class fast path, else the NFA).
        const char *pat = argv[2];
        int is_regex = 0;
        for (const char *q = pat; *q; q++)
            if (strchr(".[]*+?|(){}^$\\", *q)) { is_regex = 1; break; }
        size_t nn; uint8_t *hay = slurp_stdin(&nn);
        ptrdiff_t r;
        if (is_regex) {
            uint8_t sets[64][32];
            int L = parse_classes(pat, sets, 64);
            if (L > 0) r = (ptrdiff_t)scan_classfield(hay, nn, sets, L);
            else { gnfa_t g; r = build_gnfa(pat, &g) ? (ptrdiff_t)scan_gnfa(hay, nn, &g) : -1; }
        } else {
            r = (ptrdiff_t)run("classify", hay, nn, (const uint8_t *)pat, strlen(pat));
        }
        printf("%td\n", r);
        free(hay);
        return 0;
    }
    if (argc >= 4 && (strcmp(argv[1], "fuzzycount") == 0 || strcmp(argv[1], "fuzzypre") == 0)) {
        int k = atoi(argv[2]);
        int pre = strcmp(argv[1], "fuzzypre") == 0;
        size_t nn; uint8_t *hay = slurp_stdin(&nn);
        const uint8_t *p = (const uint8_t *)argv[3]; size_t m = strlen(argv[3]);
        printf("%zu\n", pre ? scan_kmismatch_pre(hay, nn, p, m, k)
                            : scan_kmismatch(hay, nn, p, m, k));
        free(hay);
        return 0;
    }
    if (argc >= 3 && strcmp(argv[1], "regexpre") == 0) {
        size_t nn; uint8_t *hay = slurp_stdin(&nn);
        gnfa_t g;
        if (!build_gnfa(argv[2], &g)) { printf("-1\n"); free(hay); return 0; }
        int used = 0;
        size_t r = regex_prefiltered(hay, nn, argv[2], &g, &used);
        if (!used) r = scan_gnfa(hay, nn, &g);
        printf("%td\n", (ptrdiff_t)r);
        free(hay);
        return 0;
    }
    if (argc >= 4 && (strcmp(argv[1], "benchfz") == 0 || strcmp(argv[1], "benchfzpre") == 0)) {
        // Median-of-9 MB/s for fuzzy k-mismatch: brute vs pigeonhole-prefiltered.
        int k = atoi(argv[2]), pre = strcmp(argv[1], "benchfzpre") == 0;
        size_t nn; uint8_t *hay = slurp_stdin(&nn);
        const uint8_t *p = (const uint8_t *)argv[3]; size_t m = strlen(argv[3]);
        volatile size_t sink = pre ? scan_kmismatch_pre(hay, nn, p, m, k) : scan_kmismatch(hay, nn, p, m, k);
        (void)sink;
        double dt[9];
        for (int r = 0; r < 9; r++) {
            struct timespec t0, t1;
            clock_gettime(CLOCK_MONOTONIC, &t0);
            sink = pre ? scan_kmismatch_pre(hay, nn, p, m, k) : scan_kmismatch(hay, nn, p, m, k);
            clock_gettime(CLOCK_MONOTONIC, &t1);
            dt[r] = (double)(t1.tv_sec - t0.tv_sec) + (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;
        }
        for (int a = 0; a < 9; a++) for (int b = a + 1; b < 9; b++)
            if (dt[b] < dt[a]) { double t = dt[a]; dt[a] = dt[b]; dt[b] = t; }
        printf("%.0f\n", (double)nn / 1e6 / dt[4]);
        free(hay); return 0;
    }
    if (argc >= 3 && (strcmp(argv[1], "benchre") == 0 || strcmp(argv[1], "benchpre") == 0)) {
        // Median-of-9 MB/s for the regex field: benchre = full field, benchpre =
        // literal-prefiltered field (falls back to full when out of subset).
        int pre = strcmp(argv[1], "benchpre") == 0;
        size_t nn; uint8_t *hay = slurp_stdin(&nn);
        gnfa_t g;
        if (!build_gnfa(argv[2], &g)) { printf("0\n"); free(hay); return 0; }
        int used = 0;
        volatile size_t sink = pre ? regex_prefiltered(hay, nn, argv[2], &g, &used) : scan_gnfa(hay, nn, &g);
        if (pre && !used) sink = scan_gnfa(hay, nn, &g);
        (void)sink;
        double dt[9];
        for (int r = 0; r < 9; r++) {
            struct timespec t0, t1;
            clock_gettime(CLOCK_MONOTONIC, &t0);
            sink = pre ? regex_prefiltered(hay, nn, argv[2], &g, &used) : scan_gnfa(hay, nn, &g);
            if (pre && !used) sink = scan_gnfa(hay, nn, &g);
            clock_gettime(CLOCK_MONOTONIC, &t1);
            dt[r] = (double)(t1.tv_sec - t0.tv_sec) + (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;
        }
        for (int a = 0; a < 9; a++) for (int b = a + 1; b < 9; b++)
            if (dt[b] < dt[a]) { double t = dt[a]; dt[a] = dt[b]; dt[b] = t; }
        printf("%.0f\n", (double)nn / 1e6 / dt[4]);
        free(hay); return 0;
    }
    if (argc >= 3 && strcmp(argv[1], "regexcount") == 0) {
        size_t nn; uint8_t *hay = slurp_stdin(&nn);
        uint8_t sets[64][32];
        int L = parse_classes(argv[2], sets, 64);   // fixed-length fast path
        if (L > 0) {
            size_t r = scan_classfield(hay, nn, sets, L);
            printf("%td\n", (r == (size_t)-1) ? (ptrdiff_t)-1 : (ptrdiff_t)r);
        } else {                                     // quantifiers / alternation
            gnfa_t g;
            if (build_gnfa(argv[2], &g)) printf("%td\n", (ptrdiff_t)scan_gnfa(hay, nn, &g));
            else printf("-1\n");
        }
        free(hay);
        return 0;
    }
    if (argc >= 2 && strcmp(argv[1], "repscore") == 0) {
        size_t n; uint8_t *hay = slurp_stdin(&n);
        printf("%.4f\n", repetition_score(hay, n));
        free(hay);
        return 0;
    }
    if (argc < 4) { fprintf(stderr, "usage: %s count|bench <strategy> <pattern>\n", argv[0]); return 2; }
    const char *mode = argv[1], *strat = argv[2], *pat = argv[3];
    size_t m = strlen(pat), n;
    uint8_t *hay = slurp_stdin(&n);

    if (strcmp(mode, "count") == 0) {
        printf("%zu\n", run(strat, hay, n, (const uint8_t *)pat, m));
    } else if (strcmp(mode, "poscheck") == 0) {
        g_pmode = 1; g_pchk = 1469598103934665603ull;
        run(strat, hay, n, (const uint8_t *)pat, m);
        printf("%llu\n", (unsigned long long)g_pchk);
    } else if (strcmp(mode, "bench") == 0) {
        // Warm one pass (not timed), then the MEDIAN of 9 (honest central value,
        // not the optimistic best-of-N).
        volatile size_t sink = run(strat, hay, n, (const uint8_t *)pat, m);
        (void)sink;
        double dt[9];
        for (int r = 0; r < 9; r++) {
            struct timespec t0, t1;
            clock_gettime(CLOCK_MONOTONIC, &t0);
            sink = run(strat, hay, n, (const uint8_t *)pat, m);
            clock_gettime(CLOCK_MONOTONIC, &t1);
            dt[r] = (double)(t1.tv_sec - t0.tv_sec) + (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;
        }
        for (int a = 0; a < 9; a++) for (int b = a + 1; b < 9; b++)
            if (dt[b] < dt[a]) { double t = dt[a]; dt[a] = dt[b]; dt[b] = t; }
        printf("%.0f\n", (double)n / 1e6 / dt[4]);   // MB/s (median of 9)
    } else {
        fprintf(stderr, "unknown mode: %s\n", mode); return 2;
    }
    free(hay);
    return 0;
}
