// POSITION-SET OPS, INSTANTIATED PER WIDTH.
//
// These MUST live here rather than beside the shared types: they read PW, so a
// single shared copy is compiled once at whatever PW happened to be in scope --
// which was 1. Both engines then called the narrow ops, so the wide engine
// zeroed, OR'd and iterated only word 0. D[1] was genuinely uninitialized, and a
// four-branch alternation that needed 92 positions returned 2 matches instead of
// 4. The compiler said so; the -Wmaybe-uninitialized on D[1] was not noise.
//
// At PW == 1 every loop unrolls to a single scalar operation, so the narrow path
// keeps exactly the code it had when the field was a bare uint64_t.
static inline void FW(ps_zero)(uint64_t *a) { for (int i = 0; i < PW; i++) a[i] = 0; }
static inline void FW(ps_copy)(uint64_t *a, const uint64_t *b) { for (int i = 0; i < PW; i++) a[i] = b[i]; }
static inline void FW(ps_or)(uint64_t *a, const uint64_t *b) { for (int i = 0; i < PW; i++) a[i] |= b[i]; }
static inline void FW(ps_and)(uint64_t *a, const uint64_t *b) { for (int i = 0; i < PW; i++) a[i] &= b[i]; }
static inline int FW(ps_any)(const uint64_t *a) { uint64_t t = 0; for (int i = 0; i < PW; i++) t |= a[i]; return t != 0; }
static inline void FW(ps_set)(uint64_t *a, int p) { a[p >> 6] |= 1ull << (p & 63); }
static inline int FW(ps_test)(const uint64_t *a, int p) { return (int)((a[p >> 6] >> (p & 63)) & 1u); }
static inline int FW(ps_eq)(const uint64_t *a, const uint64_t *b) {
    for (int i = 0; i < PW; i++) if (a[i] != b[i]) return 0;
    return 1;
}
// Iterate the set bits of `a`, lowest first, binding `i`. Undefined at the end
// of this file so the next instantiation can define its own.
#define PS_FOREACH(a, i, BODY) \
    do { for (int _w = 0; _w < PW; _w++) { \
        uint64_t _t = (a)[_w]; \
        while (_t) { int i = (_w << 6) + __builtin_ctzll(_t); _t &= _t - 1; BODY } \
    } } while (0)

// W-DEPENDENT ENGINE, INSTANTIATED PER FIELD WIDTH.
//
// Included once per specialization with PW set to the number of 64-bit words
// in a position set and FW() naming the instance. At PW == 1 every ps_* loop
// unrolls to a single scalar operation, so the narrow path keeps exactly the
// code it had when the field was a bare uint64_t -- which is the whole reason
// this is specialized rather than parameterized at run time.
//
// Nothing here is guarded by an include guard ON PURPOSE: it is meant to be
// included more than once.

// A literal byte SEQUENCE as a chain of positions, returned as one atom. Used
// for the case-fold alternation below, where each branch is a whole UTF-8
// encoding rather than a single byte.
static gattr_t FW(g_bytes)(gpar_t *x, const unsigned char *bytes, int n) {
    gattr_t a; a.nullable = 0; FW(ps_zero)(a.first); FW(ps_zero)(a.last);
    int first_pos = -1, prev = -1;
    for (int i = 0; i < n; i++) {
        if (x->g->npos >= x->g->nwords * 64) { x->g->ok = 0; return a; }
        int p = x->g->npos++;
        memset(x->g->setb[p], 0, 32);
        gset_byte(x->g->setb[p], bytes[i], 0);   // exact bytes: the fold is the branch
        if (first_pos < 0) first_pos = p;
        else FW(ps_set)(x->g->follow[prev], p);
        prev = p;
    }
    if (first_pos < 0) { a.nullable = 1; return a; }
    FW(ps_set)(a.first, first_pos);
    FW(ps_set)(a.last, prev);
    return a;
}

static gattr_t FW(g_atom)(gpar_t *x) {
    gattr_t a; a.nullable = 0; FW(ps_zero)(a.first); FW(ps_zero)(a.last);
    char c = *x->p;
    int icase = x->g->icase;
    if (c == '(') {
        x->p++; a = FW(g_alt)(x);
        if (*x->p == ')') x->p++; else x->g->ok = 0;
        return a;
    }
    // CASE FOLD THAT NEEDS AN ALTERNATION, decided BEFORE a position is
    // allocated. These are the folds whose two UTF-8 encodings differ before the
    // last byte, or in length: one position sequence cannot hold both without
    // also accepting the CROSSINGS -- an upper lead byte followed by a lower
    // tail, decoding to a character nobody wrote. Two branches instead, which
    // costs positions and is why the field learned a second width.
    if (icase && (unsigned char)c >= 0xC0 && x->fold_left == 0) {
        uint32_t cp = 0;
        int n = u8_decode((const unsigned char *)x->p, strlen(x->p), &cp);
        uint32_t members[3];
        int nm = n >= 2 ? fold_alt_members(cp, members) : 0;
        if (nm > 0) {
            // One branch per class member, the written form first. A class can
            // hold up to four (case folding is not a bijection).
            gattr_t br = FW(g_bytes)(x, (const unsigned char *)x->p, n);
            FW(ps_copy)(a.first, br.first);
            FW(ps_copy)(a.last,  br.last);
            for (int i = 0; i < nm && x->g->ok; i++) {
                unsigned char enc[4];
                int m = u8_encode(members[i], enc);
                if (m <= 0) continue;
                gattr_t b2 = FW(g_bytes)(x, enc, m);
                FW(ps_or)(a.first, b2.first);
                FW(ps_or)(a.last,  b2.last);
            }
            if (!x->g->ok) return a;
            a.nullable = 0;
            x->p += n;
            return a;
        }
    }
    if (x->g->npos >= x->g->nwords * 64) { x->g->ok = 0; return a; }
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
    a.nullable = 0;
    FW(ps_zero)(a.first); FW(ps_set)(a.first, pos);
    FW(ps_zero)(a.last);  FW(ps_set)(a.last,  pos);
    return a;
}

static gattr_t FW(g_repeat)(gpar_t *x) {
    int pos_before = x->g->npos;
    gattr_t a = FW(g_atom)(x);
    char c = *x->p;
    if (c == '*' || c == '+') {
        x->p++;
        PS_FOREACH(a.last, i, { FW(ps_or)(x->g->follow[i], a.first); });
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
            FW(ps_zero)(a.first); FW(ps_zero)(a.last); a.nullable = 1;
            return a;
        }
        uint8_t setcopy[32]; memcpy(setcopy, x->g->setb[pos_before], 32);
        if (lo == 0) a.nullable = 1;
        for (int ci = 1; ci < hi; ci++) {
            if (x->g->npos >= x->g->nwords * 64) { x->g->ok = 0; return a; }
            int p = x->g->npos++;
            memcpy(x->g->setb[p], setcopy, 32);
            gattr_t b; b.nullable = (ci >= lo) ? 1 : 0;
            FW(ps_zero)(b.first); FW(ps_set)(b.first, p);
            FW(ps_zero)(b.last);  FW(ps_set)(b.last,  p);
            PS_FOREACH(a.last, i, { FW(ps_or)(x->g->follow[i], b.first); });
            uint64_t nf[SUBLIMATION_SEARCH_POS_WORDS], nl[SUBLIMATION_SEARCH_POS_WORDS];
            FW(ps_copy)(nf, a.first); if (a.nullable) FW(ps_or)(nf, b.first);
            FW(ps_copy)(nl, b.last);  if (b.nullable) FW(ps_or)(nl, a.last);
            FW(ps_copy)(a.first, nf); FW(ps_copy)(a.last, nl);
            a.nullable = a.nullable && b.nullable;
        }
    }
    return a;
}

static gattr_t FW(g_concat)(gpar_t *x) {
    gattr_t a; a.nullable = 1; FW(ps_zero)(a.first); FW(ps_zero)(a.last);
    int any = 0;
    // `&& x->g->ok`: once a position-cap or syntax error trips ok, g_atom stops
    // consuming input, so without this guard the loop spins forever on an
    // over-64-position pattern instead of returning invalid.
    while (*x->p && *x->p != '|' && *x->p != ')' && x->g->ok) {
        gattr_t b = FW(g_repeat)(x);
        if (!any) { a = b; any = 1; }
        else {
            PS_FOREACH(a.last, i, { FW(ps_or)(x->g->follow[i], b.first); });
            uint64_t nf[SUBLIMATION_SEARCH_POS_WORDS], nl[SUBLIMATION_SEARCH_POS_WORDS];
            FW(ps_copy)(nf, a.first); if (a.nullable) FW(ps_or)(nf, b.first);
            FW(ps_copy)(nl, b.last);  if (b.nullable) FW(ps_or)(nl, a.last);
            FW(ps_copy)(a.first, nf); FW(ps_copy)(a.last, nl);
            a.nullable = a.nullable && b.nullable;
        }
    }
    return a;
}

static gattr_t FW(g_alt)(gpar_t *x) {
    gattr_t a = FW(g_concat)(x);
    while (*x->p == '|' && x->g->ok) {
        x->p++; gattr_t b = FW(g_concat)(x);
        FW(ps_or)(a.first, b.first); FW(ps_or)(a.last, b.last);
        a.nullable = a.nullable || b.nullable;
    }
    return a;
}

static int FW(build_gnfa)(const char *pat, gnfa_t *g, int icase) {
    memset(g, 0, sizeof(*g)); g->ok = 1; g->icase = icase;
    // Width of the position field for this pattern. One word is the common
    // path and the only one built today; the wide path is selected here once
    // the two-word specialization exists.
    g->nwords = PW;
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
        g->npos = 0; FW(ps_zero)(g->first); FW(ps_zero)(g->last); g->nullable_all = 1;
        return 1;
    }
    memcpy(buf, pat + s, e - s); buf[e - s] = '\0';
    gpar_t x = { buf, g, 0, 0 };
    gattr_t a = FW(g_alt)(&x);
    if (!g->ok || *x.p != '\0' || g->npos == 0) return 0;
    FW(ps_copy)(g->first, a.first); FW(ps_copy)(g->last, a.last);
    g->nullable_all = a.nullable;
    return 1;
}

// Build the per-byte position map. Case-insensitivity is already folded into
// each position's set at compile time (see gset_byte), so this is a plain map.
static void FW(build_imap)(const gnfa_t *g, uint64_t I[256][SUBLIMATION_SEARCH_POS_WORDS]) {
    for (int c = 0; c < 256; c++) {
        FW(ps_zero)(I[c]);
        for (int i = 0; i < g->npos; i++) {
            if ((g->setb[i][c>>3] >> (c&7)) & 1) FW(ps_set)(I[c], i);
        }
    }
}

// reach(D) = first | union(follow[i], i in D), memoized on the state set.
static inline void FW(reach_compute)(const uint64_t *D, const gnfa_t *g, uint64_t *out) {
    FW(ps_copy)(out, g->first);
    PS_FOREACH(D, i, { FW(ps_or)(out, g->follow[i]); });
}

static inline void FW(reach_of)(const uint64_t *D, const gnfa_t *g, reach_ent *cache,
                            uint64_t *out) {
    if (!FW(ps_any)(D)) { FW(ps_copy)(out, g->first); return; }
    uint64_t mix = 0;
    for (int w = 0; w < PW; w++) mix = (mix ^ D[w]) * 0x9E3779B97F4A7C15ull;
    size_t h = (size_t)(mix >> (64 - REACH_BITS));
    size_t probes = 0;
    while (cache[h].used && !FW(ps_eq)(cache[h].key, D)) {
        h = (h + 1) & (REACH_CAP - 1);
        // A pathological pattern can produce more than REACH_CAP distinct state
        // sets and fill the table; compute the reach without memoizing rather
        // than probe forever.
        if (++probes >= REACH_CAP) { FW(reach_compute)(D, g, out); return; }
    }
    if (cache[h].used) { FW(ps_copy)(out, cache[h].reach); return; }
    FW(reach_compute)(D, g, out);
    FW(ps_copy)(cache[h].key, D); FW(ps_copy)(cache[h].reach, out); cache[h].used = 1;
}

// Full-field match-end count over hay[0..n). Byte-parity reference for the regex
// face; the prefilter and class fast path must reproduce this exactly. `I` is
// the compile-time per-byte position map (sublimation_search.imap).
static size_t FW(scan_gnfa)(const uint8_t *hay, size_t n, const gnfa_t *g,
                        const uint64_t I[256][SUBLIMATION_SEARCH_POS_WORDS]) {
    if (g->nullable_all && !g->anchored_start && !g->anchored_end) return n + 1;
    // Anchor-only pattern (npos == 0): exactly one zero-width match, at the
    // start for ^ or the end for $; ^$ only matches the empty field.
    if (g->npos == 0) {
        if (g->anchored_start && g->anchored_end) return n == 0 ? 1 : 0;
        return 1;
    }
    uint64_t D[SUBLIMATION_SEARCH_POS_WORDS]; FW(ps_zero)(D);
    uint64_t reach[SUBLIMATION_SEARCH_POS_WORDS], acc[SUBLIMATION_SEARCH_POS_WORDS];
    size_t count = 0;
    if (g->anchored_start || g->anchored_end) {
        for (size_t j = 0; j < n; j++) {
            if (!g->anchored_start || j == 0) FW(ps_copy)(reach, g->first);
            else FW(ps_zero)(reach);
            PS_FOREACH(D, i, { FW(ps_or)(reach, g->follow[i]); });
            FW(ps_copy)(D, reach); FW(ps_and)(D, I[(unsigned char)hay[j]]);
            FW(ps_copy)(acc, D); FW(ps_and)(acc, g->last);
            if (FW(ps_any)(acc) && (!g->anchored_end || j + 1 == n)) count++;
        }
        return count;
    }
    reach_ent *cache = reach_cache_get();
    if (!cache) {
        // Allocation failure: no-cache scan (same fallback convention as the
        // fuzzy face). Recomputes reach per step; byte-identical count.
        for (size_t j = 0; j < n; j++) {
            FW(reach_compute)(D, g, reach);
            FW(ps_copy)(D, reach); FW(ps_and)(D, I[(unsigned char)hay[j]]);
            FW(ps_copy)(acc, D); FW(ps_and)(acc, g->last);
            if (FW(ps_any)(acc)) count++;
        }
        return count;
    }
    for (size_t j = 0; j < n; j++) {
        FW(reach_of)(D, g, cache, reach);
        FW(ps_copy)(D, reach); FW(ps_and)(D, I[(unsigned char)hay[j]]);
        FW(ps_copy)(acc, D); FW(ps_and)(acc, g->last);
        if (FW(ps_any)(acc)) count++;
    }
    return count;
}

static size_t FW(gnfa_range)(const uint8_t *hay, size_t a, size_t b,
                         const uint64_t I[256][SUBLIMATION_SEARCH_POS_WORDS],
                         const gnfa_t *g, reach_ent *cache) {
    uint64_t D[SUBLIMATION_SEARCH_POS_WORDS]; FW(ps_zero)(D);
    uint64_t reach[SUBLIMATION_SEARCH_POS_WORDS], acc[SUBLIMATION_SEARCH_POS_WORDS];
    size_t count = 0;
    for (size_t j = a; j < b; j++) {
        FW(reach_of)(D, g, cache, reach);
        FW(ps_copy)(D, reach); FW(ps_and)(D, I[hay[j]]);
        FW(ps_copy)(acc, D); FW(ps_and)(acc, g->last);
        if (FW(ps_any)(acc)) count++;
    }
    return count;
}

// Prefiltered regex count: anchor on a required literal, run the field only over
// coalesced regions around its occurrences. *used stays 0 (result meaningless) when
// the pattern is outside the sound subset, so the caller falls back. Provably byte-
// identical to the full field on the subset.
static size_t FW(regex_prefiltered)(const uint8_t *hay, size_t n, const char *pat,
                                const gnfa_t *g,
                                const uint64_t I[256][SUBLIMATION_SEARCH_POS_WORDS],
                                int *used) {
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
    reach_ent *cache = reach_cache_get();
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
            else { count += FW(gnfa_range)(hay, reg_start, reg_end, I, g, cache); reg_start = ws; reg_end = we; }
        }
        q = hit + 1;
    }
    if (have) count += FW(gnfa_range)(hay, reg_start, reg_end, I, g, cache);
    *used = 1;
    return count;
}

// Regex count dispatch. Prefilter where applicable, else the class fast path, else
// the full field -- all byte-identical to the full field.
static size_t FW(regex_count)(const sublimation_search *s, const uint8_t *hay, size_t n) {
    // Anchor-only patterns have no positions for the prefilter or class field
    // to anchor on; the full field handles their zero-width semantics directly.
    if (s->g.npos == 0) return FW(scan_gnfa)(hay, n, &s->g, s->imap);
    if (s->icase) return FW(scan_gnfa)(hay, n, &s->g, s->imap);
    int used = 0;
    size_t r = FW(regex_prefiltered)(hay, n, s->pattern, &s->g, s->imap, &used);
    if (used) return r;
    uint8_t sets[64][32];
    int L = parse_classes(s->pattern, sets, 64);
    if (L > 0) { size_t c = scan_classfield(hay, n, sets, L); if (c != (size_t)-1) return c; }
    return FW(scan_gnfa)(hay, n, &s->g, s->imap);
}

// Fixed-start Glushkov walk: longest match-end for a match starting exactly at
// `start`, or -1. No restart when the field goes empty (fixed start, not a scan).
static long FW(gnfa_start_longest)(const gnfa_t *g,
                               const uint64_t I[256][SUBLIMATION_SEARCH_POS_WORDS],
                               const uint8_t *hay, size_t n, size_t start) {
    long best = -1;
    if (g->nullable_all && (!g->anchored_end || start == n)) best = (long)start;
    uint64_t D[SUBLIMATION_SEARCH_POS_WORDS]; FW(ps_zero)(D);
    uint64_t cand[SUBLIMATION_SEARCH_POS_WORDS], acc[SUBLIMATION_SEARCH_POS_WORDS];
    int consumed = 0;
    for (size_t j = start; j < n; j++) {
        if (!consumed) FW(ps_copy)(cand, g->first);
        else { FW(ps_zero)(cand); PS_FOREACH(D, i, { FW(ps_or)(cand, g->follow[i]); }); }
        FW(ps_copy)(D, cand); FW(ps_and)(D, I[hay[j]]);
        consumed = 1;
        if (!FW(ps_any)(D)) break;
        FW(ps_copy)(acc, D); FW(ps_and)(acc, g->last);
        if (FW(ps_any)(acc)) { if (!g->anchored_end || j + 1 == n) best = (long)(j + 1); }
    }
    return best;
}

// Whole-input match: does the regex match hay[0..n) end to end?
static int FW(gnfa_full)(const gnfa_t *g,
                     const uint64_t I[256][SUBLIMATION_SEARCH_POS_WORDS],
                     const uint8_t *hay, size_t n) {
    if (n == 0) return g->nullable_all;
    uint64_t D[SUBLIMATION_SEARCH_POS_WORDS], reach[SUBLIMATION_SEARCH_POS_WORDS];
    FW(ps_copy)(D, g->first); FW(ps_and)(D, I[hay[0]]);
    if (!FW(ps_any)(D)) return 0;
    for (size_t j = 1; j < n; j++) {
        FW(ps_zero)(reach);
        PS_FOREACH(D, i, { FW(ps_or)(reach, g->follow[i]); });
        FW(ps_copy)(D, reach); FW(ps_and)(D, I[hay[j]]);
        if (!FW(ps_any)(D)) return 0;
    }
    FW(ps_and)(D, g->last);
    return FW(ps_any)(D);
}

#undef PS_FOREACH
