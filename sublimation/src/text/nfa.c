// nfa.c -- Thompson NFA regex engine (sublimation_text.h).
// 1:1 C23 port of montauk's ThompsonNFA: same UTF-8 decode/encode, same
// shunting-yard, same codepoint->byte fragment lowering, same SPLIT/CHAR/CLASS
// simulation, same leftmost-longest find(). The C++ original is the oracle; this
// matches it byte-for-byte on every (pattern, input) pair.
#include "sublimation_text.h"
#include <stdlib.h>
#include <string.h>

// ── Op codes (mirror C++ enum class Op) ────────────────────────────────
enum { OP_CHAR = 0, OP_CLASS = 1, OP_SPLIT = 2, OP_MATCH = 3 };

#define MAX_STATES SUBLIMATION_NFA_MAX_STATES
#define SETWORDS   (MAX_STATES / 64)   // 4
#define MAX_OUTS   MAX_STATES          // a fragment's dangling outputs <= states

// ── CharClass helpers ───────────────────────────────────────────────────
static inline void cc_clear(sublimation_nfa_class *c) { memset(c->bits, 0, 32); }
static inline void cc_set(sublimation_nfa_class *c, uint8_t v) { c->bits[v >> 3] |= (uint8_t)(1u << (v & 7)); }
static inline int  cc_test(const sublimation_nfa_class *c, uint8_t v) { return (c->bits[v >> 3] >> (v & 7)) & 1; }
static inline void cc_set_range(sublimation_nfa_class *c, uint8_t lo, uint8_t hi) {
    for (int v = lo; v <= hi; ++v) cc_set(c, (uint8_t)v);
}

// ── Bitset helpers (simulation) ──────────────────────────────────────────
static inline void set_bit(uint64_t *s, int i)  { s[i >> 6] |= (1ULL << (i & 63)); }
static inline int  test_bit(const uint64_t *s, int i) { return (s[i >> 6] & (1ULL << (i & 63))) != 0; }
static inline void clear_set(uint64_t *s) { for (int i = 0; i < SETWORDS; ++i) s[i] = 0; }
static inline int  empty_set(const uint64_t *s) { for (int i = 0; i < SETWORDS; ++i) if (s[i]) return 0; return 1; }

// ── UTF-8 (verbatim from the C++) ────────────────────────────────────────
static int decode_utf8(const char *s, size_t len, uint32_t *cp) {
    if (len == 0) return 0;
    uint8_t c = (uint8_t)s[0];
    if (c < 0x80) { *cp = c; return 1; }
    if ((c & 0xE0) == 0xC0 && len >= 2) {
        *cp = ((uint32_t)(c & 0x1F) << 6) | (s[1] & 0x3F);
        return (*cp >= 0x80) ? 2 : 0;
    }
    if ((c & 0xF0) == 0xE0 && len >= 3) {
        *cp = ((uint32_t)(c & 0x0F) << 12) | ((uint32_t)(s[1] & 0x3F) << 6) | (s[2] & 0x3F);
        return (*cp >= 0x800) ? 3 : 0;
    }
    if ((c & 0xF8) == 0xF0 && len >= 4) {
        *cp = ((uint32_t)(c & 0x07) << 18) | ((uint32_t)(s[1] & 0x3F) << 12)
            | ((uint32_t)(s[2] & 0x3F) << 6) | (s[3] & 0x3F);
        return (*cp >= 0x10000 && *cp <= 0x10FFFF) ? 4 : 0;
    }
    return 0;
}

static int encode_utf8(uint32_t cp, uint8_t out[4]) {
    if (cp < 0x80)    { out[0] = (uint8_t)cp; return 1; }
    if (cp < 0x800)   { out[0] = (uint8_t)(0xC0 | (cp >> 6)); out[1] = (uint8_t)(0x80 | (cp & 0x3F)); return 2; }
    if (cp < 0x10000) { out[0] = (uint8_t)(0xE0 | (cp >> 12)); out[1] = (uint8_t)(0x80 | ((cp >> 6) & 0x3F));
                        out[2] = (uint8_t)(0x80 | (cp & 0x3F)); return 3; }
    out[0] = (uint8_t)(0xF0 | (cp >> 18)); out[1] = (uint8_t)(0x80 | ((cp >> 12) & 0x3F));
    out[2] = (uint8_t)(0x80 | ((cp >> 6) & 0x3F)); out[3] = (uint8_t)(0x80 | (cp & 0x3F));
    return 4;
}

// ── Tokens / ranges / fragments ──────────────────────────────────────────
enum {
    T_LITERAL, T_DOT, T_STAR, T_PLUS, T_QUES, T_PIPE,
    T_LPAREN, T_RPAREN, T_ANCHOR_S, T_ANCHOR_E, T_CLASS, T_CONCAT
};

typedef struct { uint32_t lo, hi; } cprange;
typedef struct { uint8_t type; uint32_t cp; uint8_t class_idx; uint8_t negated; } tok_t;
typedef struct { int16_t state; uint8_t is_out1; } patch_t;
typedef struct { int start; patch_t outs[MAX_OUTS]; int n_outs; } frag_t;

// ── State / class construction ───────────────────────────────────────────
static int nfa_add_state(sublimation_nfa *n, uint8_t op, int16_t out, int16_t out1) {
    if (n->num_states >= MAX_STATES) return -1;
    sublimation_nfa_state *s = &n->states[n->num_states];
    s->op = op; s->ch = 0; s->class_idx = 0; s->negated = 0; s->out = out; s->out1 = out1;
    return n->num_states++;
}
static int nfa_add_char(sublimation_nfa *n, uint8_t ch, int16_t out) {
    int s = nfa_add_state(n, OP_CHAR, out, -1);
    if (s >= 0) n->states[s].ch = ch;
    return s;
}
static int nfa_add_class(sublimation_nfa *n, uint8_t class_idx, int negated, int16_t out) {
    int s = nfa_add_state(n, OP_CLASS, out, -1);
    if (s >= 0) { n->states[s].class_idx = class_idx; n->states[s].negated = (uint8_t)negated; }
    return s;
}
// Reserve a fresh, cleared class. Returns its index, or -1 if the table is full.
static int nfa_new_class(sublimation_nfa *n) {
    if (n->num_classes >= MAX_STATES) return -1;
    cc_clear(&n->classes[n->num_classes]);
    return n->num_classes++;
}

static void frag_patch(sublimation_nfa *n, const patch_t *outs, int n_outs, int target) {
    for (int i = 0; i < n_outs; ++i) {
        if (outs[i].is_out1) n->states[outs[i].state].out1 = (int16_t)target;
        else                 n->states[outs[i].state].out  = (int16_t)target;
    }
}
// Append src outs onto dst; returns 0 on overflow.
static int outs_append(patch_t *dst, int *dn, const patch_t *src, int sn) {
    if (*dn + sn > MAX_OUTS) return 0;
    for (int i = 0; i < sn; ++i) dst[(*dn)++] = src[i];
    return 1;
}

// Compile-time scratch, malloc'd by pattern size.
typedef struct {
    tok_t   *tokens;       int n_tokens;
    cprange *range_pool;   int range_pool_n;
    struct { int off, cnt; } *cls;  int n_cls;   // parse-phase classes (parallel to CLASS tokens)
    tok_t   *withcc;       int n_withcc;
    tok_t   *postfix;      int n_postfix;
    tok_t   *opstack;      int n_opstack;
    frag_t  *fstack;       int n_fstack;
} cctx_t;

static int prec(uint8_t t) {
    if (t == T_PIPE)   return 2;
    if (t == T_CONCAT) return 3;
    return 0;
}

// ── Fragment builders (the C++ lambdas, as functions) ────────────────────

// Single codepoint -> chain of CHAR states.
static frag_t make_codepoint_frag(sublimation_nfa *n, uint32_t cp, int *ok) {
    frag_t f; f.start = -1; f.n_outs = 0;
    uint8_t buf[4];
    int cnt = encode_utf8(cp, buf);
    int first = nfa_add_char(n, buf[0], -1);
    if (first < 0) { *ok = 0; return f; }
    int prev = first;
    for (int i = 1; i < cnt; ++i) {
        int s = nfa_add_char(n, buf[i], -1);
        if (s < 0) { *ok = 0; return f; }
        n->states[prev].out = (int16_t)s;
        prev = s;
    }
    f.start = first; f.outs[0].state = (int16_t)prev; f.outs[0].is_out1 = 0; f.n_outs = 1;
    return f;
}

// Any single UTF-8 codepoint (dot lowering, excludes '\n').
static frag_t make_dot_frag(sublimation_nfa *n, int *ok) {
    frag_t f; f.start = -1; f.n_outs = 0;
    int ci_ascii = nfa_new_class(n);
    if (ci_ascii < 0) { *ok = 0; return f; }
    for (int c = 0; c < 0x80; ++c) if (c != '\n') cc_set(&n->classes[ci_ascii], (uint8_t)c);
    int s_ascii = nfa_add_class(n, (uint8_t)ci_ascii, 0, -1);

    int ci_lead2 = nfa_new_class(n);
    if (ci_lead2 < 0) { *ok = 0; return f; }
    cc_set_range(&n->classes[ci_lead2], 0xC2, 0xDF);
    int ci_cont = nfa_new_class(n);
    if (ci_cont < 0) { *ok = 0; return f; }
    cc_set_range(&n->classes[ci_cont], 0x80, 0xBF);
    int s_cont2 = nfa_add_class(n, (uint8_t)ci_cont, 0, -1);
    int s_lead2 = nfa_add_class(n, (uint8_t)ci_lead2, 0, (int16_t)s_cont2);

    int ci_lead3 = nfa_new_class(n);
    if (ci_lead3 < 0) { *ok = 0; return f; }
    cc_set_range(&n->classes[ci_lead3], 0xE0, 0xEF);
    int s_cont3b = nfa_add_class(n, (uint8_t)ci_cont, 0, -1);
    int s_cont3a = nfa_add_class(n, (uint8_t)ci_cont, 0, (int16_t)s_cont3b);
    int s_lead3 = nfa_add_class(n, (uint8_t)ci_lead3, 0, (int16_t)s_cont3a);

    int ci_lead4 = nfa_new_class(n);
    if (ci_lead4 < 0) { *ok = 0; return f; }
    cc_set_range(&n->classes[ci_lead4], 0xF0, 0xF4);
    int s_cont4c = nfa_add_class(n, (uint8_t)ci_cont, 0, -1);
    int s_cont4b = nfa_add_class(n, (uint8_t)ci_cont, 0, (int16_t)s_cont4c);
    int s_cont4a = nfa_add_class(n, (uint8_t)ci_cont, 0, (int16_t)s_cont4b);
    int s_lead4 = nfa_add_class(n, (uint8_t)ci_lead4, 0, (int16_t)s_cont4a);

    if (s_ascii < 0 || s_lead2 < 0 || s_lead3 < 0 || s_lead4 < 0) { *ok = 0; return f; }

    int sp3 = nfa_add_state(n, OP_SPLIT, (int16_t)s_lead3, (int16_t)s_lead4);
    int sp2 = nfa_add_state(n, OP_SPLIT, (int16_t)s_lead2, (int16_t)sp3);
    int sp1 = nfa_add_state(n, OP_SPLIT, (int16_t)s_ascii, (int16_t)sp2);
    if (sp1 < 0) { *ok = 0; return f; }

    f.start = sp1;
    f.outs[0] = (patch_t){ (int16_t)s_ascii,  0 };
    f.outs[1] = (patch_t){ (int16_t)s_cont2,  0 };
    f.outs[2] = (patch_t){ (int16_t)s_cont3b, 0 };
    f.outs[3] = (patch_t){ (int16_t)s_cont4c, 0 };
    f.n_outs = 4;
    return f;
}

// Complement of `ranges` over [0, cap] -> out (must hold up to n+1 ranges).
static int complement_ranges(const cprange *ranges, int n, uint32_t cap, cprange *out) {
    // sort by lo (insertion sort; n is tiny)
    cprange *s = (cprange*)malloc(sizeof(cprange) * (size_t)(n > 0 ? n : 1));
    if (!s) return -1;
    for (int i = 0; i < n; ++i) s[i] = ranges[i];
    for (int i = 1; i < n; ++i) {
        cprange key = s[i]; int j = i - 1;
        while (j >= 0 && s[j].lo > key.lo) { s[j+1] = s[j]; --j; }
        s[j+1] = key;
    }
    // merge overlapping (+adjacent) ranges
    cprange *merged = (cprange*)malloc(sizeof(cprange) * (size_t)(n > 0 ? n : 1));
    if (!merged) { free(s); return -1; }
    int m = 0;
    for (int i = 0; i < n; ++i) {
        if (m > 0 && s[i].lo <= merged[m-1].hi + 1) {
            if (s[i].hi > merged[m-1].hi) merged[m-1].hi = s[i].hi;
        } else {
            merged[m++] = s[i];
        }
    }
    int r = 0;
    uint32_t cursor = 0;
    for (int i = 0; i < m; ++i) {
        if (merged[i].lo > cursor) out[r++] = (cprange){ cursor, merged[i].lo - 1 };
        cursor = merged[i].hi + 1;
    }
    if (cursor <= cap) out[r++] = (cprange){ cursor, cap };
    free(s); free(merged);
    return r;
}

// Character class with codepoint ranges (negated handled by caller via complement
// for multi-byte, or runtime negation for ASCII-only).
static frag_t make_class_frag(sublimation_nfa *n, const cprange *ranges, int nr, int *ok) {
    frag_t f; f.start = -1; f.n_outs = 0;

    int all_ascii = 1;
    for (int i = 0; i < nr; ++i) if (ranges[i].hi >= 0x80) { all_ascii = 0; break; }

    if (all_ascii) {
        int ci = nfa_new_class(n);
        if (ci < 0) { *ok = 0; return f; }
        for (int i = 0; i < nr; ++i)
            for (uint32_t c = ranges[i].lo; c <= ranges[i].hi; ++c) cc_set(&n->classes[ci], (uint8_t)c);
        int s = nfa_add_class(n, (uint8_t)ci, 0, -1);
        if (s < 0) { *ok = 0; return f; }
        f.start = s; f.outs[0] = (patch_t){ (int16_t)s, 0 }; f.n_outs = 1;
        return f;
    }

    // Multi-byte: alternation of byte-sequence branches.
    frag_t *branches = (frag_t*)malloc(sizeof(frag_t) * MAX_STATES);
    if (!branches) { *ok = 0; return f; }
    int nb = 0;

    sublimation_nfa_class ascii_cls; cc_clear(&ascii_cls);
    int has_ascii = 0;

    for (int ri = 0; ri < nr; ++ri) {
        uint32_t rlo = ranges[ri].lo, rhi = ranges[ri].hi;

        // ASCII portion
        uint32_t alo = rlo, ahi = (rhi < 0x7F) ? rhi : 0x7F;
        if (alo <= 0x7F) {
            has_ascii = 1;
            for (uint32_t c = alo; c <= ahi; ++c) cc_set(&ascii_cls, (uint8_t)c);
        }

        // 2-byte portion (0x80..0x7FF)
        uint32_t blo = (rlo > 0x80) ? rlo : 0x80;
        uint32_t bhi = (rhi < 0x7FF) ? rhi : 0x7FF;
        if (blo <= bhi) {
            for (uint32_t lead_cp = blo; lead_cp <= bhi; ) {
                uint8_t lead = (uint8_t)(0xC0 | (lead_cp >> 6));
                uint32_t cap = (uint32_t)(((lead_cp >> 6) + 1) << 6) - 1;
                uint32_t group_end = (bhi < cap) ? bhi : cap;
                uint8_t tlo = (uint8_t)(0x80 | (lead_cp & 0x3F));
                uint8_t thi = (uint8_t)(0x80 | (group_end & 0x3F));
                int ci = nfa_new_class(n);
                if (ci < 0) { *ok = 0; free(branches); return f; }
                cc_set_range(&n->classes[ci], tlo, thi);
                int s_trail = nfa_add_class(n, (uint8_t)ci, 0, -1);
                int s_lead  = nfa_add_char(n, lead, (int16_t)s_trail);
                if (s_lead < 0 || s_trail < 0) { *ok = 0; free(branches); return f; }
                if (nb >= MAX_STATES) { *ok = 0; free(branches); return f; }
                branches[nb].start = s_lead; branches[nb].outs[0] = (patch_t){ (int16_t)s_trail, 0 };
                branches[nb].n_outs = 1; ++nb;
                lead_cp = group_end + 1;
            }
        }

        // 3-byte portion (0x800..0xFFFF)
        uint32_t clo = (rlo > 0x800)  ? rlo : 0x800;
        uint32_t chi = (rhi < 0xFFFF) ? rhi : 0xFFFF;
        if (clo <= chi) {
            for (uint32_t cp = clo; cp <= chi; ) {
                uint8_t b0 = (uint8_t)(0xE0 | (cp >> 12));
                uint8_t b1_base = (uint8_t)((cp >> 6) & 0x3F);
                uint32_t cap_b1 = (uint32_t)((((cp >> 6) + 1) << 6) - 1);
                uint32_t cap_b0 = (uint32_t)((((cp >> 12) + 1) << 12) - 1);
                uint32_t group_end_b1 = (chi < cap_b1) ? chi : cap_b1;
                uint32_t group_end_b0 = (chi < cap_b0) ? chi : cap_b0;

                if (group_end_b1 < group_end_b0) {
                    uint8_t tlo = (uint8_t)(0x80 | (cp & 0x3F));
                    uint8_t thi = (uint8_t)(0x80 | (group_end_b1 & 0x3F));
                    int ci = nfa_new_class(n);
                    if (ci < 0) { *ok = 0; free(branches); return f; }
                    cc_set_range(&n->classes[ci], tlo, thi);
                    int s2 = nfa_add_class(n, (uint8_t)ci, 0, -1);
                    int s1 = nfa_add_char(n, (uint8_t)(0x80 | b1_base), (int16_t)s2);
                    int s0 = nfa_add_char(n, b0, (int16_t)s1);
                    if (s0 < 0) { *ok = 0; free(branches); return f; }
                    if (nb >= MAX_STATES) { *ok = 0; free(branches); return f; }
                    branches[nb].start = s0; branches[nb].outs[0] = (patch_t){ (int16_t)s2, 0 };
                    branches[nb].n_outs = 1; ++nb;
                    cp = group_end_b1 + 1;
                } else {
                    uint8_t tlo = (uint8_t)(0x80 | (cp & 0x3F));
                    uint8_t thi = (uint8_t)(0x80 | (group_end_b0 & 0x3F));
                    uint8_t b1lo = (uint8_t)(0x80 | ((cp >> 6) & 0x3F));
                    uint8_t b1hi = (uint8_t)(0x80 | ((group_end_b0 >> 6) & 0x3F));
                    int ci_b1 = nfa_new_class(n);
                    if (ci_b1 < 0) { *ok = 0; free(branches); return f; }
                    cc_set_range(&n->classes[ci_b1], b1lo, b1hi);
                    int ci_b2 = nfa_new_class(n);
                    if (ci_b2 < 0) { *ok = 0; free(branches); return f; }
                    cc_set_range(&n->classes[ci_b2], tlo, thi);
                    int s2 = nfa_add_class(n, (uint8_t)ci_b2, 0, -1);
                    int s1 = nfa_add_class(n, (uint8_t)ci_b1, 0, (int16_t)s2);
                    int s0 = nfa_add_char(n, b0, (int16_t)s1);
                    if (s0 < 0) { *ok = 0; free(branches); return f; }
                    if (nb >= MAX_STATES) { *ok = 0; free(branches); return f; }
                    branches[nb].start = s0; branches[nb].outs[0] = (patch_t){ (int16_t)s2, 0 };
                    branches[nb].n_outs = 1; ++nb;
                    cp = group_end_b0 + 1;
                }
            }
        }
        // 4-byte: omitted in the C++ original too.
    }

    if (has_ascii) {
        int ci = n->num_classes;
        if (ci >= MAX_STATES) { *ok = 0; free(branches); return f; }
        n->classes[ci] = ascii_cls; n->num_classes++;
        int s = nfa_add_class(n, (uint8_t)ci, 0, -1);
        if (s < 0) { *ok = 0; free(branches); return f; }
        if (nb >= MAX_STATES) { *ok = 0; free(branches); return f; }
        // insert at front
        for (int i = nb; i > 0; --i) branches[i] = branches[i-1];
        branches[0].start = s; branches[0].outs[0] = (patch_t){ (int16_t)s, 0 };
        branches[0].n_outs = 1; ++nb;
    }

    if (nb == 0) { *ok = 0; free(branches); return f; }
    if (nb == 1) { f = branches[0]; free(branches); return f; }

    // Alternation tree from branches.
    frag_t result = branches[nb-1];
    for (int i = nb - 2; i >= 0; --i) {
        int sp = nfa_add_state(n, OP_SPLIT, (int16_t)branches[i].start, (int16_t)result.start);
        if (sp < 0) { *ok = 0; free(branches); return f; }
        patch_t outs[MAX_OUTS]; int no = 0;
        if (!outs_append(outs, &no, branches[i].outs, branches[i].n_outs) ||
            !outs_append(outs, &no, result.outs, result.n_outs)) { *ok = 0; free(branches); return f; }
        result.start = sp; memcpy(result.outs, outs, sizeof(patch_t) * (size_t)no); result.n_outs = no;
    }
    free(branches);
    return result;
}

// ── Compile ───────────────────────────────────────────────────────────────
static int nfa_compile(sublimation_nfa *n, const char *pattern, size_t plen) {
    n->num_states = 0; n->num_classes = 0;
    n->start = -1; n->anchored_start = 0; n->anchored_end = 0;

    size_t cap = plen + 2;
    cctx_t cx; memset(&cx, 0, sizeof(cx));
    cx.tokens     = (tok_t*)  malloc(sizeof(tok_t)   * cap);
    cx.range_pool = (cprange*)malloc(sizeof(cprange) * cap);
    cx.cls        = malloc(sizeof(*cx.cls) * cap);
    cx.withcc     = (tok_t*)  malloc(sizeof(tok_t)   * (cap * 2));
    cx.postfix    = (tok_t*)  malloc(sizeof(tok_t)   * (cap * 2));
    cx.opstack    = (tok_t*)  malloc(sizeof(tok_t)   * (cap * 2));
    cx.fstack     = (frag_t*) malloc(sizeof(frag_t)  * (cap * 2));
    int rc = 0;
    if (!cx.tokens || !cx.range_pool || !cx.cls || !cx.withcc ||
        !cx.postfix || !cx.opstack || !cx.fstack) goto done;

    const char *p = pattern;
    const char *end = pattern + plen;

    if (p < end && *p == '^') { n->anchored_start = 1; ++p; }

    if (plen >= 1 && pattern[plen-1] == '$') {
        int backslashes = 0;
        for (int i = (int)plen - 2; i >= 0 && pattern[i] == '\\'; --i) ++backslashes;
        if (backslashes % 2 == 0) { n->anchored_end = 1; --end; }
    }

    // Phase 1: tokenize
    while (p < end) {
        uint8_t c = (uint8_t)*p;
        if (c == '\\' && p + 1 < end) {
            ++p; uint32_t cp;
            int nn = decode_utf8(p, (size_t)(end - p), &cp);
            if (nn == 0) goto done;
            cx.tokens[cx.n_tokens++] = (tok_t){ T_LITERAL, cp, 0, 0 };
            p += nn;
        } else if (c == '.') { cx.tokens[cx.n_tokens++] = (tok_t){ T_DOT, 0, 0, 0 }; ++p; }
        else if (c == '*')   { cx.tokens[cx.n_tokens++] = (tok_t){ T_STAR, 0, 0, 0 }; ++p; }
        else if (c == '+')   { cx.tokens[cx.n_tokens++] = (tok_t){ T_PLUS, 0, 0, 0 }; ++p; }
        else if (c == '?')   { cx.tokens[cx.n_tokens++] = (tok_t){ T_QUES, 0, 0, 0 }; ++p; }
        else if (c == '|')   { cx.tokens[cx.n_tokens++] = (tok_t){ T_PIPE, 0, 0, 0 }; ++p; }
        else if (c == '(')   { cx.tokens[cx.n_tokens++] = (tok_t){ T_LPAREN, 0, 0, 0 }; ++p; }
        else if (c == ')')   { cx.tokens[cx.n_tokens++] = (tok_t){ T_RPAREN, 0, 0, 0 }; ++p; }
        else if (c == '[') {
            ++p;
            int neg = 0;
            if (p < end && *p == '^') { neg = 1; ++p; }
            int roff = cx.range_pool_n, rcnt = 0;
            int first = 1;
            while (p < end && (*p != ']' || first)) {
                first = 0;
                uint32_t lo;
                if (*p == '\\' && p + 1 < end) {
                    ++p; int nn = decode_utf8(p, (size_t)(end - p), &lo);
                    if (nn == 0) goto done; p += nn;
                } else {
                    int nn = decode_utf8(p, (size_t)(end - p), &lo);
                    if (nn == 0) goto done; p += nn;
                }
                if (p + 1 < end && *p == '-' && *(p+1) != ']') {
                    ++p; uint32_t hi;
                    if (*p == '\\' && p + 1 < end) {
                        ++p; int nn = decode_utf8(p, (size_t)(end - p), &hi);
                        if (nn == 0) goto done; p += nn;
                    } else {
                        int nn = decode_utf8(p, (size_t)(end - p), &hi);
                        if (nn == 0) goto done; p += nn;
                    }
                    if (hi < lo) { uint32_t t = lo; lo = hi; hi = t; }
                    cx.range_pool[cx.range_pool_n++] = (cprange){ lo, hi }; ++rcnt;
                } else {
                    cx.range_pool[cx.range_pool_n++] = (cprange){ lo, lo }; ++rcnt;
                }
            }
            if (p < end && *p == ']') ++p; else goto done;
            uint8_t cidx = (uint8_t)cx.n_cls;
            cx.cls[cx.n_cls].off = roff; cx.cls[cx.n_cls].cnt = rcnt; ++cx.n_cls;
            cx.tokens[cx.n_tokens++] = (tok_t){ T_CLASS, 0, cidx, (uint8_t)neg };
        } else {
            uint32_t cp; int nn = decode_utf8(p, (size_t)(end - p), &cp);
            if (nn == 0) goto done;
            cx.tokens[cx.n_tokens++] = (tok_t){ T_LITERAL, cp, 0, 0 };
            p += nn;
        }
    }

    if (cx.n_tokens == 0 && !n->anchored_start && !n->anchored_end) goto done;

    // Phase 2: insert explicit CONCAT
    for (int i = 0; i < cx.n_tokens; ++i) {
        cx.withcc[cx.n_withcc++] = cx.tokens[i];
        if (i + 1 < cx.n_tokens) {
            uint8_t a = cx.tokens[i].type, b = cx.tokens[i+1].type;
            int a_prod = (a == T_LITERAL || a == T_DOT || a == T_CLASS || a == T_RPAREN
                       || a == T_STAR || a == T_PLUS || a == T_QUES);
            int b_cons = (b == T_LITERAL || b == T_DOT || b == T_CLASS || b == T_LPAREN);
            if (a_prod && b_cons) cx.withcc[cx.n_withcc++] = (tok_t){ T_CONCAT, 0, 0, 0 };
        }
    }

    // Phase 3: shunting-yard -> postfix
    for (int i = 0; i < cx.n_withcc; ++i) {
        tok_t tok = cx.withcc[i];
        switch (tok.type) {
            case T_LITERAL: case T_DOT: case T_CLASS:
            case T_STAR: case T_PLUS: case T_QUES:
                cx.postfix[cx.n_postfix++] = tok; break;
            case T_LPAREN:
                cx.opstack[cx.n_opstack++] = tok; break;
            case T_RPAREN:
                while (cx.n_opstack > 0 && cx.opstack[cx.n_opstack-1].type != T_LPAREN)
                    cx.postfix[cx.n_postfix++] = cx.opstack[--cx.n_opstack];
                if (cx.n_opstack == 0) goto done;
                --cx.n_opstack; break;
            case T_CONCAT: case T_PIPE: {
                int p1 = prec(tok.type);
                while (cx.n_opstack > 0 && cx.opstack[cx.n_opstack-1].type != T_LPAREN
                       && prec(cx.opstack[cx.n_opstack-1].type) >= p1)
                    cx.postfix[cx.n_postfix++] = cx.opstack[--cx.n_opstack];
                cx.opstack[cx.n_opstack++] = tok; break;
            }
            default: break;
        }
    }
    while (cx.n_opstack > 0) {
        if (cx.opstack[cx.n_opstack-1].type == T_LPAREN) goto done;
        cx.postfix[cx.n_postfix++] = cx.opstack[--cx.n_opstack];
    }

    if (cx.n_postfix == 0) {
        n->start = nfa_add_state(n, OP_MATCH, -1, -1);
        rc = (n->start >= 0);
        goto done;
    }

    // Phase 4: lower postfix to NFA fragments
    for (int ti = 0; ti < cx.n_postfix; ++ti) {
        tok_t tok = cx.postfix[ti];
        int ok = 1;
        switch (tok.type) {
            case T_LITERAL: {
                frag_t f = make_codepoint_frag(n, tok.cp, &ok);
                if (!ok || f.start < 0) goto done;
                cx.fstack[cx.n_fstack++] = f; break;
            }
            case T_DOT: {
                frag_t f = make_dot_frag(n, &ok);
                if (!ok || f.start < 0) goto done;
                cx.fstack[cx.n_fstack++] = f; break;
            }
            case T_CLASS: {
                const cprange *cr = &cx.range_pool[cx.cls[tok.class_idx].off];
                int crn = cx.cls[tok.class_idx].cnt;
                frag_t f; f.start = -1; f.n_outs = 0;
                if (tok.negated) {
                    int all_ascii = 1;
                    for (int i = 0; i < crn; ++i) if (cr[i].hi >= 0x80) { all_ascii = 0; break; }
                    if (all_ascii) {
                        int ci = nfa_new_class(n);
                        if (ci < 0) goto done;
                        for (int i = 0; i < crn; ++i)
                            for (uint32_t c = cr[i].lo; c <= cr[i].hi; ++c) cc_set(&n->classes[ci], (uint8_t)c);
                        int s = nfa_add_class(n, (uint8_t)ci, 1, -1);
                        if (s < 0) goto done;
                        f.start = s; f.outs[0] = (patch_t){ (int16_t)s, 0 }; f.n_outs = 1;
                    } else {
                        cprange comp[256];
                        int cn = complement_ranges(cr, crn, 0x7FF, comp);
                        if (cn < 0) goto done;
                        f = make_class_frag(n, comp, cn, &ok);
                    }
                } else {
                    f = make_class_frag(n, cr, crn, &ok);
                }
                if (!ok || f.start < 0) goto done;
                cx.fstack[cx.n_fstack++] = f; break;
            }
            case T_CONCAT: {
                if (cx.n_fstack < 2) goto done;
                frag_t f2 = cx.fstack[--cx.n_fstack];
                frag_t f1 = cx.fstack[--cx.n_fstack];
                frag_patch(n, f1.outs, f1.n_outs, f2.start);
                f1.start = f1.start; memcpy(f1.outs, f2.outs, sizeof(patch_t) * (size_t)f2.n_outs);
                f1.n_outs = f2.n_outs;
                cx.fstack[cx.n_fstack++] = f1; break;
            }
            case T_PIPE: {
                if (cx.n_fstack < 2) goto done;
                frag_t f2 = cx.fstack[--cx.n_fstack];
                frag_t f1 = cx.fstack[--cx.n_fstack];
                int sp = nfa_add_state(n, OP_SPLIT, (int16_t)f1.start, (int16_t)f2.start);
                if (sp < 0) goto done;
                patch_t outs[MAX_OUTS]; int no = 0;
                if (!outs_append(outs, &no, f1.outs, f1.n_outs) ||
                    !outs_append(outs, &no, f2.outs, f2.n_outs)) goto done;
                frag_t r; r.start = sp; memcpy(r.outs, outs, sizeof(patch_t) * (size_t)no); r.n_outs = no;
                cx.fstack[cx.n_fstack++] = r; break;
            }
            case T_STAR: {
                if (cx.n_fstack < 1) goto done;
                frag_t f = cx.fstack[--cx.n_fstack];
                int sp = nfa_add_state(n, OP_SPLIT, (int16_t)f.start, -1);
                if (sp < 0) goto done;
                frag_patch(n, f.outs, f.n_outs, sp);
                frag_t r; r.start = sp; r.outs[0] = (patch_t){ (int16_t)sp, 1 }; r.n_outs = 1;
                cx.fstack[cx.n_fstack++] = r; break;
            }
            case T_PLUS: {
                if (cx.n_fstack < 1) goto done;
                frag_t f = cx.fstack[--cx.n_fstack];
                int sp = nfa_add_state(n, OP_SPLIT, (int16_t)f.start, -1);
                if (sp < 0) goto done;
                frag_patch(n, f.outs, f.n_outs, sp);
                frag_t r; r.start = f.start; r.outs[0] = (patch_t){ (int16_t)sp, 1 }; r.n_outs = 1;
                cx.fstack[cx.n_fstack++] = r; break;
            }
            case T_QUES: {
                if (cx.n_fstack < 1) goto done;
                frag_t f = cx.fstack[--cx.n_fstack];
                int sp = nfa_add_state(n, OP_SPLIT, (int16_t)f.start, -1);
                if (sp < 0) goto done;
                patch_t outs[MAX_OUTS]; int no = 0;
                if (!outs_append(outs, &no, f.outs, f.n_outs)) goto done;
                if (no >= MAX_OUTS) goto done;
                outs[no++] = (patch_t){ (int16_t)sp, 1 };
                frag_t r; r.start = sp; memcpy(r.outs, outs, sizeof(patch_t) * (size_t)no); r.n_outs = no;
                cx.fstack[cx.n_fstack++] = r; break;
            }
            default: break;
        }
    }

    if (cx.n_fstack != 1) goto done;

    int match = nfa_add_state(n, OP_MATCH, -1, -1);
    if (match < 0) goto done;
    frag_patch(n, cx.fstack[0].outs, cx.fstack[0].n_outs, match);
    n->start = cx.fstack[0].start;
    rc = 1;

done:
    free(cx.tokens); free(cx.range_pool); free(cx.cls);
    free(cx.withcc); free(cx.postfix); free(cx.opstack); free(cx.fstack);
    return rc;
}

// ── Simulation ──────────────────────────────────────────────────────────
static void eps_closure(const sublimation_nfa *n, uint64_t *set, int s) {
    if (s < 0 || s >= n->num_states) return;
    if (test_bit(set, s)) return;
    set_bit(set, s);
    if (n->states[s].op == OP_SPLIT) {
        eps_closure(n, set, n->states[s].out);
        eps_closure(n, set, n->states[s].out1);
    }
}

static void nfa_step(const sublimation_nfa *n, const uint64_t *cur, uint64_t *next, uint8_t byte) {
    clear_set(next);
    for (int i = 0; i < n->num_states; ++i) {
        if (!test_bit(cur, i)) continue;
        const sublimation_nfa_state *st = &n->states[i];
        int matched = 0;
        if (st->op == OP_CHAR)       matched = (byte == st->ch);
        else if (st->op == OP_CLASS) matched = st->negated ? !cc_test(&n->classes[st->class_idx], byte)
                                                           :  cc_test(&n->classes[st->class_idx], byte);
        if (matched && st->out >= 0) eps_closure(n, next, st->out);
    }
}

static int nfa_has_match(const sublimation_nfa *n, const uint64_t *set) {
    for (int i = 0; i < n->num_states; ++i)
        if (test_bit(set, i) && n->states[i].op == OP_MATCH) return 1;
    return 0;
}

// ── Public API ────────────────────────────────────────────────────────────
void sublimation_nfa_compile(sublimation_nfa *out, const char *pattern, size_t len) {
    out->valid = nfa_compile(out, pattern, len);
}

int sublimation_nfa_valid(const sublimation_nfa *nfa) { return nfa->valid; }

int sublimation_nfa_full_match(const sublimation_nfa *nfa, const char *input, size_t n) {
    if (!nfa->valid) return 0;
    uint64_t cur[SETWORDS], next[SETWORDS];
    clear_set(cur);
    eps_closure(nfa, cur, nfa->start);
    for (size_t i = 0; i < n; ++i) {
        nfa_step(nfa, cur, next, (uint8_t)input[i]);
        if (empty_set(next)) return 0;
        memcpy(cur, next, sizeof(cur));
    }
    return nfa_has_match(nfa, cur);
}

long sublimation_nfa_find(const sublimation_nfa *nfa, const char *input, size_t n, long *end_out) {
    if (!nfa->valid) return -1;
    int best_start = -1, best_end = -1;
    int start_limit = nfa->anchored_start ? 1 : (int)n + 1;

    for (int start = 0; start < start_limit; ++start) {
        uint64_t cur[SETWORDS], next[SETWORDS];
        clear_set(cur);
        eps_closure(nfa, cur, nfa->start);

        if (nfa_has_match(nfa, cur)) {
            if (!nfa->anchored_end || start == (int)n) {
                if (best_start < 0) { best_start = start; best_end = start; }
            }
        }

        for (int i = start; i < (int)n; ++i) {
            nfa_step(nfa, cur, next, (uint8_t)input[i]);
            if (empty_set(next)) break;
            memcpy(cur, next, sizeof(cur));
            if (nfa_has_match(nfa, cur)) {
                if (!nfa->anchored_end || i + 1 == (int)n) {
                    if (best_start < 0 || start < best_start
                        || (start == best_start && i + 1 > best_end)) {
                        best_start = start; best_end = i + 1;
                    }
                }
            }
        }

        if (best_start == start) { if (end_out) *end_out = best_end; return best_start; }
    }

    if (best_start >= 0 && end_out) *end_out = best_end;
    return best_start;
}
