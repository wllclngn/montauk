// kmerge_strings.c -- k-way merge of already-sorted string runs.
//
// The string half of the merge family. Same contract as the numeric entries in
// sublimation.h: merging k already-sorted runs is byte-identical to sorting the
// concatenation, and the merge is stable by run index so equal keys leave in
// run order.
//
// TWO ENGINES HERE, NOT ONE, and the reason is the output type rather than a
// second convention: the value face merges `const char *` and emits pointers,
// while the index face emits uint32_t positions into a caller-owned array. A
// shared core would need a key accessor per element on every comparison to
// serve both, which buys nothing when the ordering rule -- strcmp, ties to the
// lower run index -- is written once and used by both.
//
// The index face is deliberately NOT streamed. An index only means something
// against an array the caller already holds, so there is nothing to pull.

#include "sublimation_strings.h"
#include <stdlib.h>
#include <string.h>

#ifndef SUB_KMERGE_BUF
#define SUB_KMERGE_BUF 512
#endif

#define SUB_MERGE_ENOMEM (-1)

// ORDERING RULE, written once. Returns 1 if (sa, run a) sorts before (sb, b).
static int str_before(const char *sa, size_t a, const char *sb, size_t b) {
    int c = strcmp(sa, sb);
    if (c != 0) return c < 0;
    return a < b;
}

// VALUE FACE

typedef struct {
    const char **buf;
    size_t len, pos;
    int done;
} scur_t;

static int scur_fill(scur_t *c, size_t run, sublimation_merge_pull_strings pull, void *ctx) {
    if (c->pos < c->len) return 1;
    if (c->done) return 0;
    c->len = pull(ctx, run, c->buf, SUB_KMERGE_BUF);
    c->pos = 0;
    if (c->len == 0) { c->done = 1; return 0; }
    return 1;
}

// Tree of losers, same structure and reasoning as the numeric core in
// kmerge_impl.h: one comparison per level rather than a heap's two, with an
// explicit rank byte (-1 sentinel, 0 live, 1 exhausted) instead of a magic key,
// since there is no "impossible" string to reserve.
#define SKM_LOSES(a, b)                                                        \
    (rank[a] != rank[b] ? rank[a] > rank[b]                                    \
     : rank[a] != 0 ? (a) > (b)   /* both exhausted or both sentinel: key is  \
                                     NULL, so never reach strcmp */           \
     : !str_before(key[a], (a), key[b], (b)))
#define SKM_ADJUST(s0)                                                         \
    do {                                                                       \
        size_t s_ = (s0);                                                      \
        for (size_t t_ = (s_ + k) / 2; t_ > 0; t_ /= 2) {                      \
            if (SKM_LOSES(s_, ls[t_])) {                                       \
                size_t tmp_ = s_; s_ = ls[t_]; ls[t_] = tmp_;                  \
            }                                                                  \
        }                                                                      \
        ls[0] = s_;                                                            \
    } while (0)

int sublimation_merge_stream_strings(size_t k, sublimation_merge_pull_strings pull,
                                     void *pull_ctx,
                                     sublimation_merge_emit_strings emit,
                                     void *emit_ctx) {
    if (k == 0 || pull == NULL || emit == NULL) return 0;

    scur_t       *cur  = (scur_t *)calloc(k, sizeof(*cur));
    const char  **slab = (const char **)malloc(k * SUB_KMERGE_BUF * sizeof(char *));
    size_t       *ls   = (size_t *)malloc(k * sizeof(size_t));
    const char  **key  = (const char **)malloc((k + 1) * sizeof(char *));
    signed char  *rank = (signed char *)malloc(k + 1);
    const char  **out  = (const char **)malloc(SUB_KMERGE_BUF * sizeof(char *));
    if (cur == NULL || slab == NULL || ls == NULL || key == NULL ||
        rank == NULL || out == NULL) {
        free(cur); free(slab); free(ls); free(key); free(rank); free(out);
        return SUB_MERGE_ENOMEM;
    }

    const size_t senti = k;
    key[senti] = NULL;
    rank[senti] = -1;
    for (size_t i = 0; i < k; i++) {
        cur[i].buf = slab + i * SUB_KMERGE_BUF;
        if (scur_fill(&cur[i], i, pull, pull_ctx)) {
            key[i] = cur[i].buf[cur[i].pos];
            rank[i] = 0;
        } else {
            key[i] = NULL;
            rank[i] = 1;
        }
        ls[i] = senti;
    }
    for (size_t i = k; i-- > 0;) SKM_ADJUST(i);

    int rc = 0;
    size_t n_out = 0;
    for (;;) {
        size_t run = ls[0];
        if (run == senti || rank[run] != 0) break;

        out[n_out++] = cur[run].buf[cur[run].pos++];
        if (n_out == SUB_KMERGE_BUF) {
            if ((rc = emit(emit_ctx, out, n_out)) != 0) goto done;
            n_out = 0;
        }
        if (scur_fill(&cur[run], run, pull, pull_ctx)) {
            key[run] = cur[run].buf[cur[run].pos];
        } else {
            rank[run] = 1;
        }
        SKM_ADJUST(run);
    }
    if (n_out > 0) rc = emit(emit_ctx, out, n_out);

done:
    free(cur); free(slab); free(ls); free(key); free(rank); free(out);
    return rc;
}

#undef SKM_LOSES
#undef SKM_ADJUST

typedef struct {
    const char *const *const *runs;
    const size_t *lens;
    size_t *taken;
} sspan_t;

static size_t sspan_pull(void *ctx, size_t run, const char **buf, size_t cap) {
    sspan_t *s = (sspan_t *)ctx;
    size_t left = s->lens[run] - s->taken[run];
    size_t take = left < cap ? left : cap;
    if (take > 0) {
        memcpy(buf, s->runs[run] + s->taken[run], take * sizeof(char *));
        s->taken[run] += take;
    }
    return take;
}

typedef struct { const char **out; size_t n; } ssink_t;

static int sspan_emit(void *ctx, const char *const *buf, size_t n) {
    ssink_t *s = (ssink_t *)ctx;
    memcpy(s->out + s->n, buf, n * sizeof(char *));
    s->n += n;
    return 0;
}

int sublimation_merge_strings(const char *const *const *runs, const size_t *lens,
                              size_t k, const char **out) {
    if (k == 0) return 0;
    size_t *taken = (size_t *)calloc(k, sizeof(size_t));
    if (taken == NULL) return SUB_MERGE_ENOMEM;
    sspan_t src = { runs, lens, taken };
    ssink_t dst = { out, 0 };
    int rc = sublimation_merge_stream_strings(k, sspan_pull, &src, sspan_emit, &dst);
    free(taken);
    return rc;
}

// INDEX FACE
//
// For callers holding rows rather than keys: `arr` is the caller's string
// array, each run is an already-ordered list of indices into it, and the result
// is one ordered index permutation.

int sublimation_merge_strings_indices(const char **arr,
                                      const uint32_t *const *runs,
                                      const size_t *lens, size_t k,
                                      uint32_t *out) {
    if (k == 0) return 0;
    size_t      *pos  = (size_t *)calloc(k, sizeof(size_t));
    size_t      *ls   = (size_t *)malloc(k * sizeof(size_t));
    const char **key  = (const char **)malloc((k + 1) * sizeof(char *));
    signed char *rank = (signed char *)malloc(k + 1);
    if (pos == NULL || ls == NULL || key == NULL || rank == NULL) {
        free(pos); free(ls); free(key); free(rank);
        return SUB_MERGE_ENOMEM;
    }

    const size_t senti = k;
    key[senti] = NULL;
    rank[senti] = -1;
    for (size_t i = 0; i < k; i++) {
        if (lens[i] > 0) { key[i] = arr[runs[i][0]]; rank[i] = 0; }
        else             { key[i] = NULL;            rank[i] = 1; }
        ls[i] = senti;
    }

#define SKI_LOSES(a, b)                                                        \
    (rank[a] != rank[b] ? rank[a] > rank[b]                                    \
     : rank[a] != 0 ? (a) > (b)   /* both exhausted or both sentinel: key is  \
                                     NULL, so never reach strcmp */           \
     : !str_before(key[a], (a), key[b], (b)))
#define SKI_ADJUST(s0)                                                         \
    do {                                                                       \
        size_t s_ = (s0);                                                      \
        for (size_t t_ = (s_ + k) / 2; t_ > 0; t_ /= 2) {                      \
            if (SKI_LOSES(s_, ls[t_])) {                                       \
                size_t tmp_ = s_; s_ = ls[t_]; ls[t_] = tmp_;                  \
            }                                                                  \
        }                                                                      \
        ls[0] = s_;                                                            \
    } while (0)

    for (size_t i = k; i-- > 0;) SKI_ADJUST(i);

    size_t n_out = 0;
    for (;;) {
        size_t run = ls[0];
        if (run == senti || rank[run] != 0) break;
        out[n_out++] = runs[run][pos[run]++];
        if (pos[run] < lens[run]) key[run] = arr[runs[run][pos[run]]];
        else                      rank[run] = 1;
        SKI_ADJUST(run);
    }
#undef SKI_LOSES
#undef SKI_ADJUST

    free(pos); free(ls); free(key); free(rank);
    return 0;
}
