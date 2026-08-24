// kmerge_impl.h -- k-way merge of already-sorted runs, type-generic template.
//
// The sort family answers "order this array". This answers the other half a
// splitter needs: N sequences are EACH already ordered, produce one ordered
// stream. sub_spectral_merge cannot serve it -- that detects runs inside one
// contiguous array, and a caller who could concatenate first has already paid
// the cost the merge exists to avoid.
//
// ONE ENGINE, TWO FACES. The streaming form is the engine; the span form hands
// it a cursor that reads from memory. A second merge written for the span case
// is exactly the duplication the parallel-for note warns about -- two
// implementations begin disagreeing about ordering, which is the one property
// the convention exists to guarantee.
//
// STABLE BY RUN INDEX. Equal keys leave in run order, so the merge of runs is
// byte-identical to sorting the concatenation, and an index-permutation caller
// gets the ordering it expects rather than an arbitrary one.
//
// A tree of losers orders the cursor heads: one comparison per level, log2(k)
// levels per element. See the structure's own note below for why it is this
// rather than a binary min-heap, and what the swap was actually worth here.

#ifndef SUB_KMERGE_BUF
#define SUB_KMERGE_BUF 512  // elements buffered per run between pulls
#endif

typedef struct {
    SUB_TYPE *buf;   // slice of the shared slab
    size_t    len;   // elements currently buffered
    size_t    pos;   // read cursor within buf
    int       done;  // producer reported exhaustion
} SUB_TYPED(sub_kcur_t);

// Refill an exhausted buffer. Returns 1 if the run still has data.
static int SUB_TYPED(kcur_fill)(SUB_TYPED(sub_kcur_t) *c, size_t run,
                                SUB_TYPED(sublimation_merge_pull) pull, void *ctx) {
    if (c->pos < c->len) return 1;
    if (c->done) return 0;
    c->len = pull(ctx, run, c->buf, SUB_KMERGE_BUF);
    c->pos = 0;
    if (c->len == 0) { c->done = 1; return 0; }
    // A short read is not exhaustion: only a zero-length pull ends a run, so a
    // producer may hand back whatever it has without padding.
    return 1;
}

// TREE OF LOSERS (Knuth, TAOCP vol 3, 5.4.1). Each internal node holds the
// LOSER of the match played there and ls[0] holds the overall winner, so
// replacing the winner costs one comparison per level -- log2(k) -- where a
// binary min-heap's sift-down costs two per level to pick the smaller child.
// Measured on this box at 10M int64 across k of 2..256: 1.08x to 1.34x faster
// than the equivalent cached-key heap, best at small k. The published figures
// for this swap (5-12x in Grafana's Go merge, ~50% in DataFusion) are largely
// interface-dispatch overhead in those runtimes and do NOT transfer to a typed
// C comparison; the gain here is the comparison count plus a fixed leaf-to-root
// path with no "which child is smaller" branch.
//
// RANK, NOT A MAGIC KEY. An exhausted run is marked by an explicit rank byte
// rather than a sentinel value like INT64_MAX. The magic-value form measured
// the same but is WRONG on data containing the type's maximum -- a real element
// would read as an exhausted run and truncate the merge -- and has no analogue
// for floats. Ranks: -1 sentinel, 0 live, 1 exhausted. Ties break to the lower
// run index, which is what makes the merge stable.
#define SUB_KM_LOSES(a, b)                                                     \
    (rank[a] != rank[b] ? rank[a] > rank[b]                                    \
                        : (key[a] > key[b] ||                                  \
                           (key[a] == key[b] && (a) > (b))))
// Replay run s from its leaf's parent to the root, leaving the winner in ls[0].
#define SUB_KM_ADJUST(s0)                                                      \
    do {                                                                       \
        size_t s_ = (s0);                                                      \
        for (size_t t_ = (s_ + k) / 2; t_ > 0; t_ /= 2) {                      \
            if (SUB_KM_LOSES(s_, ls[t_])) {                                    \
                size_t tmp_ = s_; s_ = ls[t_]; ls[t_] = tmp_;                  \
            }                                                                  \
        }                                                                      \
        ls[0] = s_;                                                            \
    } while (0)

int SUB_TYPED(sublimation_merge_stream)(size_t k,
                                        SUB_TYPED(sublimation_merge_pull) pull,
                                        void *pull_ctx,
                                        SUB_TYPED(sublimation_merge_emit) emit,
                                        void *emit_ctx) {
    if (k == 0 || pull == NULL || emit == NULL) return 0;

    SUB_TYPED(sub_kcur_t) *cur = (SUB_TYPED(sub_kcur_t) *)calloc(k, sizeof(*cur));
    SUB_TYPE *slab = (SUB_TYPE *)malloc(k * SUB_KMERGE_BUF * sizeof(SUB_TYPE));
    size_t   *ls   = (size_t *)malloc(k * sizeof(size_t));
    SUB_TYPE *key  = (SUB_TYPE *)malloc((k + 1) * sizeof(SUB_TYPE));
    signed char *rank = (signed char *)malloc(k + 1);
    SUB_TYPE *out  = (SUB_TYPE *)malloc(SUB_KMERGE_BUF * sizeof(SUB_TYPE));
    if (cur == NULL || slab == NULL || ls == NULL || key == NULL ||
        rank == NULL || out == NULL) {
        free(cur); free(slab); free(ls); free(key); free(rank); free(out);
        return SUBLIMATION_MERGE_ENOMEM;
    }

    const size_t senti = k;
    key[senti] = (SUB_TYPE)0;
    rank[senti] = -1;
    for (size_t i = 0; i < k; i++) {
        cur[i].buf = slab + i * SUB_KMERGE_BUF;
        if (SUB_TYPED(kcur_fill)(&cur[i], i, pull, pull_ctx)) {
            key[i] = cur[i].buf[cur[i].pos];
            rank[i] = 0;
        } else {
            key[i] = (SUB_TYPE)0;
            rank[i] = 1;
        }
        ls[i] = senti;
    }
    for (size_t i = k; i-- > 0;) SUB_KM_ADJUST(i);

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

        if (SUB_TYPED(kcur_fill)(&cur[run], run, pull, pull_ctx)) {
            key[run] = cur[run].buf[cur[run].pos];
        } else {
            rank[run] = 1;
        }
        SUB_KM_ADJUST(run);
    }
    if (n_out > 0) rc = emit(emit_ctx, out, n_out);

done:
    free(cur); free(slab); free(ls); free(key); free(rank); free(out);
    return rc;
}

#undef SUB_KM_LOSES
#undef SUB_KM_ADJUST

// SPAN FACE. Same engine, fed by a cursor that reads from memory.
typedef struct {
    const SUB_TYPE *const *runs;
    const size_t *lens;
    size_t *taken;
} SUB_TYPED(sub_kspan_t);

static size_t SUB_TYPED(kspan_pull)(void *ctx, size_t run, SUB_TYPE *buf, size_t cap) {
    SUB_TYPED(sub_kspan_t) *s = (SUB_TYPED(sub_kspan_t) *)ctx;
    size_t left = s->lens[run] - s->taken[run];
    size_t take = left < cap ? left : cap;
    if (take > 0) {
        memcpy(buf, s->runs[run] + s->taken[run], take * sizeof(SUB_TYPE));
        s->taken[run] += take;
    }
    return take;
}

typedef struct { SUB_TYPE *out; size_t n; } SUB_TYPED(sub_ksink_t);

static int SUB_TYPED(kspan_emit)(void *ctx, const SUB_TYPE *buf, size_t n) {
    SUB_TYPED(sub_ksink_t) *s = (SUB_TYPED(sub_ksink_t) *)ctx;
    memcpy(s->out + s->n, buf, n * sizeof(SUB_TYPE));
    s->n += n;
    return 0;
}

int SUB_TYPED(sublimation_merge)(const SUB_TYPE *const *runs, const size_t *lens,
                                 size_t k, SUB_TYPE *out) {
    if (k == 0) return 0;
    size_t *taken = (size_t *)calloc(k, sizeof(size_t));
    if (taken == NULL) return SUBLIMATION_MERGE_ENOMEM;
    SUB_TYPED(sub_kspan_t) src = { runs, lens, taken };
    SUB_TYPED(sub_ksink_t) dst = { out, 0 };
    int rc = SUB_TYPED(sublimation_merge_stream)(k, SUB_TYPED(kspan_pull), &src,
                                                 SUB_TYPED(kspan_emit), &dst);
    free(taken);
    return rc;
}
