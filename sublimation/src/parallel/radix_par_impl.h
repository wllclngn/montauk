// radix_par_impl.h -- templated parallel MSD radix (in-place American Flag) on
// the work-stealing engine. Included per type by radix_par.c with SUB_TYPE,
// SUB_SUFFIX, SUB_ORDER_KEY(v) (value -> monotonic unsigned key) and
// SUB_TOPBYTE (highest byte index) defined. No include guard.
//
// Each frame is one byte-bucket subrange at a byte level. Processing a frame
// partitions it in place by that byte into 256 sub-buckets (American Flag: a
// cycle-following permutation, no scratch), then pushes the large sub-buckets
// as frames for the next byte and finishes small ones serially. The original
// values move; the ordering byte is read through SUB_ORDER_KEY so signed and
// float keys need no separate transform pass. Not stable -- fine for a value
// sort, where equal keys are identical values.

#define SUB_PAR_MIN 4096u    // sub-buckets >= this are pushed as parallel frames
#define SUB_PAR_INS 32u      // <= this: insertion sort

static inline void SUB_TYPED(rp_ins)(SUB_TYPE *a, size_t n) {
    for (size_t i = 1; i < n; i++) {
        SUB_TYPE k = a[i]; size_t j = i;
        while (j > 0 && a[j-1] > k) { a[j] = a[j-1]; j--; }
        a[j] = k;
    }
}

// One in-place American Flag pass by the ordering byte at `level`. Fills
// start[]/cnt[] (bucket bases and sizes) and permutes a[] in place.
static void SUB_TYPED(rp_pass)(SUB_TYPE *a, size_t n, int level,
                               size_t start[256], size_t cnt[256]) {
    int sh = level * 8;
    for (int b = 0; b < 256; b++) cnt[b] = 0;
    for (size_t i = 0; i < n; i++) cnt[(SUB_ORDER_KEY(a[i]) >> sh) & 0xff]++;
    size_t acc = 0, next[256], end[256];
    for (int b = 0; b < 256; b++) { start[b] = acc; next[b] = acc; acc += cnt[b]; end[b] = acc; }
    for (int b = 0; b < 256; b++) {
        while (next[b] < end[b]) {
            SUB_TYPE v = a[next[b]];
            uint8_t d = (uint8_t)((SUB_ORDER_KEY(v) >> sh) & 0xff);
            while (d != b) {
                SUB_TYPE t = a[next[d]];
                a[next[d]] = v; next[d]++;
                v = t; d = (uint8_t)((SUB_ORDER_KEY(v) >> sh) & 0xff);
            }
            a[next[b]] = v; next[b]++;
        }
    }
}

// Serial recursive American Flag for a sub-bucket (no more frames).
static void SUB_TYPED(rp_serial)(SUB_TYPE *a, size_t n, int level) {
    while (n > SUB_PAR_INS && level >= 0) {
        size_t start[256], cnt[256];
        SUB_TYPED(rp_pass)(a, n, level, start, cnt);
        if (level == 0) return;                 // last byte placed: sorted
        // Recurse into every non-trivial sub-bucket; tail-loop the largest is
        // not worth the bookkeeping here (buckets shrink ~256x per byte).
        int last = -1;
        for (int b = 0; b < 256; b++) {
            if (cnt[b] <= 1) continue;
            if (last < 0) { last = b; continue; }
            SUB_TYPED(rp_serial)(a + start[last], cnt[last], level - 1);
            last = b;
        }
        if (last < 0) return;
        a += start[last]; n = cnt[last]; level--;  // loop on the final bucket
    }
    if (n > 1) SUB_TYPED(rp_ins)(a, n);
}

// Parallel frame processor: partition by byte[level], push big sub-buckets,
// finish small ones serially in place.
static void SUB_TYPED(rp_frame)(sub_dfs_frame_t f, sub_dfs_ctx_t *ctx, void *user) {
    (void)user;
    SUB_TYPE *a = (SUB_TYPE *)f.base;
    size_t n = f.n;
    int level = (int)f.depth;
    if (n <= SUB_PAR_INS) { SUB_TYPED(rp_ins)(a, n); return; }
    if (level < 0) return;
    size_t start[256], cnt[256];
    SUB_TYPED(rp_pass)(a, n, level, start, cnt);
    if (level == 0) return;
    // Always fan the top byte out to its (up to 256) buckets -- that is the
    // coarsest parallelism and must not depend on n. Deeper levels push only
    // buckets large enough to amortize a frame; smaller ones finish serially.
    bool top = (level == SUB_TOPBYTE);
    for (int b = 0; b < 256; b++) {
        if (cnt[b] <= 1) continue;
        if (cnt[b] >= SUB_PAR_MIN || (top && cnt[b] > SUB_PAR_INS))
            sub_dfs_push(ctx, (sub_dfs_frame_t){ .base = a + start[b], .n = cnt[b],
                                                 .depth = (uint32_t)(level - 1) });
        else
            SUB_TYPED(rp_serial)(a + start[b], cnt[b], level - 1);
    }
}

void SUB_TYPED(sub_radix_sort_par)(SUB_TYPE *arr, size_t n, size_t workers) {
    if (n < 2) return;
#ifdef SUB_TYPE_IS_FLOAT
    size_t keep = 0;                             // park NaNs at the tail
    for (size_t r = 0; r < n; r++)
        if (arr[r] == arr[r]) { if (keep != r) { SUB_TYPE t = arr[keep]; arr[keep] = arr[r]; arr[r] = t; } keep++; }
    n = keep;
    if (n < 2) return;
#endif
    if (workers < 2 || n < SUB_PAR_MIN) { SUB_TYPED(rp_serial)(arr, n, SUB_TOPBYTE); return; }
    sub_dfs_frame_t root = { .base = arr, .n = n, .depth = (uint32_t)SUB_TOPBYTE };
    if (!sub_dfs_run(workers, root, SUB_TYPED(rp_frame), nullptr))
        SUB_TYPED(rp_serial)(arr, n, SUB_TOPBYTE);   // engine OOM: serial radix
}

#undef SUB_PAR_MIN
#undef SUB_PAR_INS
