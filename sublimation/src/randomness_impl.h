// randomness_impl.h -- Template body for the orthogonal-basis lenses that the
// randomness battery computes directly from the values (the others are read off
// sublimation_classify). Included once per type; requires SUB_TYPE / SUB_SUFFIX.
//
// Two lenses live here because they need value comparisons over the raw series,
// not the permutation profile classify produces:
//   - HVG mean degree (horizontal visibility graph, Luque-Lacasa): IID random
//     drives the mean degree to 4; periodic series stay near 2.
//   - Bandt-Pompe d=3 permutation entropy: normalized Shannon entropy of the
//     ordinal-pattern distribution; uniform (all 6 patterns equiprobable) -> 1.
// Two samplers also live here: they read the raw values and hand the RQA and
// spectral lenses (randomness.c) a type-erased double sample.

#include <stdlib.h>
#include <math.h>

// Horizontal-visibility-graph mean degree, O(n) via a monotonic stack.
// Bars i<j are visible iff every bar strictly between them is lower than both;
// each visibility edge has a unique right endpoint, counted once as that bar is
// processed (one edge per popped lower bar, plus one to the blocking bar).
// Mean degree = 2 * edges / n.
static double SUB_TYPED(sub_hvg_mean_degree)(const SUB_TYPE *arr, size_t n) {
    if (n < 2) return 0.0;
    SUB_TYPE *stack = (SUB_TYPE *)malloc(n * sizeof(SUB_TYPE));
    if (!stack) return 0.0;
    size_t top = 0;
    uint64_t edges = 0;
    for (size_t i = 0; i < n; i++) {
        SUB_TYPE x = arr[i];
        while (top > 0 && stack[top - 1] < x) { top--; edges++; }
        if (top > 0) {
            edges++;                                  // x sees the blocking bar
            if (stack[top - 1] == x) top--;           // equal height blocks further
        }
        stack[top++] = x;
    }
    free(stack);
    return 2.0 * (double)edges / (double)n;
}

// Bandt-Pompe d=3 permutation entropy, normalized to [0,1]. Slides a length-3
// window, maps each window to one of 6 ordinal patterns via three comparisons,
// histograms, and returns Shannon entropy / log2(6). Monotone -> 0; uniform
// ordinal distribution -> 1. The two transitively-impossible comparison codes
// (1,1,0)/(0,0,1) only arise from ties and fold harmlessly into pattern 0.
static double SUB_TYPED(sub_bandt_pompe_h)(const SUB_TYPE *arr, size_t n) {
    if (n < 3) return 0.0;
    // index = ab*4 + bc*2 + ac, with ab=(a<b), bc=(b<c), ac=(a<c).
    static const int pat[8] = { 5, 0, 4, 3, 2, 1, 0, 0 };
    uint64_t hist[6] = { 0 };
    uint64_t total = 0;
    for (size_t i = 0; i + 2 < n; i++) {
        SUB_TYPE a = arr[i], b = arr[i + 1], c = arr[i + 2];
        int ab = (a < b) ? 1 : 0;
        int bc = (b < c) ? 1 : 0;
        int ac = (a < c) ? 1 : 0;
        hist[pat[(ab << 2) | (bc << 1) | ac]]++;
        total++;
    }
    if (total == 0) return 0.0;
    double h = 0.0;
    for (int k = 0; k < 6; k++) {
        if (hist[k]) {
            double p = (double)hist[k] / (double)total;
            h -= p * log2(p);
        }
    }
    return h / log2(6.0);
}

// Contiguous leading window as doubles, for the RQA lens. RQA measures
// TEMPORAL determinism (diagonal recurrence lines need consecutive sample
// points to be consecutive in time); an evenly-strided subsample composes any
// underlying map stride-fold, whose derivative grows geometrically, and erases
// the diagonal structure it exists to detect (verified: logistic-map DET falls
// from 0.69 contiguous to the IID baseline at stride 7). Returns the sample
// size min(n, cap).
static size_t SUB_TYPED(sub_rand_window_f64)(const SUB_TYPE *arr, size_t n,
                                             double *out, size_t cap) {
    size_t m = n < cap ? n : cap;
    for (size_t i = 0; i < m; i++) out[i] = (double)arr[i];
    return m;
}

// Evenly-strided sample as doubles, for the spectral lens. Spectral flatness
// reads the VALUE distribution, so the sample follows classify's
// estimate_distinct stride convention (stride = n / m, take arr[i * stride])
// and covers the whole array. Returns the sample size min(n, cap).
static size_t SUB_TYPED(sub_rand_stride_f64)(const SUB_TYPE *arr, size_t n,
                                             double *out, size_t cap) {
    size_t m = n < cap ? n : cap;
    size_t stride = n / m;
    if (stride < 1) stride = 1;
    for (size_t i = 0; i < m; i++) out[i] = (double)arr[i * stride];
    return m;
}
