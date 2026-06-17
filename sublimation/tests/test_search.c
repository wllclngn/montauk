// test_search.c -- the structural locator: find WHERE a disorder pattern lives
// in a stream. We build a stream that is mostly random noise with three known
// structural regions embedded -- a sorted run, a reversed run, and a few-unique
// block -- and show that sublimation_locate finds exactly those window positions
// and nothing else. This is grep for structure: the window is the line, the
// disorder class is the pattern.
#include "../src/include/sublimation_search.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

static int _pass = 0, _fail = 0;
static void check(int ok, const char *what) {
    if (ok) { printf("  [PASS] %s\n", what); _pass++; }
    else    { printf("  [FAIL] %s\n", what); _fail++; }
}

static uint64_t lcg;
static uint64_t rnd(void) { lcg = lcg * 6364136223846793005ull + 1442695040888963407ull; return lcg; }

// Region layout, all 1024-wide (two 512-windows each):
//   [0,1024)    RANDOM
//   [1024,2048) SORTED      (ascending distinct)
//   [2048,3072) RANDOM
//   [3072,4096) REVERSED    (descending distinct)
//   [4096,5120) FEW_UNIQUE  (values mod 4)
//   [5120,6144) RANDOM
#define N 6144u
#define W 512u

// Does every window-start in `got` fall inside [lo,hi)?
static int all_within(const sub_match_t *got, size_t k, size_t lo, size_t hi) {
    for (size_t i = 0; i < k; i++)
        if (got[i].start < lo || got[i].start + got[i].len > hi) return 0;
    return 1;
}
// Are the window-starts in `got` exactly {expected[0..ne)} in order?
static int exact_starts(const sub_match_t *got, size_t k, const size_t *expected, size_t ne) {
    if (k != ne) return 0;
    for (size_t i = 0; i < ne; i++) if (got[i].start != expected[i]) return 0;
    return 1;
}

int main(void) {
    lcg = 0xC0DEFEEDull;
    uint64_t *a = (uint64_t *)malloc(N * sizeof(uint64_t));
    for (size_t i = 0; i < N; i++) {
        if      (i >= 1024 && i < 2048) a[i] = (uint64_t)(i - 1024) * 1000ull + 1; // SORTED
        else if (i >= 3072 && i < 4096) a[i] = (uint64_t)(4096 - i) * 1000ull + 1; // REVERSED
        else if (i >= 4096 && i < 5120) a[i] = rnd() % 4u;                          // FEW_UNIQUE
        else                            a[i] = rnd();                               // RANDOM
    }

    // 1. The raw scan: the disorder strip over position (window=512, stride=512).
    sub_match_t prof[64];
    size_t np = sublimation_profile_u64(a, N, W, W, prof, 64);
    printf("structural map (window=%u, stride=%u, %zu windows):\n", W, W, np);
    for (size_t i = 0; i < np; i++)
        printf("  [%5zu,%5zu)  %-13s  inv=%.2f distinct~%zu\n",
               prof[i].start, prof[i].start + prof[i].len,
               sublimation_disorder_name(prof[i].disorder),
               (double)prof[i].inversion_ratio, prof[i].distinct_estimate);
    printf("\n");

    // 2. The grep-analog: locate each target class.
    sub_match_t hit[64];
    size_t exp_sorted[]   = {1024, 1536};
    size_t exp_reversed[] = {3072, 3584};
    size_t exp_few[]      = {4096, 4608};

    size_t ks = sublimation_locate_u64(a, N, W, W, SUB_SORTED, hit, 64);
    printf("locate SORTED -> %zu windows:", ks);
    for (size_t i = 0; i < ks; i++) printf(" [%zu,%zu)", hit[i].start, hit[i].start + hit[i].len);
    printf("\n");
    check(exact_starts(hit, ks, exp_sorted, 2), "SORTED located at exactly the embedded run");
    check(all_within(hit, ks, 1024, 2048), "no SORTED match outside the sorted region");

    size_t kr = sublimation_locate_u64(a, N, W, W, SUB_REVERSED, hit, 64);
    printf("locate REVERSED -> %zu windows:", kr);
    for (size_t i = 0; i < kr; i++) printf(" [%zu,%zu)", hit[i].start, hit[i].start + hit[i].len);
    printf("\n");
    check(exact_starts(hit, kr, exp_reversed, 2), "REVERSED located at exactly the embedded run");

    size_t kf = sublimation_locate_u64(a, N, W, W, SUB_FEW_UNIQUE, hit, 64);
    printf("locate FEW_UNIQUE -> %zu windows:", kf);
    for (size_t i = 0; i < kf; i++) printf(" [%zu,%zu)", hit[i].start, hit[i].start + hit[i].len);
    printf("\n");
    check(exact_starts(hit, kf, exp_few, 2), "FEW_UNIQUE located at exactly the embedded block");

    size_t kR = sublimation_locate_u64(a, N, W, W, SUB_RANDOM, hit, 64);
    printf("locate RANDOM -> %zu windows (the noise between the structure)\n", kR);
    check(kR == 6 && all_within(hit, 2, 0, 1024), "RANDOM covers the noise, not the structure");

    // 3. Finer resolution: a tight stride localizes the sorted run's edges.
    size_t kfine = sublimation_locate_u64(a, N, 256, 128, SUB_SORTED, hit, 64);
    int edges_ok = kfine > 0 && all_within(hit, kfine, 1024, 2048);
    printf("\nfine scan (window=256, stride=128) SORTED -> %zu windows, first [%zu..), last [..%zu)\n",
           kfine, kfine ? hit[0].start : 0, kfine ? hit[kfine-1].start + hit[kfine-1].len : 0);
    check(edges_ok, "fine scan localizes the sorted run, every hit inside [1024,2048)");

    free(a);
    printf("\n  %d passed, %d failed\n", _pass, _fail);
    return _fail ? 1 : 0;
}
