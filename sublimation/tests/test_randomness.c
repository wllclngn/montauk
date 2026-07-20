// test_randomness.c -- the fused randomness battery on known distributions.
//
// The contract is ORDERING, not absolute values: uniform random must score far
// above every structured input (sorted, reversed, few-unique, periodic,
// chaotic), and the confidence must stay strictly below 1. Per-lens scores are
// printed so a miscalibrated projection is visible. The RQA lens carries the
// determinism contract: a chaotic map reads high-entropy on the counting and
// ordinal lenses but its continuity stacks recurrences into diagonal lines, so
// RQA alone must veto it. All inputs are seeded and deterministic; no clocks.
#include "../src/include/sublimation_randomness.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <math.h>

static int _pass = 0, _fail = 0;

static uint64_t lcg_state;
static void lcg_seed(uint64_t s) { lcg_state = s; }
static uint64_t lcg_next(void) {
    lcg_state = lcg_state * 6364136223846793005ull + 1442695040888963407ull;
    return lcg_state;
}

static const char *LENS_NAME[SUB_RANDOMNESS_LENSES] = {
    "hook", "lis", "inv", "distinct", "hvg", "bandt-pompe", "rqa", "spectral"
};

static const char *VERDICT_NAME[4] = {
    "structured", "mixed", "consistent", "max-entropy"
};

static void show(const char *name, size_t n, sub_randomness_t r) {
    printf("  %-14s n=%-6zu conf=%.3f  (k=%u/%u %s)  [", name, n,
           (double)r.confidence, r.agree_count, r.lens_count,
           VERDICT_NAME[r.verdict]);
    for (int i = 0; i < SUB_RANDOMNESS_LENSES; i++) {
        if (r.lens_available[i]) printf(" %s=%.2f", LENS_NAME[i], (double)r.lens[i]);
        else                     printf(" %s=--", LENS_NAME[i]);
    }
    printf(" ]\n");
}

static sub_randomness_t run(const char *name, const uint64_t *a, size_t n) {
    sub_randomness_t r = sublimation_randomness_u64(a, n);
    show(name, n, r);
    return r;
}

static sub_randomness_t run_f64(const char *name, const double *a, size_t n) {
    sub_randomness_t r = sublimation_randomness_f64(a, n);
    show(name, n, r);
    return r;
}

static void check(int ok, const char *what) {
    if (ok) { printf("  [PASS] %s\n", what); _pass++; }
    else    { printf("  [FAIL] %s\n", what); _fail++; }
}

int main(void) {
    const size_t N = 4000;          // inside the 256..10000 tableau window
    uint64_t *buf = (uint64_t *)malloc(N * sizeof(uint64_t));
    double   *fbuf = (double *)malloc(N * sizeof(double));

    // 1. uniform random
    lcg_seed(0xC0DEFEEDull);
    for (size_t i = 0; i < N; i++) buf[i] = lcg_next();
    sub_randomness_t rand_r = run("uniform_random", buf, N);

    // 2. sorted ascending
    for (size_t i = 0; i < N; i++) buf[i] = (uint64_t)i * 1000ull;
    sub_randomness_t sorted_r = run("sorted", buf, N);

    // 3. reversed
    for (size_t i = 0; i < N; i++) buf[i] = (uint64_t)(N - i) * 1000ull;
    sub_randomness_t rev_r = run("reversed", buf, N);

    // 4. few-unique (4 distinct values)
    lcg_seed(0x1234ull);
    for (size_t i = 0; i < N; i++) buf[i] = lcg_next() % 4u;
    sub_randomness_t few_r = run("few_unique", buf, N);

    // 5. periodic but all-distinct (sawtooth ramp): low BP/RQA, high distinct.
    for (size_t i = 0; i < N; i++) buf[i] = (uint64_t)(i % 100) * 1000000ull + i;
    sub_randomness_t per_r = run("periodic", buf, N);

    // 6. small repeating cycle (period 8): the spectral clustering veto.
    for (size_t i = 0; i < N; i++) buf[i] = (uint64_t)(i % 8);
    sub_randomness_t cyc_r = run("cycle8", buf, N);

    // 7. deterministic chaos: logistic map x' = 3.9999 x (1 - x). Counting and
    // ordinal lenses read it near max entropy; only RQA sees the determinism.
    { double x = 0.372193;
      for (size_t i = 0; i < N; i++) { x = 3.9999 * x * (1.0 - x); fbuf[i] = x; } }
    sub_randomness_t logi_r = run_f64("logistic_map", fbuf, N);

    // 8. periodic signal: sine over a fixed stride.
    for (size_t i = 0; i < N; i++) fbuf[i] = sin((double)i * 0.35);
    sub_randomness_t sine_r = run_f64("sine", fbuf, N);

    // 9. large random with tableau lenses OFF (n > 10000): 6 lenses available.
    const size_t BIG = 50000;
    uint64_t *big = (uint64_t *)malloc(BIG * sizeof(uint64_t));
    lcg_seed(0xBEEFull);
    for (size_t i = 0; i < BIG; i++) big[i] = lcg_next();
    sub_randomness_t big_r = run("big_random", big, BIG);

    // 10. small random (n < 64): RQA and spectral honestly unavailable.
    lcg_seed(0xAAAAull);
    for (size_t i = 0; i < 32; i++) buf[i] = lcg_next();
    sub_randomness_t small_r = run("small_random", buf, 32);

    printf("\n");
    // Ordering: random dominates every structured input.
    check(rand_r.confidence > 0.80f, "uniform random confidence > 0.80");
    check(rand_r.confidence < 1.0f,  "confidence strictly < 1 (Kolmogorov)");
    check(sorted_r.confidence < 0.20f, "sorted confidence < 0.20");
    check(rev_r.confidence    < 0.20f, "reversed confidence < 0.20");
    check(few_r.confidence    < 0.30f, "few_unique confidence < 0.30");
    check(per_r.confidence    < rand_r.confidence, "periodic < uniform random");
    check(rand_r.confidence > sorted_r.confidence
       && rand_r.confidence > rev_r.confidence
       && rand_r.confidence > few_r.confidence
       && rand_r.confidence > per_r.confidence
       && rand_r.confidence > cyc_r.confidence
       && rand_r.confidence > logi_r.confidence
       && rand_r.confidence > sine_r.confidence, "random dominates all structured");

    // New lenses on uniform random: both available, both near max entropy.
    check(rand_r.lens_available[SUB_LENS_RQA]
       && rand_r.lens[SUB_LENS_RQA] > 0.90f, "random: RQA available and > 0.90");
    check(rand_r.lens_available[SUB_LENS_SPECTRAL]
       && rand_r.lens[SUB_LENS_SPECTRAL] > 0.70f, "random: spectral available and > 0.70");
    check(rand_r.lens_count == 8 && rand_r.agree_count == 8,
          "random: all 8 lenses available and agreeing");
    check(rand_r.verdict == SUB_RAND_MAX_ENTROPY, "random: verdict max-entropy");

    // Sorted input: order lenses veto. distinct is available with the REAL
    // sampled estimate: classify's sorted fast paths now fill
    // distinct_estimate at the root (a strictly-increasing ramp reads ~1.0),
    // superseding the earlier treat-zero-as-unavailable fallback. The lens
    // reads true and high; the order lenses carry the veto through the meet.
    check(sorted_r.lens_available[SUB_LENS_DISTINCT]
       && sorted_r.lens[SUB_LENS_DISTINCT] > 0.90f,
          "sorted: distinct available with the real estimate, not a fake 0.00");
    check(sorted_r.lens_available[SUB_LENS_RQA]
       && sorted_r.lens[SUB_LENS_RQA] < 0.10f, "sorted: RQA vetoes (DET = 1)");
    check(sorted_r.verdict == SUB_RAND_STRUCTURED, "sorted: verdict structured");

    // Chaos: RQA is the ONLY veto. Every counting/ordinal lens reads the
    // logistic map as high entropy; determinism shows only in the recurrence
    // plot's diagonal lines. That is this lens's whole value.
    check(logi_r.lens_available[SUB_LENS_RQA]
       && logi_r.lens[SUB_LENS_RQA] < 0.70f, "logistic: RQA vetoes the chaos");
    check(logi_r.lens[SUB_LENS_DISTINCT] > 0.90f
       && logi_r.lens[SUB_LENS_INVERSION] > 0.70f
       && logi_r.lens[SUB_LENS_HVG] > 0.70f
       && logi_r.lens[SUB_LENS_BANDT_POMPE] > 0.70f,
          "logistic: counting/ordinal lenses read it high-entropy");
    check(logi_r.agree_count == logi_r.lens_count - 1
       && logi_r.verdict == SUB_RAND_CONSISTENT,
          "logistic: k = N-1, verdict consistent (RQA the lone dissent)");
    check(logi_r.confidence < 0.50f, "logistic: confidence collapsed by the meet");

    // Periodic signals veto on the dynamics lenses.
    check(per_r.lens_available[SUB_LENS_RQA]
       && per_r.lens[SUB_LENS_RQA] < 0.10f, "sawtooth: RQA vetoes (DET = 1)");
    check(per_r.lens[SUB_LENS_BANDT_POMPE] < 0.30f, "sawtooth: bandt-pompe vetoes");
    check(sine_r.lens[SUB_LENS_BANDT_POMPE] < 0.70f, "sine: bandt-pompe vetoes");
    check(sine_r.lens[SUB_LENS_RQA] < 0.70f, "sine: RQA vetoes");
    check(cyc_r.lens_available[SUB_LENS_SPECTRAL]
       && cyc_r.lens[SUB_LENS_SPECTRAL] < 0.70f,
          "cycle8: spectral vetoes the value clustering");
    check(few_r.lens_available[SUB_LENS_SPECTRAL]
       && few_r.lens[SUB_LENS_SPECTRAL] < 0.30f,
          "few_unique: spectral vetoes the value clustering");
    check(!few_r.lens_available[SUB_LENS_RQA],
          "few_unique: RQA unavailable (degenerate distance distribution)");

    // Verdict boundaries: k == N max-entropy, k == N-1 consistent,
    // N/2 <= k < N-1 mixed, k < N/2 structured.
    check(sine_r.agree_count >= sine_r.lens_count / 2
       && sine_r.agree_count < sine_r.lens_count - 1
       && sine_r.verdict == SUB_RAND_MIXED, "sine: verdict mixed (N/2 <= k < N-1)");
    check(per_r.verdict == SUB_RAND_MIXED, "sawtooth: verdict mixed");
    check(few_r.agree_count < few_r.lens_count / 2
       && few_r.verdict == SUB_RAND_STRUCTURED, "few_unique: verdict structured (k < N/2)");
    check(rev_r.verdict == SUB_RAND_STRUCTURED, "reversed: verdict structured");

    // INVERSION lens contract: classify now publishes the analytic
    // inversion_ratio on the fast paths (reversed ~1.0, sorted 0.0), and the
    // lens score 1 - 2|r - 0.5| maps both extremes to ~0: a veto either way.
    check(rev_r.lens_available[SUB_LENS_INVERSION]
       && rev_r.lens[SUB_LENS_INVERSION] < 0.05f,
          "reversed: INVERSION lens reads the analytic ~1.0 ratio and vetoes");
    check(sorted_r.lens_available[SUB_LENS_INVERSION]
       && sorted_r.lens[SUB_LENS_INVERSION] < 0.05f,
          "sorted: INVERSION lens reads 0.0 ratio and vetoes");

    // Unavailable-lens paths: tableau lenses off above n=10000, RQA/spectral
    // off below n=64; the verdict still forms over what remains.
    check(big_r.lens_count == 6
       && !big_r.lens_available[SUB_LENS_HOOK]
       && !big_r.lens_available[SUB_LENS_LIS], "big_random: 6 lenses, tableau off");
    check(big_r.lens_available[SUB_LENS_RQA]
       && big_r.lens_available[SUB_LENS_SPECTRAL]
       && big_r.verdict == SUB_RAND_MAX_ENTROPY,
          "big_random: new lenses on, verdict max-entropy");
    check(big_r.confidence > 0.40f, "big_random still confident on 6 lenses");
    check(!small_r.lens_available[SUB_LENS_RQA]
       && !small_r.lens_available[SUB_LENS_SPECTRAL],
          "small_random (n=32): RQA and spectral honestly unavailable");
    check(small_r.lens_count == 4
       && small_r.verdict == SUB_RAND_MAX_ENTROPY,
          "small_random: verdict max-entropy over the 4 remaining lenses");

    free(buf);
    free(fbuf);
    free(big);
    printf("\n  %d passed, %d failed\n", _pass, _fail);
    return _fail ? 1 : 0;
}
