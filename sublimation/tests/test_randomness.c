// test_randomness.c -- the fused randomness battery on known distributions.
//
// The contract is ORDERING, not absolute values: uniform random must score far
// above every structured input (sorted, reversed, few-unique, periodic), and
// the confidence must stay strictly below 1. Per-lens scores are printed so a
// miscalibrated projection is visible.
#include "../src/include/sublimation_randomness.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

static int _pass = 0, _fail = 0;

static uint64_t lcg_state;
static void lcg_seed(uint64_t s) { lcg_state = s; }
static uint64_t lcg_next(void) {
    lcg_state = lcg_state * 6364136223846793005ull + 1442695040888963407ull;
    return lcg_state;
}

static const char *LENS_NAME[SUB_RANDOMNESS_LENSES] = {
    "hook", "lis", "inv", "distinct", "hvg", "bandt-pompe"
};

static sub_randomness_t run(const char *name, const uint64_t *a, size_t n) {
    sub_randomness_t r = sublimation_randomness_u64(a, n);
    printf("  %-14s n=%-6zu conf=%.3f  (k=%u/%u)  [", name, n,
           (double)r.confidence, r.agree_count, r.lens_count);
    for (int i = 0; i < SUB_RANDOMNESS_LENSES; i++) {
        if (r.lens_available[i]) printf(" %s=%.2f", LENS_NAME[i], (double)r.lens[i]);
        else                     printf(" %s=--", LENS_NAME[i]);
    }
    printf(" ]\n");
    return r;
}

static void check(int ok, const char *what) {
    if (ok) { printf("  [PASS] %s\n", what); _pass++; }
    else    { printf("  [FAIL] %s\n", what); _fail++; }
}

int main(void) {
    const size_t N = 4000;          // inside the 256..10000 tableau window
    uint64_t *buf = (uint64_t *)malloc(N * sizeof(uint64_t));

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

    // 5. periodic but all-distinct (sawtooth ramp): low HVG/BP, high distinct.
    for (size_t i = 0; i < N; i++) buf[i] = (uint64_t)(i % 100) * 1000000ull + i;
    sub_randomness_t per_r = run("periodic", buf, N);

    // 6. large random with tableau lenses OFF (n > 10000): 4 lenses available.
    const size_t BIG = 50000;
    uint64_t *big = (uint64_t *)malloc(BIG * sizeof(uint64_t));
    lcg_seed(0xBEEFull);
    for (size_t i = 0; i < BIG; i++) big[i] = lcg_next();
    sub_randomness_t big_r = run("big_random", big, BIG);

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
       && rand_r.confidence > per_r.confidence, "random dominates all structured");
    // Unavailable-lens path: tableau lenses off above n=10000.
    check(big_r.lens_count == 4
       && !big_r.lens_available[SUB_LENS_HOOK]
       && !big_r.lens_available[SUB_LENS_LIS], "big_random: 4 lenses, tableau off");
    check(big_r.confidence > 0.40f, "big_random still confident on 4 lenses");

    free(buf);
    free(big);
    printf("\n  %d passed, %d failed\n", _pass, _fail);
    return _fail ? 1 : 0;
}
