// test_profile_contract.c -- sub_profile_t fill-contract tests.
//
// Locks the per-field contract documented on sub_profile_t in sublimation.h:
// inversion_ratio is analytic on the fast paths (reversed ~1.0, sorted and
// all-equal 0.0, rotated 2*rot*(n-rot)/(n*(n-1))) and a real sample elsewhere;
// lds_length is n for all-equal on every path (AVX2 i64 fast path, scalar
// path, tableau path all agree); distinct_estimate is exactly 1 on all-equal.
// Also locks the u64 mid-sort few-unique gate: duplicate-heavy data forced
// down the partition path must collapse to three-way partitioning instead of
// degrading quadratically (observable as a comparison-count ceiling).
#include "sublimation.h"
#include "internal/sort_internal.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <math.h>

static int _pass = 0, _fail = 0;

static void check(int ok, const char *what) {
    if (ok) { printf("  [PASS] %s\n", what); _pass++; }
    else    { printf("  [FAIL] %s\n", what); _fail++; }
}

static uint64_t lcg_state;
static void lcg_seed(uint64_t s) { lcg_state = s; }
static uint64_t lcg_next(void) {
    lcg_state = lcg_state * 6364136223846793005ull + 1442695040888963407ull;
    return lcg_state;
}

int main(void) {
    enum { N = 1024, BIG = 20000 };
    int64_t  *a64 = (int64_t *)malloc(BIG * sizeof(int64_t));
    uint64_t *u64v = (uint64_t *)malloc(BIG * sizeof(uint64_t));
    double   *f64v = (double *)malloc(BIG * sizeof(double));
    if (!a64 || !u64v || !f64v) { fprintf(stderr, "alloc failed\n"); return 1; }

    // REVERSED: analytic inversion_ratio ~1.0 on both the AVX2 (i64) and
    // scalar (u64) classifier paths.
    for (size_t i = 0; i < N; i++) a64[i] = (int64_t)(N - i) * 7;
    sub_profile_t p = sublimation_classify_i64(a64, N);
    check(p.disorder == SUB_REVERSED && p.inversion_ratio > 0.99f,
          "i64 reversed: disorder REVERSED, inversion_ratio ~1.0 (AVX2 path)");

    for (size_t i = 0; i < N; i++) u64v[i] = (uint64_t)(N - i) * 7u;
    p = sublimation_classify_u64(u64v, N);
    check(p.disorder == SUB_REVERSED && p.inversion_ratio > 0.99f,
          "u64 reversed: disorder REVERSED, inversion_ratio ~1.0 (scalar path)");
    check(p.lds_length == N && p.lis_length == 1,
          "u64 reversed: lds_length == n, lis_length == 1");

    // SORTED (distinct): inversion_ratio exactly 0, lds 1.
    for (size_t i = 0; i < N; i++) a64[i] = (int64_t)i * 3;
    p = sublimation_classify_i64(a64, N);
    check(p.disorder == SUB_SORTED && p.inversion_ratio == 0.0f && p.lds_length == 1,
          "i64 sorted: inversion_ratio 0.0, lds_length 1");

    // ALL-EQUAL: no inversions, lds_length == n, distinct exactly 1, on every
    // path. BIG > SUB_TABLEAU_MAX_N so the public wrapper cannot mask the
    // fast-path fill with a tableau recomputation: i64 exercises the AVX2
    // all-equal path, u64 and f64 the scalar sorted/all-equal path.
    for (size_t i = 0; i < BIG; i++) a64[i] = 42;
    p = sublimation_classify_i64(a64, BIG);
    check(p.disorder == SUB_SORTED && p.inversion_ratio == 0.0f,
          "i64 all-equal: SORTED with inversion_ratio 0.0");
    check(p.lds_length == BIG && p.distinct_estimate == 1,
          "i64 all-equal (AVX2 path): lds_length == n, distinct_estimate == 1");

    for (size_t i = 0; i < BIG; i++) u64v[i] = 42;
    p = sublimation_classify_u64(u64v, BIG);
    check(p.lds_length == BIG && p.distinct_estimate == 1
       && p.inversion_ratio == 0.0f,
          "u64 all-equal (scalar path): lds_length == n, distinct_estimate == 1");

    for (size_t i = 0; i < BIG; i++) f64v[i] = 42.0;
    p = sublimation_classify_f64(f64v, BIG);
    check(p.lds_length == BIG && p.distinct_estimate == 1,
          "f64 all-equal (scalar path): lds_length == n, distinct_estimate == 1");

    // All-equal inside the tableau window: the patience path publishes the
    // same lds_length == n (equal keys stack one pile of height n).
    for (size_t i = 0; i < N; i++) a64[i] = 7;
    p = sublimation_classify_i64(a64, N);
    check(p.lds_length == N, "i64 all-equal (tableau window): lds_length == n");

    // ROTATION: analytic inversion_ratio = 2*rot*(n-rot)/(n*(n-1)).
    {
        enum { RN = 1000, ROT = 300 };
        // [700..999, 0..699]: single descent at index 300, wraparound valid.
        for (size_t i = 0; i < RN; i++)
            a64[i] = (int64_t)((i + (RN - ROT)) % RN);
        p = sublimation_classify_i64(a64, RN);
        float expect = (float)(2.0 * (double)ROT * (double)(RN - ROT)
                               / ((double)RN * (double)(RN - 1)));
        check(p.disorder == SUB_NEARLY_SORTED && p.rotation_point == ROT,
              "i64 rotated: NEARLY_SORTED with the right rotation point");
        check(fabsf(p.inversion_ratio - expect) < 0.002f,
              "i64 rotated: analytic inversion_ratio 2*rot*(n-rot)/(n*(n-1))");
    }

    // EARLY NEARLY_SORTED: the run-count path must publish a real sampled
    // inversion_ratio, not a placeholder 0.0. 700 ascending + 300 descending:
    // 2 ascending runs, max_run_len 700 > n/2, ~9% of sampled pairs inverted.
    {
        enum { EN = 1000 };
        for (size_t i = 0; i < 700; i++) a64[i] = (int64_t)i;
        for (size_t i = 700; i < EN; i++) a64[i] = (int64_t)(100000 - i);
        p = sublimation_classify_i64(a64, EN);
        check(p.disorder == SUB_NEARLY_SORTED,
              "i64 early nearly-sorted: disorder NEARLY_SORTED");
        check(p.inversion_ratio > 0.02f && p.inversion_ratio < 0.5f,
              "i64 early nearly-sorted: sampled inversion_ratio, not 0.0");
    }

    // Classify-once consistency: the _stats entry reports the same disorder
    // the classifier assigns (one classification feeds both).
    {
        for (size_t i = 0; i < N; i++) a64[i] = (int64_t)(N - i);
        sub_stats_t st = {0};
        sub_profile_t before = sublimation_classify_i64(a64, N);
        sublimation_i64_stats(a64, N, &st);
        check(before.disorder == SUB_REVERSED && st.disorder == SUB_REVERSED,
              "stats: disorder matches the classifier verdict (reversed)");
        int sorted_ok = 1;
        for (size_t i = 1; i < N; i++) if (a64[i] < a64[i - 1]) { sorted_ok = 0; break; }
        check(sorted_ok, "stats: reversed input sorted");
    }

    // U64 MID-SORT FEW-UNIQUE GATE: 50% duplicates of one hot value forced
    // down the partition path (SUB_SPECTRAL routes push() without the AVX2
    // random shortcut). Without the sign-agnostic last-pivot gate the
    // duplicate block degrades quadratically (>= 25M comparisons at this n);
    // with it the three-way collapse keeps the count orders below that.
    {
        enum { GN = 20000 };
        const uint64_t HOT = 0x9000000000001234ull;  // above INT64_MAX: cast must stay bit-exact
        lcg_seed(0xFEEDBEEFull);
        for (size_t i = 0; i < GN; i++)
            u64v[i] = (i % 2 == 0) ? HOT : lcg_next();

        sub_profile_t forced = {0};
        forced.n = GN;
        forced.disorder = SUB_SPECTRAL;   // routes to push(), the gated path

        sub_adaptive_t state;
        sub_adaptive_init(&state, GN);
        sub_sort_internal_u64(u64v, GN, &state, &forced);

        int sorted_ok = 1;
        for (size_t i = 1; i < GN; i++) if (u64v[i] < u64v[i - 1]) { sorted_ok = 0; break; }
        check(sorted_ok, "u64 gate: duplicate-heavy input sorted");
        check(state.comparisons < 5000000ull,
              "u64 gate: comparisons bounded (three-way collapse engaged)");

        // Same shape through i64 (the original gate) as the differential
        // baseline: both types must live in the same comparison regime.
        lcg_seed(0xFEEDBEEFull);
        for (size_t i = 0; i < GN; i++)
            a64[i] = (i % 2 == 0) ? (int64_t)123456789
                                  : (int64_t)(lcg_next() >> 1);
        sub_adaptive_t state2;
        sub_adaptive_init(&state2, GN);
        sub_profile_t forced2 = {0};
        forced2.n = GN;
        forced2.disorder = SUB_SPECTRAL;
        sub_sort_internal_i64(a64, GN, &state2, &forced2);
        check(state2.comparisons < 5000000ull,
              "i64 gate baseline: comparisons bounded");
    }

    free(a64);
    free(u64v);
    free(f64v);
    printf("\n  %d passed, %d failed\n", _pass, _fail);
    return _fail ? 1 : 0;
}
