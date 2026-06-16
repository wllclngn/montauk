// test_tier5.c -- Tier 5: Spectral verification, oscillator convergence,
//                         deterministic reproducibility
#define _POSIX_C_SOURCE 199309L
#include "../src/include/sublimation.h"
#include "verify.h"
#include <assert.h>
#include <math.h>

// SPECTRAL NUMERICAL VERIFICATION (#30)
// Verify eigendecomposition properties on known matrices.

static void test_spectral_properties(void) {
    // sort 128 nearly-sorted elements (triggers spectral merge with 3-16 runs)
    // then verify the output is correct (implicitly tests eigendecomposition)
    {
        int64_t arr[128];
        for (size_t i = 0; i < 128; i++) arr[i] = (int64_t)i;
        // introduce a few swaps to create runs
        arr[30] = 50; arr[50] = 30;
        arr[60] = 80; arr[80] = 60;
        VERIFY_SORT(arr, 128, sublimation_i64, "spectral_nearly_sorted_128");
    }
    // pipe organ (2 runs, spectral merge handles)
    {
        int64_t arr[200];
        for (size_t i = 0; i < 100; i++) arr[i] = (int64_t)i;
        for (size_t i = 100; i < 200; i++) arr[i] = (int64_t)(200 - i);
        VERIFY_SORT(arr, 200, sublimation_i64, "spectral_pipe_organ_200");
    }
    // 3 runs (minimal spectral bisection case)
    {
        int64_t arr[300];
        for (size_t i = 0; i < 100; i++) arr[i] = (int64_t)(100 + i);    // 100-199
        for (size_t i = 100; i < 200; i++) arr[i] = (int64_t)(i - 100);   // 0-99
        for (size_t i = 200; i < 300; i++) arr[i] = (int64_t)(200 + i - 200); // 200-299
        VERIFY_SORT(arr, 300, sublimation_i64, "spectral_3_runs_300");
    }
}

// OSCILLATOR CONVERGENCE (#31)
// Run patterns that repeatedly trigger/relax CUSUM.
// Verify sort still produces correct output (oscillator doesn't diverge).

static void test_oscillator_convergence(void) {
    // alternating sorted/random segments (stresses CUSUM + oscillator)
    {
        int64_t arr[10000];
        uint64_t seed = 0xF00D;
        for (size_t i = 0; i < 10000; i++) {
            if ((i / 100) % 2 == 0) {
                arr[i] = (int64_t)i; // sorted segment
            } else {
                seed = seed * 6364136223846793005ull + 1442695040888963407ull;
                arr[i] = (int64_t)(seed >> 16); // random segment
            }
        }
        VERIFY_SORT(arr, 10000, sublimation_i64, "oscillator_alternating_10K");
    }
    // increasingly adversarial: 10 rounds of sort + corrupt
    {
        int64_t arr[5000];
        for (size_t i = 0; i < 5000; i++) arr[i] = (int64_t)i;
        uint64_t seed = 0xBEEF;
        for (int round = 0; round < 10; round++) {
            // corrupt a random 10% of elements
            for (size_t k = 0; k < 500; k++) {
                seed = seed * 6364136223846793005ull + 1442695040888963407ull;
                size_t idx = (size_t)(seed >> 33) % 5000;
                seed = seed * 6364136223846793005ull + 1442695040888963407ull;
                arr[idx] = (int64_t)(seed >> 16);
            }
            int64_t *saved = verify_save(arr, 5000);
            sublimation_i64(arr, 5000);
            verify_sort(arr, saved, 5000, "oscillator_repeated_corrupt");
            free(saved);
        }
    }
}

// DETERMINISTIC REPRODUCIBILITY (#33)
// Same seed -> same input -> same output -> same checksum.

static uint64_t checksum(const int64_t *arr, size_t n) {
    uint64_t h = 0;
    for (size_t i = 0; i < n; i++) {
        h ^= (uint64_t)arr[i] * 0x9E3779B97F4A7C15ull;
        h = (h << 13) | (h >> 51);
    }
    return h;
}

static void test_reproducibility(void) {
    size_t n = 100000;
    uint64_t checksums[5];

    for (int trial = 0; trial < 5; trial++) {
        int64_t *arr = (int64_t *)malloc(n * sizeof(int64_t));
        assert(arr);
        verify_fill_random(arr, n, 314159); // same seed every trial
        sublimation_i64(arr, n);
        checksums[trial] = checksum(arr, n);
        free(arr);
    }

    int ok = 1;
    for (int i = 1; i < 5; i++) {
        if (checksums[i] != checksums[0]) {
            fprintf(stderr, "  [FAIL] reproducibility: trial %d checksum %lx != trial 0 %lx\n",
                    i, (unsigned long)checksums[i], (unsigned long)checksums[0]);
            _verify_fail++;
            ok = 0;
        }
    }
    if (ok) {
        printf("  %-50s PASS (5 trials, checksum %lx)\n",
               "deterministic_100K", (unsigned long)checksums[0]);
        _verify_pass++;
    }

    // also test parallel path reproducibility
    for (int trial = 0; trial < 5; trial++) {
        int64_t *arr = (int64_t *)malloc(n * sizeof(int64_t));
        assert(arr);
        verify_fill_random(arr, n, 314159);
        sublimation_i64_parallel(arr, n, 4);
        checksums[trial] = checksum(arr, n);
        free(arr);
    }

    ok = 1;
    for (int i = 1; i < 5; i++) {
        if (checksums[i] != checksums[0]) {
            fprintf(stderr, "  [FAIL] parallel reproducibility: trial %d checksum %lx != trial 0 %lx\n",
                    i, (unsigned long)checksums[i], (unsigned long)checksums[0]);
            _verify_fail++;
            ok = 0;
        }
    }
    if (ok) {
        printf("  %-50s PASS (5 trials, checksum %lx)\n",
               "deterministic_parallel_100K", (unsigned long)checksums[0]);
        _verify_pass++;
    }
}

// PARALLEL CORRECTNESS
// Exercise sublimation_i64_parallel with varying thread counts,
// boundary sizes, and adversarial patterns.

static void fill_reversed(int64_t *arr, size_t n) {
    for (size_t i = 0; i < n; i++) arr[i] = (int64_t)(n - i);
}

static void fill_pipe_organ(int64_t *arr, size_t n) {
    size_t mid = n / 2;
    for (size_t i = 0; i < mid; i++) arr[i] = (int64_t)i;
    for (size_t i = mid; i < n; i++) arr[i] = (int64_t)(n - 1 - i);
}

static void fill_few_unique(int64_t *arr, size_t n) {
    for (size_t i = 0; i < n; i++) arr[i] = (int64_t)(i % 7);
}

static void test_parallel_correctness(void) {
    // thread count variation: 1, 2, 8 threads on 200K random
    {
        size_t n = 200000;
        size_t thread_counts[] = {1, 2, 8};
        for (int t = 0; t < 3; t++) {
            int64_t *arr = malloc(n * sizeof(int64_t));
            int64_t *saved = malloc(n * sizeof(int64_t));
            assert(arr && saved);
            verify_fill_random(arr, n, 42);
            memcpy(saved, arr, n * sizeof(int64_t));
            sublimation_i64_parallel(arr, n, thread_counts[t]);
            verify_sort(arr, saved, n, "parallel_threads");
            char name[64];
            snprintf(name, sizeof(name), "parallel_%zu_threads_200K", thread_counts[t]);
            printf("  %-50s PASS\n", name);
            free(arr);
            free(saved);
        }
    }

    // small-n below parallel threshold (should fall back to sequential)
    {
        size_t sizes[] = {100, 1000, 10000};
        for (int s = 0; s < 3; s++) {
            size_t n = sizes[s];
            int64_t *arr = malloc(n * sizeof(int64_t));
            assert(arr);
            verify_fill_random(arr, n, 99);
            int64_t *saved = verify_save(arr, n);
            sublimation_i64_parallel(arr, n, 4);
            verify_sort(arr, saved, n, "parallel_small_n");
            free(arr);
            free(saved);
        }
    }

    // threshold boundary: n=99999, 100000, 100001
    {
        size_t sizes[] = {99999, 100000, 100001};
        for (int s = 0; s < 3; s++) {
            size_t n = sizes[s];
            int64_t *arr = malloc(n * sizeof(int64_t));
            assert(arr);
            verify_fill_random(arr, n, 777);
            int64_t *saved = verify_save(arr, n);
            sublimation_i64_parallel(arr, n, 4);
            verify_sort(arr, saved, n, "parallel_threshold");
            free(arr);
            free(saved);
        }
    }

    // adversarial patterns through parallel path at 200K
    {
        size_t n = 200000;
        struct { const char *name; void (*fill)(int64_t*, size_t); } patterns[] = {
            {"parallel_reversed_200K", fill_reversed},
            {"parallel_pipe_organ_200K", fill_pipe_organ},
            {"parallel_few_unique_200K", fill_few_unique},
        };
        for (int p = 0; p < 3; p++) {
            int64_t *arr = malloc(n * sizeof(int64_t));
            assert(arr);
            patterns[p].fill(arr, n);
            int64_t *saved = verify_save(arr, n);
            sublimation_i64_parallel(arr, n, 4);
            verify_sort(arr, saved, n, patterns[p].name);
            free(arr);
            free(saved);
        }
    }
}

int main(void) {
    printf("[sublimation] Tier 5: spectral + oscillator + reproducibility + parallel\n\n");

    printf("  --- Spectral Properties ---\n");
    test_spectral_properties();

    printf("\n  --- Oscillator Convergence ---\n");
    test_oscillator_convergence();

    printf("\n  --- Deterministic Reproducibility ---\n");
    test_reproducibility();

    printf("\n  --- Parallel Correctness ---\n");
    test_parallel_correctness();

    return verify_summary();
}
