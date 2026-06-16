// test_zipfian.c -- Zipfian-distributed int64 keys.
//
// Real-world skew. Most production sort workloads (databases, log lines,
// web request frequencies, social-network degree sequences) follow Zipfian
// or near-Zipfian distributions. Uniform random is the academic worst case
// for adaptive sorts; Zipfian is what actually shows up.
//
// Inverse-CDF sampling with exponent s = 1.07 (matches the existing
// fill_zipfian helper in test_adversarial.c for cross-test consistency).
// Support size R = max(16, n/4): keys are int64 values rank^2 + rank so the
// sort sees meaningfully spaced keys, not just a small dense range.
#include "../src/include/sublimation.h"
#include "verify.h"
#include <assert.h>
#include <math.h>

static const size_t SIZES[] = {100, 1000, 10000, 100000};
#define NUM_SIZES (sizeof(SIZES) / sizeof(SIZES[0]))

static uint64_t lcg_state;

static void lcg_seed(uint64_t s) { lcg_state = s; }

static uint64_t lcg_next(void) {
    lcg_state = lcg_state * 6364136223846793005ull + 1442695040888963407ull;
    return lcg_state;
}

// Draw a uniform double in [0, 1).
static double lcg_unit(void) {
    return (double)(lcg_next() >> 11) * (1.0 / 9007199254740992.0);
}

// Zipfian fill via inverse-CDF.
// Builds the cumulative distribution once over R = max(16, n/4) ranks,
// then for each output slot draws u in [0,1) and binary-searches the CDF
// to find the rank. The rank is then mapped to an int64 key (rank^2 + rank)
// so the sort gets meaningful ordering work, not just a sort over [1, R].
static void fill_zipfian(int64_t *arr, size_t n) {
    const double s = 1.07;
    size_t R = n / 4;
    if (R < 16) R = 16;

    // Cumulative distribution: cdf[k] = sum_{i=1..k+1} 1/i^s, normalized.
    double *cdf = (double *)malloc(R * sizeof(double));
    assert(cdf && "malloc failed");
    double total = 0.0;
    for (size_t k = 0; k < R; k++) {
        total += 1.0 / pow((double)(k + 1), s);
        cdf[k] = total;
    }
    for (size_t k = 0; k < R; k++) {
        cdf[k] /= total;
    }

    for (size_t i = 0; i < n; i++) {
        double u = lcg_unit();
        // Binary search for the smallest k with cdf[k] >= u.
        size_t lo = 0, hi = R;
        while (lo < hi) {
            size_t mid = lo + (hi - lo) / 2;
            if (cdf[mid] < u) lo = mid + 1;
            else              hi = mid;
        }
        size_t rank = lo;  // 0-indexed rank
        int64_t key = (int64_t)rank * (int64_t)rank + (int64_t)rank;
        arr[i] = key;
    }

    free(cdf);
}

typedef void (*fill_fn)(int64_t *arr, size_t n);

static void run_pattern(const char *pattern_name, fill_fn filler) {
    for (size_t si = 0; si < NUM_SIZES; si++) {
        size_t n = SIZES[si];
        char name[128];
        snprintf(name, sizeof(name), "%s (n=%zu)", pattern_name, n);

        int64_t *arr = (int64_t *)malloc(n * sizeof(int64_t));
        assert(arr && "malloc failed");

        lcg_seed(0x21F1A41ull ^ (uint64_t)n);
        filler(arr, n);

        int64_t *saved = verify_save(arr, n);
        sublimation_i64(arr, n);
        verify_sort(arr, saved, n, name);
        free(saved);
        free(arr);
    }
}

int main(void) {
    run_pattern("zipfian", fill_zipfian);
    printf("\n  zipfian:");
    return verify_summary();
}
