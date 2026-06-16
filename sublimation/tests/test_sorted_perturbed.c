// test_sorted_perturbed.c -- sorted ascending int64 with k random pair-swaps.
//
// Models log timestamps with reordering, append-mostly DBs, and sorted
// indexes after a few inserts. Generalizes pdqsort's "ascending + 1
// out-of-place" linear-time best case. Stresses the nearly-sorted classifier
// and the run-detection fast path.
//
// k = max(2, n/100) random pair swaps. Sweeps n in {100, 1000, 10000, 100000}.
#include "../src/include/sublimation.h"
#include "verify.h"
#include <assert.h>

static const size_t SIZES[] = {100, 1000, 10000, 100000};
#define NUM_SIZES (sizeof(SIZES) / sizeof(SIZES[0]))

static uint64_t lcg_state;

static void lcg_seed(uint64_t s) { lcg_state = s; }

static uint64_t lcg_next(void) {
    lcg_state = lcg_state * 6364136223846793005ull + 1442695040888963407ull;
    return lcg_state;
}

// Sorted ascending, then k random pair-swaps.
static void fill_sorted_perturbed(int64_t *arr, size_t n) {
    for (size_t i = 0; i < n; i++) arr[i] = (int64_t)i;
    size_t k = n / 100;
    if (k < 2) k = 2;
    for (size_t i = 0; i < k; i++) {
        size_t a = (size_t)(lcg_next() >> 33) % n;
        size_t b = (size_t)(lcg_next() >> 33) % n;
        int64_t tmp = arr[a]; arr[a] = arr[b]; arr[b] = tmp;
    }
}

typedef void (*fill_fn)(int64_t *arr, size_t n);

static void run_pattern(const char *pattern_name, fill_fn filler) {
    for (size_t si = 0; si < NUM_SIZES; si++) {
        size_t n = SIZES[si];
        char name[128];
        snprintf(name, sizeof(name), "%s (n=%zu)", pattern_name, n);

        int64_t *arr = (int64_t *)malloc(n * sizeof(int64_t));
        assert(arr && "malloc failed");

        lcg_seed(0x50A7EDull ^ (uint64_t)n);
        filler(arr, n);

        int64_t *saved = verify_save(arr, n);
        sublimation_i64(arr, n);
        verify_sort(arr, saved, n, name);
        free(saved);
        free(arr);
    }
}

int main(void) {
    run_pattern("sorted_perturbed", fill_sorted_perturbed);
    printf("\n  sorted_perturbed:");
    return verify_summary();
}
