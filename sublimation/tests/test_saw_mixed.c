// test_saw_mixed.c -- alternating ascending/descending chunks of randomized length.
//
// Stresses the run-detector. Each chunk is locally ordered (one direction)
// but the sequence as a whole has no global order. The "nearly sorted"
// classifier must NOT mistake this for nearly-sorted: max_descent_gap and
// run_count should both reject the fast path. The full random sort path
// has to handle the result regardless.
//
// Chunk length: 8 + (lcg % 57)  -- mean ~36, range [8, 64]
// Direction: random per chunk
// Value range: each chunk picks a random base in [0, n) and fills [v, v+len)
// in its chosen direction.
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

// Alternating ascending/descending chunks of random length.
static void fill_saw_mixed(int64_t *arr, size_t n) {
    size_t i = 0;
    while (i < n) {
        size_t chunk = 8 + (size_t)(lcg_next() % 57);
        if (chunk > n - i) chunk = n - i;

        int direction = (int)(lcg_next() & 1u);  // 0 = ascending, 1 = descending
        int64_t base = (int64_t)(lcg_next() % (uint64_t)n);

        if (direction == 0) {
            for (size_t k = 0; k < chunk; k++) {
                arr[i + k] = base + (int64_t)k;
            }
        } else {
            for (size_t k = 0; k < chunk; k++) {
                arr[i + k] = base + (int64_t)(chunk - 1 - k);
            }
        }
        i += chunk;
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

        lcg_seed(0x5A617A17ull ^ (uint64_t)n);
        filler(arr, n);

        int64_t *saved = verify_save(arr, n);
        sublimation_i64(arr, n);
        verify_sort(arr, saved, n, name);
        free(saved);
        free(arr);
    }
}

int main(void) {
    run_pattern("saw_mixed", fill_saw_mixed);
    printf("\n  saw_mixed:");
    return verify_summary();
}
