// test_pext_partition.c -- standalone unit test for block_partition_pext_i64.
//
// Verifies the in-place PEXT partition before integration into the random
// path. Tests:
//   1. All elements left of returned p are < pivot
//   2. All elements right of returned p are >= pivot
//   3. Output is a permutation of input (multiset preserved)
//
// Edge sizes (forces both small-Lomuto and main loop paths) and edge pivots
// (extrema, median, duplicate values) are exercised.
//
// Built standalone by tests/test.py-equivalent invocation; not wired into
// the runner because the function is exposed only for this test.

#define _POSIX_C_SOURCE 200809L
#include "sublimation.h"
#include "internal/sort_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static int cmp_i64(const void *a, const void *b) {
    int64_t x = *(const int64_t *)a;
    int64_t y = *(const int64_t *)b;
    return (x > y) - (x < y);
}

// Verify that block_partition_pext_i64 produced a valid partition AND
// preserved the multiset. Returns 1 on success, 0 on failure.
static int verify_partition(const int64_t *original, const int64_t *partitioned,
                             size_t n, size_t p, int64_t pivot, const char *label) {
    // Multiset preservation: sort copies of both and compare.
    int64_t *a = (int64_t *)malloc(n * sizeof(int64_t));
    int64_t *b = (int64_t *)malloc(n * sizeof(int64_t));
    if (!a || !b) { free(a); free(b); return 0; }
    memcpy(a, original, n * sizeof(int64_t));
    memcpy(b, partitioned, n * sizeof(int64_t));
    qsort(a, n, sizeof(int64_t), cmp_i64);
    qsort(b, n, sizeof(int64_t), cmp_i64);
    int multiset_ok = (memcmp(a, b, n * sizeof(int64_t)) == 0);
    free(a); free(b);
    if (!multiset_ok) {
        fprintf(stderr, "  [FAIL] %s: multiset not preserved\n", label);
        return 0;
    }

    // Left side: all < pivot
    for (size_t i = 0; i < p; i++) {
        if (partitioned[i] >= pivot) {
            fprintf(stderr, "  [FAIL] %s: arr[%zu]=%lld >= pivot=%lld (left)\n",
                    label, i, (long long)partitioned[i], (long long)pivot);
            return 0;
        }
    }
    // Right side: all >= pivot
    for (size_t i = p; i < n; i++) {
        if (partitioned[i] < pivot) {
            fprintf(stderr, "  [FAIL] %s: arr[%zu]=%lld < pivot=%lld (right)\n",
                    label, i, (long long)partitioned[i], (long long)pivot);
            return 0;
        }
    }
    return 1;
}

// Run one test: generate input, partition, verify.
static int run_one(size_t n, int64_t pivot, uint64_t seed,
                    int64_t (*gen)(uint64_t *), const char *label) {
    int64_t *orig = (int64_t *)malloc(n * sizeof(int64_t));
    int64_t *work = (int64_t *)malloc(n * sizeof(int64_t));
    if (!orig || !work) { free(orig); free(work); return 0; }

    uint64_t s = seed;
    for (size_t i = 0; i < n; i++) {
        orig[i] = gen(&s);
    }
    memcpy(work, orig, n * sizeof(int64_t));

    size_t p = block_partition_pext_i64(work, 0, n, pivot);
    int ok = verify_partition(orig, work, n, p, pivot, label);

    free(orig);
    free(work);
    return ok;
}

// Generators (each takes its own state pointer)
static int64_t gen_random(uint64_t *s) {
    *s = (*s) * 6364136223846793005ull + 1442695040888963407ull;
    return (int64_t)((*s) >> 16);
}
static int64_t gen_uniform_small(uint64_t *s) {
    *s = (*s) * 6364136223846793005ull + 1442695040888963407ull;
    return (int64_t)(((*s) >> 16) % 100);  // [0, 100)
}
static int64_t gen_constant(uint64_t *s) { (void)s; return 42; }
static int64_t gen_ascending_state;
static int64_t gen_ascending(uint64_t *s) { (void)s; return gen_ascending_state++; }

int main(void) {
    int passed = 0, failed = 0;

    // Edge sizes: tiny (forces scalar Lomuto path), boundary (just below and
    // above 2*BLOCK=32), small block-loop, large block-loop, plus duplicates.
    size_t sizes[] = {2, 3, 16, 31, 32, 33, 64, 65, 100, 256, 1000, 10000, 65536};
    size_t n_sizes = sizeof(sizes) / sizeof(sizes[0]);

    // Edge pivots: very small, very large, mid-range; also tested against
    // the duplicate generator (where many elements equal the pivot).
    int64_t pivots[] = {INT64_MIN + 1, -1000, 0, 50, 1000, 1000000000LL, INT64_MAX - 1};
    size_t n_pivots = sizeof(pivots) / sizeof(pivots[0]);

    // Random data x edge pivots
    for (size_t si = 0; si < n_sizes; si++) {
        for (size_t pi = 0; pi < n_pivots; pi++) {
            char label[64];
            snprintf(label, sizeof(label), "random n=%zu pivot=%lld",
                     sizes[si], (long long)pivots[pi]);
            if (run_one(sizes[si], pivots[pi], 0xC0DE0001 + si * 13 + pi,
                        gen_random, label)) passed++;
            else failed++;
        }
    }

    // Small-range data with pivot in the range -- exercises duplicate handling.
    for (size_t si = 0; si < n_sizes; si++) {
        for (int64_t pv = 0; pv <= 100; pv += 25) {
            char label[64];
            snprintf(label, sizeof(label), "small n=%zu pivot=%lld",
                     sizes[si], (long long)pv);
            if (run_one(sizes[si], pv, 0xBEEF0001 + si * 7 + (uint64_t)pv,
                        gen_uniform_small, label)) passed++;
            else failed++;
        }
    }

    // Constant input (every element == 42). Pivot above, equal to, below.
    for (size_t si = 0; si < n_sizes; si++) {
        int64_t pvs[] = {41, 42, 43};
        for (int p = 0; p < 3; p++) {
            char label[64];
            snprintf(label, sizeof(label), "const n=%zu pivot=%lld",
                     sizes[si], (long long)pvs[p]);
            if (run_one(sizes[si], pvs[p], 0, gen_constant, label)) passed++;
            else failed++;
        }
    }

    // Ascending input (already sorted). Pivot at various positions.
    for (size_t si = 0; si < n_sizes; si++) {
        int64_t mids[] = {0, (int64_t)(sizes[si] / 4), (int64_t)(sizes[si] / 2),
                          (int64_t)(3 * sizes[si] / 4), (int64_t)sizes[si]};
        for (int m = 0; m < 5; m++) {
            char label[80];
            snprintf(label, sizeof(label), "ascending n=%zu pivot=%lld",
                     sizes[si], (long long)mids[m]);
            gen_ascending_state = 0;
            if (run_one(sizes[si], mids[m], 0, gen_ascending, label)) passed++;
            else failed++;
        }
    }

    printf("  pext_partition: %d passed, %d failed\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
