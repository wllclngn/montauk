// test_antiqsort.c -- McIlroy 1999 adversarial input.
//
// Reference: M. D. McIlroy, "A Killer Adversary for Quicksort,"
//            Software: Practice and Experience 29(4):341-344, 1999.
//            https://www.cs.dartmouth.edu/~doug/mdmspe.pdf
//
// The McIlroy adversary builds a worst-case permutation by intercepting
// every comparison libc qsort makes, lying just enough to drive the
// partition into worst-case shape, and recording the values it implicitly
// committed to. After qsort returns, the resulting permutation IS the
// killer for that variant of quicksort.
//
// HONESTY NOTES:
//   - The killer is generated against libc qsort (the comparison callback
//     this file passes to qsort). The attack target is whichever quicksort
//     the McIlroy comparator drives. sublimation_i64 is then run on the
//     resulting permutation as an adversarial-flavored stress test.
//   - sublimation's PCF wrapper bucketizes input before quicksort sees it,
//     which may partly destroy the adversarial structure. The killer is
//     therefore not guaranteed to drive sublimation quadratic.
//   - The wall-clock budget check IS the actual robustness assertion: if
//     any future architectural change introduces a quadratic worst case,
//     this test will catch it via the budget.
//
// Sizes: {100, 1000, 10000, 100000}. Budgets are ~100x measured best on
// the development machine and ~5-20x below quadratic detection threshold,
// leaving safe headroom for slower CI hardware and cold caches.
#define _POSIX_C_SOURCE 200809L
#include "../src/include/sublimation.h"
#include "verify.h"
#include <assert.h>
#include <time.h>

// Tiered wall-clock budgets per size. ~100x measured best on the dev box
// (Skylake i5-7300HQ, AVX2, ~2.5 GHz), ~5-20x below quadratic blowup
// detection. If sublimation goes O(n^2) on adversarial input, the largest
// size will overrun by orders of magnitude and the test fails loudly.
typedef struct {
    size_t   n;
    uint64_t budget_ns;
} antiqsort_size_t;

static const antiqsort_size_t SIZES[] = {
    {    100,     1000000ull },  //   1 ms
    {   1000,     5000000ull },  //   5 ms
    {  10000,    25000000ull },  //  25 ms
    { 100000,   250000000ull },  // 250 ms
};
#define NUM_SIZES (sizeof(SIZES) / sizeof(SIZES[0]))

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

// File-static state for the McIlroy adversary. Reset before each call to
// build_antiqsort_killer.
static int  *aq_val;       // val[i] == -1 means "unset", else assigned
static int   aq_gas;        // next value to assign
static int   aq_nsolid;     // count of items already assigned a value
static int   aq_candidate;  // index that should become the smaller on
                            // next contact (chosen by the adversary)

// The adversary comparator passed to libc qsort. Indices x and y point
// into a working array; we look up val[x] and val[y]:
//
//   - both unset:  assign aq_candidate the next gas value (making it
//                  smaller), then compare again.
//   - one unset:   the unset one becomes the new candidate; return as if
//                  the unset one is larger so qsort considers it "high".
//   - both set:    return their actual difference.
static int aq_cmp(const void *px, const void *py) {
    int x = *(const int *)px;
    int y = *(const int *)py;

    if (aq_val[x] == -1 && aq_val[y] == -1) {
        if (x == aq_candidate) {
            aq_val[x] = aq_gas++;
        } else {
            aq_val[y] = aq_gas++;
        }
        aq_nsolid++;
    }

    if (aq_val[x] == -1) {
        aq_candidate = x;
        return 1;  // x appears greater (currently unsolid)
    }
    if (aq_val[y] == -1) {
        aq_candidate = y;
        return -1; // y appears greater (currently unsolid)
    }
    return aq_val[x] - aq_val[y];
}

// Build a killer permutation of 0..n-1 in out[]. Drives libc qsort against
// the McIlroy adversary, then writes the assigned values into out[] as int64.
// Allocates and frees its own scratch.
static void build_antiqsort_killer(int64_t *out, size_t n) {
    int *idx = (int *)malloc(n * sizeof(int));
    aq_val   = (int *)malloc(n * sizeof(int));
    assert(idx && aq_val && "malloc failed");

    for (size_t i = 0; i < n; i++) {
        idx[i] = (int)i;
        aq_val[i] = -1;
    }
    aq_gas = 0;
    aq_nsolid = 0;
    aq_candidate = 0;

    qsort(idx, n, sizeof(int), aq_cmp);

    // Any indices still unset after qsort returns get assigned the
    // remaining gas values. (In practice all are usually assigned, but
    // the McIlroy paper notes the cleanup step is needed for safety.)
    for (size_t i = 0; i < n; i++) {
        if (aq_val[i] == -1) {
            aq_val[i] = aq_gas++;
        }
    }

    for (size_t i = 0; i < n; i++) {
        out[i] = (int64_t)aq_val[i];
    }

    free(idx);
    free(aq_val);
    aq_val = NULL;
}

static void run_antiqsort_test(void) {
    for (size_t si = 0; si < NUM_SIZES; si++) {
        size_t   n         = SIZES[si].n;
        uint64_t budget_ns = SIZES[si].budget_ns;
        char name[128];
        snprintf(name, sizeof(name), "antiqsort (n=%zu)", n);

        int64_t *arr = (int64_t *)malloc(n * sizeof(int64_t));
        assert(arr && "malloc failed");

        build_antiqsort_killer(arr, n);

        int64_t *saved = verify_save(arr, n);

        uint64_t t0 = now_ns();
        sublimation_i64(arr, n);
        uint64_t t1 = now_ns();
        uint64_t elapsed = t1 - t0;

        verify_sort(arr, saved, n, name);

        // Wall-clock budget check. Quadratic blowup would push elapsed into
        // multiple seconds at n=100000; the budget catches it long before.
        if (elapsed > budget_ns) {
            fprintf(stderr,
                "  [FAIL] antiqsort budget n=%zu: %llu ns > %llu ns "
                "(possible quadratic regression)\n",
                n,
                (unsigned long long)elapsed,
                (unsigned long long)budget_ns);
            _verify_fail++;
        }

        free(saved);
        free(arr);
    }
}

int main(void) {
    run_antiqsort_test();
    printf("\n  antiqsort:");
    return verify_summary();
}
