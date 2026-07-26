// test_dfspool.c -- work-stealing DFS executor: correctness + race-freedom.
//
// Drives a parallel 3-way quicksort through sub_dfs_run (partition on the
// owner, push the two outer children, coarsen to insertion sort). Checks the
// result is fully sorted AND a permutation of the input (vs a qsort oracle),
// across several worker counts and input shapes. Built under ThreadSanitizer
// by run.py: the executor's deque traffic plus the disjoint-frame ownership of
// the payload must be race-clean.
#define _POSIX_C_SOURCE 200809L
#include "internal/dfspool.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static int failures = 0;
#define CHECK(cond, msg) do { \
    if (!(cond)) { fprintf(stderr, "FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__); failures++; } \
} while (0)

static void insertion_sort(int64_t *a, size_t n) {
    for (size_t i = 1; i < n; i++) {
        int64_t key = a[i];
        size_t j = i;
        while (j > 0 && a[j - 1] > key) { a[j] = a[j - 1]; j--; }
        a[j] = key;
    }
}

static int64_t med3(int64_t x, int64_t y, int64_t z) {
    if (x < y) return y < z ? y : (x < z ? z : x);
    return x < z ? x : (y < z ? z : y);
}

// Parallel 3-way quicksort frame: coarsen small, else Bentley-McIlroy partition
// and push the < and > children (the == band is already placed).
static void qsort_frame(sub_dfs_frame_t f, sub_dfs_ctx_t *ctx, void *user) {
    (void)user;
    int64_t *a = (int64_t *)f.base;
    size_t n = f.n;
    if (n <= 32) { insertion_sort(a, n); return; }

    int64_t pivot = med3(a[0], a[n / 2], a[n - 1]);
    size_t lt = 0, gt = n, i = 0;
    while (i < gt) {
        if (a[i] < pivot) { int64_t t = a[i]; a[i] = a[lt]; a[lt] = t; lt++; i++; }
        else if (a[i] > pivot) { gt--; int64_t t = a[i]; a[i] = a[gt]; a[gt] = t; }
        else i++;
    }
    if (lt > 1)
        sub_dfs_push(ctx, (sub_dfs_frame_t){ .base = a, .n = lt, .depth = f.depth + 1 });
    if (n - gt > 1)
        sub_dfs_push(ctx, (sub_dfs_frame_t){ .base = a + gt, .n = n - gt, .depth = f.depth + 1 });
}

static int cmp_i64(const void *x, const void *y) {
    int64_t a = *(const int64_t *)x, b = *(const int64_t *)y;
    return (a > b) - (a < b);
}

static uint64_t rng_state = 0x123456789abcdef0ull;
static uint64_t xrand(void) {
    rng_state ^= rng_state << 13; rng_state ^= rng_state >> 7; rng_state ^= rng_state << 17;
    return rng_state;
}

static void run_case(const char *name, size_t n, size_t nworkers,
                     void (*fill)(int64_t *, size_t)) {
    int64_t *a = malloc(n * sizeof(int64_t));
    int64_t *oracle = malloc(n * sizeof(int64_t));
    if (!a || !oracle) { CHECK(0, "alloc"); free(a); free(oracle); return; }
    fill(a, n);
    memcpy(oracle, a, n * sizeof(int64_t));
    qsort(oracle, n, sizeof(int64_t), cmp_i64);

    bool ok = sub_dfs_run(nworkers, (sub_dfs_frame_t){ .base = a, .n = n, .depth = 0 },
                          qsort_frame, nullptr);
    CHECK(ok, "sub_dfs_run setup");

    int sorted = 1;
    for (size_t i = 1; i < n; i++) if (a[i - 1] > a[i]) { sorted = 0; break; }
    int perm = (memcmp(a, oracle, n * sizeof(int64_t)) == 0);
    if (!sorted || !perm)
        fprintf(stderr, "  case %s n=%zu workers=%zu: sorted=%d perm=%d\n",
                name, n, nworkers, sorted, perm);
    CHECK(sorted, name);
    CHECK(perm, name);

    free(a);
    free(oracle);
}

static void fill_random(int64_t *a, size_t n) { for (size_t i = 0; i < n; i++) a[i] = (int64_t)xrand(); }
static void fill_fewuniq(int64_t *a, size_t n) { for (size_t i = 0; i < n; i++) a[i] = (int64_t)(xrand() % 7); }
static void fill_sorted(int64_t *a, size_t n) { for (size_t i = 0; i < n; i++) a[i] = (int64_t)i; }
static void fill_reversed(int64_t *a, size_t n) { for (size_t i = 0; i < n; i++) a[i] = (int64_t)(n - i); }
static void fill_allequal(int64_t *a, size_t n) { for (size_t i = 0; i < n; i++) a[i] = 42; }

int main(void) {
    size_t worker_counts[] = { 1, 2, 4, 8 };
    struct { const char *name; void (*fill)(int64_t *, size_t); } cases[] = {
        { "random", fill_random }, { "few-unique", fill_fewuniq },
        { "sorted", fill_sorted }, { "reversed", fill_reversed },
        { "all-equal", fill_allequal },
    };
    for (size_t w = 0; w < sizeof(worker_counts) / sizeof(*worker_counts); w++)
        for (size_t c = 0; c < sizeof(cases) / sizeof(*cases); c++)
            run_case(cases[c].name, 500000, worker_counts[w], cases[c].fill);

    // A few tiny sizes to exercise the coarsen/empty-child edges.
    for (size_t n = 0; n <= 64; n++)
        run_case("small", n, 4, fill_random);

    if (failures) { fprintf(stderr, "test_dfspool: %d FAILED\n", failures); return 1; }
    printf("test_dfspool: OK\n");
    return 0;
}
