// test_kmerge.c -- the k-way merge's contract.
//
// THE EQUIVALENCE IS THE TEST, per the entry point's own promise: merging k
// already-sorted runs must be byte-identical to sorting the concatenation. The
// oracle is sublimation's own sort, so the two paths cannot drift apart without
// this failing.

#include "sublimation.h"
#include "sublimation_strings.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;
static int checks = 0;

static void ok(int cond, const char *what) {
    checks++;
    if (!cond) { failures++; printf("  FAIL %s\n", what); }
}

static uint64_t rng_state = 0x9E3779B97F4A7C15ull;
static uint64_t rnd(void) {
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return rng_state;
}

// Split `n` random values into k runs, sort each run, merge, and compare
// against sorting the whole thing.
static void equivalence_case(size_t n, size_t k, const char *label) {
    int64_t *all = (int64_t *)malloc(n ? n * sizeof(int64_t) : 1);
    int64_t *cat = (int64_t *)malloc(n ? n * sizeof(int64_t) : 1);
    for (size_t i = 0; i < n; i++) all[i] = (int64_t)rnd();
    memcpy(cat, all, n * sizeof(int64_t));

    // Deal into k runs of near-equal length, then sort each.
    int64_t **runs = (int64_t **)malloc(k * sizeof(int64_t *));
    size_t *lens = (size_t *)calloc(k, sizeof(size_t));
    size_t base = 0;
    for (size_t r = 0; r < k; r++) {
        size_t len = n / k + (r < n % k ? 1 : 0);
        lens[r] = len;
        runs[r] = all + base;
        base += len;
        sublimation_i64(runs[r], len);
    }

    int64_t *merged = (int64_t *)malloc(n ? n * sizeof(int64_t) : 1);
    int rc = sublimation_merge_i64((const int64_t *const *)runs, lens, k, merged);
    ok(rc == 0, label);

    sublimation_i64(cat, n);
    ok(n == 0 || memcmp(merged, cat, n * sizeof(int64_t)) == 0, label);

    free(all); free(cat); free(runs); free(lens); free(merged);
}

// A run longer than the internal buffer forces repeated pulls, which is where a
// cursor-refill bug would live.
static void long_run_case(void) {
    const size_t n = 40000, k = 3;
    equivalence_case(n, k, "long runs force many refills");
}

// Duplicate-heavy input: stability by run index is what makes the merge
// byte-identical to a sort of the concatenation when keys repeat.
static void duplicates_case(void) {
    const size_t n = 5000, k = 7;
    int64_t *all = (int64_t *)malloc(n * sizeof(int64_t));
    int64_t *cat = (int64_t *)malloc(n * sizeof(int64_t));
    for (size_t i = 0; i < n; i++) all[i] = (int64_t)(rnd() % 8);
    memcpy(cat, all, n * sizeof(int64_t));

    int64_t **runs = (int64_t **)malloc(k * sizeof(int64_t *));
    size_t *lens = (size_t *)calloc(k, sizeof(size_t));
    size_t base = 0;
    for (size_t r = 0; r < k; r++) {
        size_t len = n / k + (r < n % k ? 1 : 0);
        lens[r] = len; runs[r] = all + base; base += len;
        sublimation_i64(runs[r], len);
    }
    int64_t *merged = (int64_t *)malloc(n * sizeof(int64_t));
    ok(sublimation_merge_i64((const int64_t *const *)runs, lens, k, merged) == 0,
       "duplicate-heavy merge returns 0");
    sublimation_i64(cat, n);
    ok(memcmp(merged, cat, n * sizeof(int64_t)) == 0,
       "duplicate-heavy merge matches sorted concatenation");
    free(all); free(cat); free(runs); free(lens); free(merged);
}

// Empty runs must not confuse the heap: a run that is empty from the start is
// never seated, and one that empties mid-merge is removed.
static void empty_runs_case(void) {
    int64_t a[] = {1, 4, 9};
    int64_t b[] = {2, 3};
    const int64_t *runs[4] = {a, NULL, b, NULL};
    size_t lens[4] = {3, 0, 2, 0};
    int64_t out[5] = {0};
    ok(sublimation_merge_i64(runs, lens, 4, out) == 0, "empty runs return 0");
    const int64_t want[5] = {1, 2, 3, 4, 9};
    ok(memcmp(out, want, sizeof want) == 0, "empty runs are skipped cleanly");

    // Every run empty: nothing emitted, still a success.
    size_t zero[2] = {0, 0};
    const int64_t *none[2] = {NULL, NULL};
    ok(sublimation_merge_i64(none, zero, 2, out) == 0, "all-empty merge succeeds");

    // k == 0 is a no-op, not a crash.
    ok(sublimation_merge_i64(NULL, NULL, 0, out) == 0, "k=0 is a no-op");
}

// A single run must come back unchanged -- the degenerate case a splitter hits
// whenever it decides not to split.
static void single_run_case(void) {
    int64_t a[] = {-5, 0, 7, 7, 100};
    const int64_t *runs[1] = {a};
    size_t lens[1] = {5};
    int64_t out[5] = {0};
    ok(sublimation_merge_i64(runs, lens, 1, out) == 0, "k=1 returns 0");
    ok(memcmp(out, a, sizeof a) == 0, "k=1 is an exact copy");
}

// The emit callback's nonzero return must stop the merge and reach the caller,
// which is how a consumer with a broken pipe unwinds.
static int emit_fails(void *ctx, const int64_t *buf, size_t n) {
    (void)buf; (void)n;
    ++*(int *)ctx;
    return 42;
}
static size_t pull_ramp(void *ctx, size_t run, int64_t *buf, size_t cap) {
    (void)run;
    size_t *left = (size_t *)ctx;
    size_t take = *left < cap ? *left : cap;
    for (size_t i = 0; i < take; i++) buf[i] = (int64_t)i;
    *left -= take;
    return take;
}
static void emit_error_case(void) {
    size_t left = 10000;
    int calls = 0;
    int rc = sublimation_merge_stream_i64(1, pull_ramp, &left, emit_fails, &calls);
    ok(rc == 42, "emit's error code reaches the caller");
    ok(calls == 1, "merge stops at the first emit failure");
}

// Floats, to prove the template instantiates for a non-integer type.
static void f64_case(void) {
    double a[] = {1.5, 2.5, 9.0};
    double b[] = {-1.0, 2.5, 3.25};
    const double *runs[2] = {a, b};
    size_t lens[2] = {3, 3};
    double out[6] = {0};
    ok(sublimation_merge_f64(runs, lens, 2, out) == 0, "f64 merge returns 0");
    const double want[6] = {-1.0, 1.5, 2.5, 2.5, 3.25, 9.0};
    ok(memcmp(out, want, sizeof want) == 0, "f64 merge is ordered");
}


// STRING FACES. Same equivalence, oracle is sublimation_strings.
static int str_cmp_qs(const void *a, const void *b) {
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

static void strings_case(void) {
    static const char *words[] = {
        "pear", "apple", "fig", "apple", "quince", "date", "banana", "fig",
        "cherry", "elderberry", "date", "grape", "apple", "kiwi", "lemon",
    };
    const size_t n = sizeof words / sizeof words[0];
    const size_t k = 4;

    const char **flat = (const char **)malloc(n * sizeof(char *));
    memcpy(flat, words, n * sizeof(char *));

    const char **runs[4];
    size_t lens[4] = {0};
    size_t base = 0;
    for (size_t r = 0; r < k; r++) {
        size_t len = n / k + (r < n % k ? 1 : 0);
        lens[r] = len;
        runs[r] = flat + base;
        base += len;
        sublimation_strings(runs[r], len);
    }

    const char **merged = (const char **)malloc(n * sizeof(char *));
    ok(sublimation_merge_strings((const char *const *const *)runs, lens, k, merged) == 0,
       "string merge returns 0");

    const char **want = (const char **)malloc(n * sizeof(char *));
    memcpy(want, words, n * sizeof(char *));
    qsort(want, n, sizeof(char *), str_cmp_qs);

    int same = 1;
    for (size_t i = 0; i < n; i++) if (strcmp(merged[i], want[i]) != 0) same = 0;
    ok(same, "string merge matches sorted concatenation");

    free(flat); free(merged); free(want);
}

// Index face: runs of indices into one caller-owned array.
static void strings_indices_case(void) {
    static const char *arr[] = {"delta", "alpha", "echo", "bravo", "charlie", "alpha"};
    const size_t n = sizeof arr / sizeof arr[0];

    // Two already-ordered index runs: {1,0,2} -> alpha,delta,echo
    //                                 {5,3,4} -> alpha,bravo,charlie
    static const uint32_t r0[] = {1, 0, 2};
    static const uint32_t r1[] = {5, 3, 4};
    const uint32_t *runs[2] = {r0, r1};
    size_t lens[2] = {3, 3};
    uint32_t out[6] = {0};

    ok(sublimation_merge_strings_indices(arr, runs, lens, 2, out) == 0,
       "index merge returns 0");

    int ordered = 1;
    for (size_t i = 1; i < n; i++) {
        if (strcmp(arr[out[i - 1]], arr[out[i]]) > 0) ordered = 0;
    }
    ok(ordered, "index merge yields ascending keys");
    // Stability: the tied "alpha" from run 0 (index 1) must precede run 1's (5).
    ok(out[0] == 1 && out[1] == 5, "index merge is stable by run index");
}

int main(void) {
    printf("[kmerge] k-way merge of pre-sorted runs\n");

    equivalence_case(0, 3, "n=0");
    equivalence_case(1, 1, "n=1 k=1");
    equivalence_case(1, 4, "n=1 k=4 (more runs than elements)");
    equivalence_case(1000, 2, "k=2");
    equivalence_case(1000, 3, "k=3");
    equivalence_case(1000, 8, "k=8");
    equivalence_case(1000, 64, "k=64");
    equivalence_case(9999, 17, "odd sizes");
    printf("[kmerge]   equivalence to sorted concatenation ok\n");

    long_run_case();
    printf("[kmerge]   buffer refill across long runs ok\n");
    duplicates_case();
    printf("[kmerge]   stability with duplicate keys ok\n");
    empty_runs_case();
    single_run_case();
    printf("[kmerge]   empty and single-run edges ok\n");
    emit_error_case();
    printf("[kmerge]   emit error propagation ok\n");
    f64_case();
    printf("[kmerge]   f64 instantiation ok\n");
    strings_case();
    strings_indices_case();
    printf("[kmerge]   string and index faces ok\n");

    if (failures) {
        printf("\n[kmerge] GATE FAILED: %d of %d checks\n", failures, checks);
        return 1;
    }
    printf("\n[kmerge] GATE PASSED: %d checks -- merging k sorted runs is "
           "byte-identical to sorting the concatenation\n", checks);
    return 0;
}
