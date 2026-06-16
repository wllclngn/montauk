// test_tier1.c -- Tier 1: Exhaustive correctness + boundary testing
//
// Every sort result is property-verified: sorted + permutation.
// No test passes without both properties confirmed.
#include "../src/include/sublimation.h"
#include "verify.h"
#include <assert.h>
#include <limits.h>

// EXHAUSTIVE PERMUTATION TESTING
// For n <= 8: test ALL permutations (n! cases)
// For n = 9,10: test 100K random permutations

static void swap(int64_t *a, int64_t *b) { int64_t t = *a; *a = *b; *b = t; }

// Heap's algorithm for generating all permutations
static void test_all_permutations(size_t n) {
    char name[64];
    snprintf(name, sizeof(name), "all_perms_n%zu", n);

    int64_t arr[10];
    size_t c[10] = {0};
    for (size_t i = 0; i < n; i++) arr[i] = (int64_t)i;

    // test the identity permutation
    int64_t *saved = verify_save(arr, n);
    sublimation_i64(arr, n);
    verify_sort(arr, saved, n, name);
    free(saved);

    // generate all other permutations via Heap's algorithm
    size_t count = 1;
    size_t i = 0;
    while (i < n) {
        if (c[i] < i) {
            if (i % 2 == 0) swap(&arr[0], &arr[i]);
            else swap(&arr[c[i]], &arr[i]);
            c[i]++;
            i = 0;
            count++;

            // sort and verify this permutation
            int64_t work[10];
            memcpy(work, arr, n * sizeof(int64_t));
            saved = verify_save(work, n);
            sublimation_i64(work, n);
            if (!verify_sorted(work, n, name) ||
                !verify_permutation(work, saved, n, name)) {
                fprintf(stderr, "    FAILED on permutation #%zu of n=%zu\n", count, n);
                free(saved);
                return;
            }
            free(saved);
            _verify_pass++; // count quietly (don't print each perm)
        } else {
            c[i] = 0;
            i++;
        }
    }
    printf("  %-50s PASS (%zu perms)\n", name, count);
}

static void test_random_permutations(size_t n, size_t trials) {
    char name[64];
    snprintf(name, sizeof(name), "random_perms_n%zu_%zuK", n, trials / 1000);

    int64_t arr[16];
    uint64_t seed = 0xDEADBEEF + (uint64_t)n;

    for (size_t t = 0; t < trials; t++) {
        // generate random permutation via Fisher-Yates
        for (size_t i = 0; i < n; i++) arr[i] = (int64_t)i;
        for (size_t i = n - 1; i > 0; i--) {
            seed = seed * 6364136223846793005ull + 1442695040888963407ull;
            size_t j = (size_t)(seed >> 33) % (i + 1);
            swap(&arr[i], &arr[j]);
        }

        int64_t *saved = verify_save(arr, n);
        sublimation_i64(arr, n);
        if (!verify_sorted(arr, n, name) ||
            !verify_permutation(arr, saved, n, name)) {
            fprintf(stderr, "    FAILED on trial %zu of n=%zu\n", t, n);
            free(saved);
            return;
        }
        free(saved);
    }
    printf("  %-50s PASS (%zu trials)\n", name, trials);
    _verify_pass++;
}

// BOUNDARY VALUE TESTING

static void test_boundary_values(void) {
    // INT64 extremes
    {
        int64_t arr[] = {INT64_MAX, INT64_MIN, 0, -1, 1, INT64_MAX, INT64_MIN};
        VERIFY_SORT(arr, 7, sublimation_i64, "boundary_extremes");
    }
    // alternating min/max
    {
        int64_t arr[20];
        for (size_t i = 0; i < 20; i++)
            arr[i] = (i % 2 == 0) ? INT64_MIN : INT64_MAX;
        VERIFY_SORT(arr, 20, sublimation_i64, "boundary_alternating_minmax");
    }
    // all same value
    {
        int64_t arr[100];
        for (size_t i = 0; i < 100; i++) arr[i] = 42;
        VERIFY_SORT(arr, 100, sublimation_i64, "boundary_all_same");
    }
    // two values only
    {
        int64_t arr[100];
        for (size_t i = 0; i < 100; i++) arr[i] = (int64_t)(i % 2);
        VERIFY_SORT(arr, 100, sublimation_i64, "boundary_two_values");
    }
    // negative values only
    {
        int64_t arr[100];
        for (size_t i = 0; i < 100; i++) arr[i] = -(int64_t)(i + 1);
        VERIFY_SORT(arr, 100, sublimation_i64, "boundary_all_negative");
    }
    // single repeated pair
    {
        int64_t arr[] = {INT64_MIN, INT64_MAX};
        VERIFY_SORT(arr, 2, sublimation_i64, "boundary_min_max_pair");
    }
}

// THRESHOLD CROSSING TESTS
// Test at exactly n-1, n, n+1 for each threshold

static void test_threshold(size_t n, const char *label) {
    for (int delta = -1; delta <= 1; delta++) {
        size_t sz = (size_t)((int64_t)n + delta);
        if (sz == 0) continue;

        char name[80];
        snprintf(name, sizeof(name), "threshold_%s_%zu", label, sz);

        int64_t *arr = (int64_t *)malloc(sz * sizeof(int64_t));
        assert(arr);
        verify_fill_random(arr, sz, 12345 + sz);
        VERIFY_SORT(arr, sz, sublimation_i64, name);
        free(arr);
    }
}

// EMPTY AND TINY

static void test_empty_and_tiny(void) {
    // n = 0
    sublimation_i64(NULL, 0);
    printf("  %-50s PASS\n", "empty_n0");
    _verify_pass++;

    // n = 1
    {
        int64_t arr[] = {42};
        VERIFY_SORT(arr, 1, sublimation_i64, "tiny_n1");
    }
    // n = 2 sorted
    {
        int64_t arr[] = {1, 2};
        VERIFY_SORT(arr, 2, sublimation_i64, "tiny_n2_sorted");
    }
    // n = 2 reversed
    {
        int64_t arr[] = {2, 1};
        VERIFY_SORT(arr, 2, sublimation_i64, "tiny_n2_reversed");
    }
}

int main(void) {
    printf("[sublimation] Tier 1: exhaustive correctness + boundary testing\n\n");

    // empty/tiny
    test_empty_and_tiny();

    // exhaustive permutations n=1..8
    for (size_t n = 1; n <= 8; n++) {
        test_all_permutations(n);
    }

    // random permutation sampling n=9,10
    test_random_permutations(9, 100000);
    test_random_permutations(10, 100000);

    // boundary values
    test_boundary_values();

    // threshold crossings
    test_threshold(32, "base_case");       // SUB_SMALL_THRESHOLD
    test_threshold(64, "spectral_min");    // SUB_SPECTRAL_MIN_N
    test_threshold(128, "medium");         // SUB_MEDIUM_THRESHOLD
    test_threshold(512, "spectral_max");   // SUB_SPECTRAL_MAX_N
    test_threshold(100000, "parallel");    // SUB_PARALLEL_THRESHOLD

    return verify_summary();
}
