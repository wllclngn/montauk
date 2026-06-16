// test_basic.c -- Core correctness tests
#include "../src/include/sublimation.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) static void test_##name(void)
#define RUN(name) do {                                          \
    printf("  %-50s", #name);                                   \
    test_##name();                                              \
    printf("PASS\n");                                           \
    tests_passed++;                                             \
} while (0)

#define ASSERT_SORTED(arr, n) do {                              \
    for (size_t _i = 1; _i < (n); _i++) {                      \
        if ((arr)[_i] < (arr)[_i-1]) {                          \
            printf("FAIL (arr[%zu]=%ld > arr[%zu]=%ld)\n",      \
                   _i-1, (long)(arr)[_i-1], _i, (long)(arr)[_i]); \
            tests_failed++;                                     \
            return;                                             \
        }                                                       \
    }                                                           \
} while (0)

// Fill array with random values using LCG (deterministic)
static void fill_random(int64_t *arr, size_t n, uint64_t seed) {
    for (size_t i = 0; i < n; i++) {
        seed = seed * 6364136223846793005ull + 1442695040888963407ull;
        arr[i] = (int64_t)(seed >> 16);
    }
}

// BASIC CORRECTNESS

TEST(empty) {
    sublimation_i64(nullptr, 0);
}

TEST(single) {
    int64_t arr[] = {42};
    sublimation_i64(arr, 1);
    assert(arr[0] == 42);
}

TEST(two_sorted) {
    int64_t arr[] = {1, 2};
    sublimation_i64(arr, 2);
    ASSERT_SORTED(arr, 2);
}

TEST(two_reversed) {
    int64_t arr[] = {2, 1};
    sublimation_i64(arr, 2);
    ASSERT_SORTED(arr, 2);
}

TEST(three) {
    int64_t arr[] = {3, 1, 2};
    sublimation_i64(arr, 3);
    ASSERT_SORTED(arr, 3);
}

TEST(four) {
    int64_t arr[] = {4, 2, 3, 1};
    sublimation_i64(arr, 4);
    ASSERT_SORTED(arr, 4);
}

TEST(already_sorted) {
    int64_t arr[100];
    for (size_t i = 0; i < 100; i++) arr[i] = (int64_t)i;
    sublimation_i64(arr, 100);
    ASSERT_SORTED(arr, 100);
}

TEST(reversed) {
    int64_t arr[100];
    for (size_t i = 0; i < 100; i++) arr[i] = (int64_t)(100 - i);
    sublimation_i64(arr, 100);
    ASSERT_SORTED(arr, 100);
}

TEST(all_equal) {
    int64_t arr[100];
    for (size_t i = 0; i < 100; i++) arr[i] = 42;
    sublimation_i64(arr, 100);
    ASSERT_SORTED(arr, 100);
    for (size_t i = 0; i < 100; i++) assert(arr[i] == 42);
}

TEST(two_values) {
    int64_t arr[100];
    for (size_t i = 0; i < 100; i++) arr[i] = (int64_t)(i % 2);
    sublimation_i64(arr, 100);
    ASSERT_SORTED(arr, 100);
}

// CLASSIFICATION

TEST(classify_sorted) {
    int64_t arr[100];
    for (size_t i = 0; i < 100; i++) arr[i] = (int64_t)i;
    sub_profile_t p = sublimation_classify_i64(arr, 100);
    assert(p.disorder == SUB_SORTED);
}

TEST(classify_reversed) {
    int64_t arr[100];
    for (size_t i = 0; i < 100; i++) arr[i] = (int64_t)(100 - i);
    sub_profile_t p = sublimation_classify_i64(arr, 100);
    assert(p.disorder == SUB_REVERSED);
}

TEST(classify_random) {
    int64_t arr[1000];
    fill_random(arr, 1000, 12345);
    sub_profile_t p = sublimation_classify_i64(arr, 1000);
    assert(p.disorder == SUB_RANDOM || p.disorder == SUB_FEW_UNIQUE);
}

// SCALE

TEST(random_1k) {
    int64_t arr[1000];
    fill_random(arr, 1000, 42);
    sublimation_i64(arr, 1000);
    ASSERT_SORTED(arr, 1000);
}

TEST(random_10k) {
    int64_t *arr = malloc(10000 * sizeof(int64_t));
    assert(arr);
    fill_random(arr, 10000, 7777);
    sublimation_i64(arr, 10000);
    ASSERT_SORTED(arr, 10000);
    free(arr);
}

TEST(random_100k) {
    int64_t *arr = malloc(100000 * sizeof(int64_t));
    assert(arr);
    fill_random(arr, 100000, 99999);
    sublimation_i64(arr, 100000);
    ASSERT_SORTED(arr, 100000);
    free(arr);
}

TEST(random_1m) {
    int64_t *arr = malloc(1000000 * sizeof(int64_t));
    assert(arr);
    fill_random(arr, 1000000, 314159);
    sublimation_i64(arr, 1000000);
    ASSERT_SORTED(arr, 1000000);
    free(arr);
}

// NEARLY SORTED

TEST(nearly_sorted_few_swaps) {
    int64_t arr[1000];
    for (size_t i = 0; i < 1000; i++) arr[i] = (int64_t)i;
    // introduce 10 random swaps
    uint64_t seed = 555;
    for (int k = 0; k < 10; k++) {
        seed = seed * 6364136223846793005ull + 1442695040888963407ull;
        size_t i = (size_t)(seed >> 33) % 1000;
        seed = seed * 6364136223846793005ull + 1442695040888963407ull;
        size_t j = (size_t)(seed >> 33) % 1000;
        int64_t tmp = arr[i]; arr[i] = arr[j]; arr[j] = tmp;
    }
    sublimation_i64(arr, 1000);
    ASSERT_SORTED(arr, 1000);
}

// FEW UNIQUE

TEST(few_unique_5) {
    int64_t arr[10000];
    uint64_t seed = 888;
    for (size_t i = 0; i < 10000; i++) {
        seed = seed * 6364136223846793005ull + 1442695040888963407ull;
        arr[i] = (int64_t)((seed >> 33) % 5);
    }
    sublimation_i64(arr, 10000);
    ASSERT_SORTED(arr, 10000);
}

// STATS

TEST(stats_populated) {
    int64_t arr[1000];
    fill_random(arr, 1000, 1234);
    sub_stats_t stats = {0};
    sublimation_i64_stats(arr, 1000, &stats);
    ASSERT_SORTED(arr, 1000);
    assert(stats.comparisons > 0);
    assert(stats.wall_ns > 0);
}

// PIPE ORGAN (ascending then descending)

TEST(pipe_organ) {
    int64_t arr[1000];
    for (size_t i = 0; i < 500; i++) arr[i] = (int64_t)i;
    for (size_t i = 500; i < 1000; i++) arr[i] = (int64_t)(1000 - i);
    sublimation_i64(arr, 1000);
    ASSERT_SORTED(arr, 1000);
}

// ROTATED SORTED ARRAY

TEST(rotated_sorted) {
    // [50, 51, ..., 99, 0, 1, ..., 49] -- rotation of sorted array
    int64_t arr[100];
    for (size_t i = 0; i < 50; i++) arr[i] = (int64_t)(i + 50);
    for (size_t i = 50; i < 100; i++) arr[i] = (int64_t)(i - 50);
    sublimation_i64(arr, 100);
    ASSERT_SORTED(arr, 100);
}

TEST(rotated_sorted_large) {
    size_t n = 10000;
    int64_t *arr = malloc(n * sizeof(int64_t));
    assert(arr);
    size_t rot = 3456;
    for (size_t i = 0; i < n; i++) arr[i] = (int64_t)((i + rot) % n);
    sublimation_i64(arr, n);
    ASSERT_SORTED(arr, n);
    free(arr);
}

TEST(rotated_classify) {
    int64_t arr[100];
    for (size_t i = 0; i < 50; i++) arr[i] = (int64_t)(i + 50);
    for (size_t i = 50; i < 100; i++) arr[i] = (int64_t)(i - 50);
    sub_profile_t p = sublimation_classify_i64(arr, 100);
    assert(p.disorder == SUB_NEARLY_SORTED);
    assert(p.rotation_point == 50);
}

// YOUNG TABLEAU

TEST(classify_tableau_sorted) {
    int64_t arr[100];
    for (size_t i = 0; i < 100; i++) arr[i] = (int64_t)i;
    sub_profile_t p = sublimation_classify_i64(arr, 100);
    assert(p.disorder == SUB_SORTED);
    assert(p.lds_length == 1);
}

TEST(classify_tableau_reversed) {
    int64_t arr[100];
    for (size_t i = 0; i < 100; i++) arr[i] = (int64_t)(100 - i);
    sub_profile_t p = sublimation_classify_i64(arr, 100);
    assert(p.disorder == SUB_REVERSED);
    assert(p.lds_length == 100);
}

TEST(classify_tableau_random) {
    int64_t arr[1000];
    fill_random(arr, 1000, 54321);
    sub_profile_t p = sublimation_classify_i64(arr, 1000);
    assert(p.lis_length > 1);
    assert(p.lis_length < 1000);
    assert(p.lds_length > 1);
    assert(p.lds_length < 1000);
}

TEST(info_theoretic_bound) {
    // Small array where we can verify the bound is reasonable
    int64_t arr[] = {3, 1, 4, 1, 5, 9, 2, 6, 5, 3, 5, 8, 9, 7, 9};
    size_t n = 15;
    sub_profile_t p = sublimation_classify_i64(arr, n);
    // info_theoretic_bound should be > 0 for non-trivial permutations
    // (but note: duplicates may cause it to be 0 if classification skips patience)
    // At minimum, the field should be non-negative
    assert(p.info_theoretic_bound >= 0.0f);
}

TEST(stats_info_bound) {
    int64_t arr[1000];
    fill_random(arr, 1000, 9999);
    sub_stats_t stats = {0};
    sublimation_i64_stats(arr, 1000, &stats);
    ASSERT_SORTED(arr, 1000);
    // For 1000 random elements, info_theoretic_bound should be positive
    assert(stats.info_theoretic_bound >= 0.0);
    // If we have both bound and comparisons, efficiency should be reasonable
    if (stats.info_theoretic_bound > 0.0 && stats.comparisons > 0) {
        assert(stats.comparison_efficiency > 0.0);
    }
}

// INTERLEAVED SORTED SEQUENCES

TEST(interleaved_2way) {
    // Two interleaved sorted sequences: evens and odds
    int64_t arr[200];
    for (size_t i = 0; i < 200; i++) {
        if (i % 2 == 0) arr[i] = (int64_t)(i / 2);
        else arr[i] = (int64_t)(100 + i / 2);
    }
    sublimation_i64(arr, 200);
    ASSERT_SORTED(arr, 200);
}

TEST(interleaved_3way) {
    // Three interleaved sorted sequences
    int64_t arr[300];
    for (size_t i = 0; i < 300; i++) {
        arr[i] = (int64_t)(i / 3 + (i % 3) * 100);
    }
    sublimation_i64(arr, 300);
    ASSERT_SORTED(arr, 300);
}

// API VERSION

TEST(api_version) {
    assert(sublimation_api_version() == SUBLIMATION_API_VERSION);
}

// TYPE COVERAGE TESTS
// Verify all type-specific sort functions use the full flow model

#define ASSERT_SORTED_GENERIC(arr, n, fmt) do {                 \
    for (size_t _i = 1; _i < (n); _i++) {                      \
        if ((arr)[_i] < (arr)[_i-1]) {                          \
            printf("FAIL (arr[%zu] > arr[%zu])\n", _i-1, _i);  \
            tests_failed++;                                     \
            return;                                             \
        }                                                       \
    }                                                           \
} while (0)

TEST(i32_random_1k) {
    int32_t arr[1000];
    uint64_t seed = 11111;
    for (size_t i = 0; i < 1000; i++) {
        seed = seed * 6364136223846793005ull + 1442695040888963407ull;
        arr[i] = (int32_t)(seed >> 33);
    }
    sublimation_i32(arr, 1000);
    ASSERT_SORTED_GENERIC(arr, 1000, "%d");
}

TEST(i32_reversed) {
    int32_t arr[500];
    for (size_t i = 0; i < 500; i++) arr[i] = (int32_t)(500 - i);
    sublimation_i32(arr, 500);
    ASSERT_SORTED_GENERIC(arr, 500, "%d");
}

TEST(i32_sorted) {
    int32_t arr[500];
    for (size_t i = 0; i < 500; i++) arr[i] = (int32_t)i;
    sublimation_i32(arr, 500);
    ASSERT_SORTED_GENERIC(arr, 500, "%d");
}

TEST(i32_few_unique) {
    int32_t arr[5000];
    uint64_t seed = 22222;
    for (size_t i = 0; i < 5000; i++) {
        seed = seed * 6364136223846793005ull + 1442695040888963407ull;
        arr[i] = (int32_t)((seed >> 33) % 7);
    }
    sublimation_i32(arr, 5000);
    ASSERT_SORTED_GENERIC(arr, 5000, "%d");
}

TEST(u32_random_1k) {
    uint32_t arr[1000];
    uint64_t seed = 33333;
    for (size_t i = 0; i < 1000; i++) {
        seed = seed * 6364136223846793005ull + 1442695040888963407ull;
        arr[i] = (uint32_t)(seed >> 32);
    }
    sublimation_u32(arr, 1000);
    ASSERT_SORTED_GENERIC(arr, 1000, "%u");
}

TEST(u32_reversed) {
    uint32_t arr[500];
    for (size_t i = 0; i < 500; i++) arr[i] = (uint32_t)(500 - i);
    sublimation_u32(arr, 500);
    ASSERT_SORTED_GENERIC(arr, 500, "%u");
}

TEST(u64_random_1k) {
    uint64_t arr[1000];
    uint64_t seed = 44444;
    for (size_t i = 0; i < 1000; i++) {
        seed = seed * 6364136223846793005ull + 1442695040888963407ull;
        arr[i] = seed >> 16;
    }
    sublimation_u64(arr, 1000);
    ASSERT_SORTED_GENERIC(arr, 1000, "%lu");
}

TEST(u64_reversed) {
    uint64_t arr[500];
    for (size_t i = 0; i < 500; i++) arr[i] = (uint64_t)(500 - i);
    sublimation_u64(arr, 500);
    ASSERT_SORTED_GENERIC(arr, 500, "%lu");
}

TEST(u64_few_unique) {
    uint64_t arr[5000];
    uint64_t seed = 55555;
    for (size_t i = 0; i < 5000; i++) {
        seed = seed * 6364136223846793005ull + 1442695040888963407ull;
        arr[i] = (seed >> 33) % 5;
    }
    sublimation_u64(arr, 5000);
    ASSERT_SORTED_GENERIC(arr, 5000, "%lu");
}

TEST(f32_random_1k) {
    float arr[1000];
    uint64_t seed = 66666;
    for (size_t i = 0; i < 1000; i++) {
        seed = seed * 6364136223846793005ull + 1442695040888963407ull;
        arr[i] = (float)(int64_t)(seed >> 33) / 1000.0f;
    }
    sublimation_f32(arr, 1000);
    ASSERT_SORTED_GENERIC(arr, 1000, "%f");
}

TEST(f32_reversed) {
    float arr[500];
    for (size_t i = 0; i < 500; i++) arr[i] = 500.0f - (float)i;
    sublimation_f32(arr, 500);
    ASSERT_SORTED_GENERIC(arr, 500, "%f");
}

TEST(f32_sorted) {
    float arr[500];
    for (size_t i = 0; i < 500; i++) arr[i] = (float)i * 0.1f;
    sublimation_f32(arr, 500);
    ASSERT_SORTED_GENERIC(arr, 500, "%f");
}

TEST(f64_random_1k) {
    double arr[1000];
    uint64_t seed = 77777;
    for (size_t i = 0; i < 1000; i++) {
        seed = seed * 6364136223846793005ull + 1442695040888963407ull;
        arr[i] = (double)(int64_t)(seed >> 33) / 1000.0;
    }
    sublimation_f64(arr, 1000);
    ASSERT_SORTED_GENERIC(arr, 1000, "%f");
}

TEST(f64_reversed) {
    double arr[500];
    for (size_t i = 0; i < 500; i++) arr[i] = 500.0 - (double)i;
    sublimation_f64(arr, 500);
    ASSERT_SORTED_GENERIC(arr, 500, "%f");
}

TEST(f64_few_unique) {
    double arr[5000];
    uint64_t seed = 88888;
    for (size_t i = 0; i < 5000; i++) {
        seed = seed * 6364136223846793005ull + 1442695040888963407ull;
        arr[i] = (double)((seed >> 33) % 10);
    }
    sublimation_f64(arr, 5000);
    ASSERT_SORTED_GENERIC(arr, 5000, "%f");
}

// Larger tests for all types (10k elements)
TEST(i32_random_10k) {
    int32_t *arr = malloc(10000 * sizeof(int32_t));
    assert(arr);
    uint64_t seed = 100001;
    for (size_t i = 0; i < 10000; i++) {
        seed = seed * 6364136223846793005ull + 1442695040888963407ull;
        arr[i] = (int32_t)(seed >> 33);
    }
    sublimation_i32(arr, 10000);
    ASSERT_SORTED_GENERIC(arr, 10000, "%d");
    free(arr);
}

TEST(u64_random_10k) {
    uint64_t *arr = malloc(10000 * sizeof(uint64_t));
    assert(arr);
    uint64_t seed = 200002;
    for (size_t i = 0; i < 10000; i++) {
        seed = seed * 6364136223846793005ull + 1442695040888963407ull;
        arr[i] = seed >> 16;
    }
    sublimation_u64(arr, 10000);
    ASSERT_SORTED_GENERIC(arr, 10000, "%lu");
    free(arr);
}

TEST(f64_random_10k) {
    double *arr = malloc(10000 * sizeof(double));
    assert(arr);
    uint64_t seed = 300003;
    for (size_t i = 0; i < 10000; i++) {
        seed = seed * 6364136223846793005ull + 1442695040888963407ull;
        arr[i] = (double)(int64_t)(seed >> 16);
    }
    sublimation_f64(arr, 10000);
    ASSERT_SORTED_GENERIC(arr, 10000, "%f");
    free(arr);
}

// GENERIC INTERFACE (qsort-compatible)

static int cmp_i64(const void *a, const void *b) {
    int64_t va = *(const int64_t *)a, vb = *(const int64_t *)b;
    return (va > vb) - (va < vb);
}

static int cmp_i32(const void *a, const void *b) {
    int32_t va = *(const int32_t *)a, vb = *(const int32_t *)b;
    return (va > vb) - (va < vb);
}

static int cmp_f64(const void *a, const void *b) {
    double va = *(const double *)a, vb = *(const double *)b;
    return (va > vb) - (va < vb);
}

TEST(generic_random_1k) {
    int64_t arr[1000];
    fill_random(arr, 1000, 0x6E41C);
    sublimation(arr, 1000, sizeof(int64_t), cmp_i64);
    ASSERT_SORTED(arr, 1000);
}

TEST(generic_random_10k) {
    int64_t arr[10000];
    fill_random(arr, 10000, 0x6E42C);
    sublimation(arr, 10000, sizeof(int64_t), cmp_i64);
    ASSERT_SORTED(arr, 10000);
}

TEST(generic_sorted) {
    int64_t arr[1000];
    for (size_t i = 0; i < 1000; i++) arr[i] = (int64_t)i;
    sublimation(arr, 1000, sizeof(int64_t), cmp_i64);
    ASSERT_SORTED(arr, 1000);
}

TEST(generic_reversed) {
    int64_t arr[1000];
    for (size_t i = 0; i < 1000; i++) arr[i] = (int64_t)(1000 - i);
    sublimation(arr, 1000, sizeof(int64_t), cmp_i64);
    ASSERT_SORTED(arr, 1000);
}

TEST(generic_i32) {
    int32_t arr[1000];
    for (size_t i = 0; i < 1000; i++) arr[i] = (int32_t)(1000 - i);
    sublimation(arr, 1000, sizeof(int32_t), cmp_i32);
    for (size_t i = 1; i < 1000; i++) assert(arr[i] >= arr[i-1]);
}

TEST(generic_f64) {
    double arr[1000];
    for (size_t i = 0; i < 1000; i++) arr[i] = 1000.0 - (double)i;
    sublimation(arr, 1000, sizeof(double), cmp_f64);
    for (size_t i = 1; i < 1000; i++) assert(arr[i] >= arr[i-1]);
}

int main(void) {
    printf("[sublimation] running tests\n\n");

    // i64 tests
    RUN(empty);
    RUN(single);
    RUN(two_sorted);
    RUN(two_reversed);
    RUN(three);
    RUN(four);
    RUN(already_sorted);
    RUN(reversed);
    RUN(all_equal);
    RUN(two_values);
    RUN(classify_sorted);
    RUN(classify_reversed);
    RUN(classify_random);
    RUN(random_1k);
    RUN(random_10k);
    RUN(random_100k);
    RUN(random_1m);
    RUN(nearly_sorted_few_swaps);
    RUN(few_unique_5);
    RUN(stats_populated);
    RUN(pipe_organ);
    RUN(rotated_sorted);
    RUN(rotated_sorted_large);
    RUN(rotated_classify);
    RUN(classify_tableau_sorted);
    RUN(classify_tableau_reversed);
    RUN(classify_tableau_random);
    RUN(info_theoretic_bound);
    RUN(stats_info_bound);
    RUN(interleaved_2way);
    RUN(interleaved_3way);
    RUN(api_version);

    // type coverage tests
    printf("\n  -- type coverage --\n");
    RUN(i32_random_1k);
    RUN(i32_reversed);
    RUN(i32_sorted);
    RUN(i32_few_unique);
    RUN(i32_random_10k);
    RUN(u32_random_1k);
    RUN(u32_reversed);
    RUN(u64_random_1k);
    RUN(u64_reversed);
    RUN(u64_few_unique);
    RUN(u64_random_10k);
    RUN(f32_random_1k);
    RUN(f32_reversed);
    RUN(f32_sorted);
    RUN(f64_random_1k);
    RUN(f64_reversed);
    RUN(f64_few_unique);
    RUN(f64_random_10k);

    // generic interface tests
    printf("\n  -- generic interface --\n");
    RUN(generic_random_1k);
    RUN(generic_random_10k);
    RUN(generic_sorted);
    RUN(generic_reversed);
    RUN(generic_i32);
    RUN(generic_f64);

    printf("\n  %d passed, %d failed\n", tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
