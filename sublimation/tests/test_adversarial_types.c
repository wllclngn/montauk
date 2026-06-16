// test_adversarial_types.c -- Multi-type adversarial pattern testing
//
// Runs 5 key adversarial patterns across all 6 numeric types at n=1000,10000.
// Each result is property-verified: sorted + permutation.
//
// Patterns selected:
//   1. pipe_organ_nested   -- pivot killer (nested V-shapes)
//   2. median_of_three_killer -- anti-quicksort (Musser sequence)
//   3. interleaved_sorted  -- merge pathology (maximum merge cost)
//   4. zipfian             -- power-law distribution
//   5. all_equal_except_endpoints -- stability stress (two displaced elements)
#include "../src/include/sublimation.h"
#include "verify.h"
#include <assert.h>
#include <limits.h>
#include <float.h>
#include <math.h>

static const size_t SIZES[] = {1000, 10000};
#define NUM_SIZES 2

// Deterministic LCG
static uint64_t _at_lcg_state;
static void at_lcg_seed(uint64_t s) { _at_lcg_state = s; }
static uint64_t at_lcg_next(void) {
    _at_lcg_state = _at_lcg_state * 6364136223846793005ull + 1442695040888963407ull;
    return _at_lcg_state;
}

// ============================================================
// PATTERN FILL FUNCTIONS (generic via macro)
// ============================================================

#define DEFINE_ADVERSARIAL_PATTERNS(T, SUFFIX, sort_fn, T_MAX, T_MIN)          \
                                                                               \
static void fill_pipe_organ_nested_##SUFFIX(T *arr, size_t n) {                \
    size_t seg = n / 4;                                                        \
    for (size_t s = 0; s < 4; s++) {                                           \
        size_t base = s * seg;                                                 \
        size_t len = (s == 3) ? (n - base) : seg;                              \
        size_t half = len / 2;                                                 \
        for (size_t i = 0; i < half; i++)                                      \
            arr[base + i] = (T)i;                                              \
        for (size_t i = half; i < len; i++)                                    \
            arr[base + i] = (T)(len - 1 - i);                                 \
    }                                                                          \
}                                                                              \
                                                                               \
static void fill_median_of_three_killer_##SUFFIX(T *arr, size_t n) {           \
    for (size_t i = 0; i < n; i++)                                             \
        arr[i] = (T)i;                                                         \
    for (size_t i = n; i >= 3; i--) {                                          \
        T tmp = arr[i - 1];                                                    \
        arr[i - 1] = arr[(i - 1) / 2];                                        \
        arr[(i - 1) / 2] = tmp;                                               \
    }                                                                          \
}                                                                              \
                                                                               \
static void fill_interleaved_sorted_##SUFFIX(T *arr, size_t n) {              \
    size_t half = n / 2;                                                       \
    for (size_t i = 0; i < n; i++) {                                           \
        if (i % 2 == 0)                                                        \
            arr[i] = (T)(i / 2);                                               \
        else                                                                   \
            arr[i] = (T)(half + i / 2);                                        \
    }                                                                          \
}                                                                              \
                                                                               \
static void fill_zipfian_##SUFFIX(T *arr, size_t n) {                          \
    for (size_t i = 0; i < n; i++) {                                           \
        uint64_t rank = (at_lcg_next() >> 16) % n;                            \
        arr[i] = (T)(n / (rank + 1));                                          \
    }                                                                          \
}                                                                              \
                                                                               \
static void fill_all_equal_except_endpoints_##SUFFIX(T *arr, size_t n) {       \
    for (size_t i = 0; i < n; i++)                                             \
        arr[i] = (T)0;                                                         \
    if (n >= 1) arr[0] = T_MAX;                                                \
    if (n >= 2) arr[n - 1] = T_MIN;                                           \
}                                                                              \
                                                                               \
typedef void (*fill_fn_##SUFFIX)(T *, size_t);                                 \
                                                                               \
static void run_pattern_##SUFFIX(const char *pattern_name,                     \
                                  fill_fn_##SUFFIX filler) {                   \
    for (int si = 0; si < NUM_SIZES; si++) {                                   \
        size_t n = SIZES[si];                                                  \
        char name[128];                                                        \
        snprintf(name, sizeof(name), "%s/" #SUFFIX " (n=%zu)",                \
                 pattern_name, n);                                             \
                                                                               \
        T *arr = (T *)malloc(n * sizeof(T));                                   \
        assert(arr && "malloc failed");                                        \
                                                                               \
        at_lcg_seed(0xAD0E5A41A1ull ^ (uint64_t)n);                           \
        filler(arr, n);                                                        \
                                                                               \
        VERIFY_SORT_TYPED(T, SUFFIX, arr, n, sort_fn, name);                  \
        printf("  %-50s PASS\n", name);                                        \
        free(arr);                                                             \
    }                                                                          \
}                                                                              \
                                                                               \
static void run_all_adversarial_##SUFFIX(void) {                               \
    printf("\n  -- " #SUFFIX " adversarial patterns --\n");                    \
    run_pattern_##SUFFIX("pipe_organ_nested",                                  \
                         fill_pipe_organ_nested_##SUFFIX);                     \
    run_pattern_##SUFFIX("median_of_three_killer",                             \
                         fill_median_of_three_killer_##SUFFIX);                \
    run_pattern_##SUFFIX("interleaved_sorted",                                 \
                         fill_interleaved_sorted_##SUFFIX);                    \
    run_pattern_##SUFFIX("zipfian",                                            \
                         fill_zipfian_##SUFFIX);                               \
    run_pattern_##SUFFIX("all_equal_except_endpoints",                         \
                         fill_all_equal_except_endpoints_##SUFFIX);            \
}

// For float endpoints, we use large finite values rather than INF
// to keep the permutation check working with the comparison function.
DEFINE_ADVERSARIAL_PATTERNS(int32_t,  i32, sublimation_i32,
                            (int32_t)INT32_MAX, (int32_t)INT32_MIN)
DEFINE_ADVERSARIAL_PATTERNS(int64_t,  i64, sublimation_i64,
                            (int64_t)INT64_MAX, (int64_t)INT64_MIN)
DEFINE_ADVERSARIAL_PATTERNS(uint32_t, u32, sublimation_u32,
                            (uint32_t)UINT32_MAX, (uint32_t)0)
DEFINE_ADVERSARIAL_PATTERNS(uint64_t, u64, sublimation_u64,
                            (uint64_t)UINT64_MAX, (uint64_t)0)
DEFINE_ADVERSARIAL_PATTERNS(float,    f32, sublimation_f32,
                            (float)FLT_MAX, (float)(-FLT_MAX))
DEFINE_ADVERSARIAL_PATTERNS(double,   f64, sublimation_f64,
                            (double)DBL_MAX, (double)(-DBL_MAX))

// ============================================================
// MAIN
// ============================================================

int main(void) {
    printf("[sublimation] Multi-type adversarial pattern testing\n");

    run_all_adversarial_i32();
    run_all_adversarial_i64();
    run_all_adversarial_u32();
    run_all_adversarial_u64();
    run_all_adversarial_f32();
    run_all_adversarial_f64();

    printf("\n  adversarial_types: %d passed, %d failed\n",
           _verify_pass, _verify_fail);
    return _verify_fail > 0 ? 1 : 0;
}
