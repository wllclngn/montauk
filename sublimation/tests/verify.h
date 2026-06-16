// verify.h -- Property-based sort verification harness (type-generic)
//
// Every sort result MUST pass these checks:
//   1. Output is sorted (monotonically non-decreasing)
//   2. Output is a permutation of input (same multiset)
//   3. Element count preserved
//
// Usage (i64, legacy):
//   int64_t *input_copy = verify_save(arr, n);
//   sublimation_i64(arr, n);
//   verify_sorted(arr, n, "test_name");
//   verify_permutation(arr, input_copy, n, "test_name");
//   free(input_copy);
//
// Usage (any type):
//   VERIFY_SORT_TYPED(int32_t, i32, arr, n, sublimation_i32, "test_name");
#ifndef SUB_VERIFY_H
#define SUB_VERIFY_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <math.h>

static int _verify_pass = 0;
static int _verify_fail = 0;

// ============================================================
// TYPE-GENERIC VERIFICATION (macro-generated per type)
// ============================================================

#define VERIFY_DEFINE_TYPE(T, FMT, SUFFIX)                                     \
                                                                               \
static T *_verify_saved_##SUFFIX = NULL;                                       \
                                                                               \
static void verify_save_##SUFFIX(const T *arr, size_t n) {                     \
    _verify_saved_##SUFFIX = (T *)malloc(n * sizeof(T));                       \
    if (_verify_saved_##SUFFIX)                                                \
        memcpy(_verify_saved_##SUFFIX, arr, n * sizeof(T));                    \
}                                                                              \
                                                                               \
static int _cmp_##SUFFIX(const void *a, const void *b) {                       \
    T va = *(const T *)a, vb = *(const T *)b;                                 \
    return (va > vb) - (va < vb);                                              \
}                                                                              \
                                                                               \
static bool verify_sorted_##SUFFIX(const T *arr, size_t n, const char *name) { \
    for (size_t i = 1; i < n; i++) {                                           \
        if (arr[i] < arr[i - 1]) {                                             \
            fprintf(stderr, "  [FAIL] %s: not sorted at [%zu]: "               \
                    FMT " > " FMT "\n", name, i - 1, arr[i - 1], arr[i]);     \
            _verify_fail++;                                                    \
            return false;                                                      \
        }                                                                      \
    }                                                                          \
    _verify_pass++;                                                            \
    return true;                                                               \
}                                                                              \
                                                                               \
static bool verify_permutation_##SUFFIX(const T *sorted_arr,                   \
                                        const T *saved, size_t n,              \
                                        const char *name) {                    \
    T *a = (T *)malloc(n * sizeof(T));                                         \
    T *b = (T *)malloc(n * sizeof(T));                                         \
    memcpy(a, sorted_arr, n * sizeof(T));                                      \
    memcpy(b, saved, n * sizeof(T));                                           \
    qsort(a, n, sizeof(T), _cmp_##SUFFIX);                                    \
    qsort(b, n, sizeof(T), _cmp_##SUFFIX);                                    \
    bool ok = (memcmp(a, b, n * sizeof(T)) == 0);                             \
    free(a);                                                                   \
    free(b);                                                                   \
    if (ok) _verify_pass++;                                                    \
    else {                                                                     \
        fprintf(stderr, "  [FAIL] %s: not a permutation\n", name);             \
        _verify_fail++;                                                        \
    }                                                                          \
    return ok;                                                                 \
}                                                                              \
                                                                               \
static void verify_fill_random_##SUFFIX(T *arr, size_t n, uint64_t seed) {     \
    for (size_t i = 0; i < n; i++) {                                           \
        seed = seed * 6364136223846793005ull + 1442695040888963407ull;          \
        arr[i] = (T)(seed >> 16);                                              \
    }                                                                          \
}

// Instantiate for all 6 types
VERIFY_DEFINE_TYPE(int32_t,  "%d",  i32)
VERIFY_DEFINE_TYPE(int64_t,  "%ld", i64)
VERIFY_DEFINE_TYPE(uint32_t, "%u",  u32)
VERIFY_DEFINE_TYPE(uint64_t, "%lu", u64)
VERIFY_DEFINE_TYPE(float,    "%f",  f32)
VERIFY_DEFINE_TYPE(double,   "%f",  f64)

// ============================================================
// CONVENIENCE MACROS
// ============================================================

// Full save-sort-verify-free cycle for any type
// NOTE: name can be a string literal OR a char[] variable.
#define VERIFY_SORT_TYPED(T, SUFFIX, arr, n, sort_fn, name) do {               \
    verify_save_##SUFFIX(arr, n);                                              \
    sort_fn(arr, n);                                                           \
    verify_sorted_##SUFFIX(arr, n, name);                                      \
    verify_permutation_##SUFFIX(arr, _verify_saved_##SUFFIX, n, name);         \
    free(_verify_saved_##SUFFIX);                                              \
    _verify_saved_##SUFFIX = NULL;                                             \
} while (0)

// ============================================================
// LEGACY i64 API (backward compatible with existing tests)
// ============================================================

// save a copy of the input before sorting
static int64_t *verify_save(const int64_t *arr, size_t n) {
    int64_t *copy = (int64_t *)malloc(n * sizeof(int64_t));
    if (copy) memcpy(copy, arr, n * sizeof(int64_t));
    return copy;
}

// check: output is sorted
static int verify_sorted(const int64_t *arr, size_t n, const char *name) {
    for (size_t i = 1; i < n; i++) {
        if (arr[i] < arr[i - 1]) {
            fprintf(stderr, "  [FAIL] %s: not sorted at [%zu]: %ld > %ld\n",
                    name, i - 1, (long)arr[i - 1], (long)arr[i]);
            _verify_fail++;
            return 0;
        }
    }
    return 1;
}

static int _verify_cmp_i64(const void *a, const void *b) {
    int64_t va = *(const int64_t *)a, vb = *(const int64_t *)b;
    return (va > vb) - (va < vb);
}

// check: output is permutation of input (same multiset)
// sorts both copies and compares element-by-element
static int verify_permutation(const int64_t *sorted_arr, int64_t *saved_input,
                               size_t n, const char *name) {
    qsort(saved_input, n, sizeof(int64_t), _verify_cmp_i64);

    for (size_t i = 0; i < n; i++) {
        if (sorted_arr[i] != saved_input[i]) {
            fprintf(stderr, "  [FAIL] %s: not a permutation at [%zu]: "
                    "got %ld, expected %ld\n",
                    name, i, (long)sorted_arr[i], (long)saved_input[i]);
            _verify_fail++;
            return 0;
        }
    }
    return 1;
}

// full verification: sorted + permutation
static int verify_sort(int64_t *arr, int64_t *saved, size_t n, const char *name) {
    int ok = 1;
    if (!verify_sorted(arr, n, name)) ok = 0;
    if (saved && !verify_permutation(arr, saved, n, name)) ok = 0;
    if (ok) {
        printf("  %-50s PASS\n", name);
        _verify_pass++;
    }
    return ok;
}

// convenience: save, sort, verify, free
#define VERIFY_SORT(arr, n, sort_fn, name) do { \
    int64_t *_saved = verify_save(arr, n);       \
    sort_fn(arr, n);                              \
    verify_sort(arr, _saved, n, name);            \
    free(_saved);                                 \
} while (0)

// print summary
static int verify_summary(void) {
    printf("\n  %d passed, %d failed\n", _verify_pass, _verify_fail);
    return _verify_fail > 0 ? 1 : 0;
}

// deterministic RNG (legacy i64)
static void verify_fill_random(int64_t *arr, size_t n, uint64_t seed) {
    for (size_t i = 0; i < n; i++) {
        seed = seed * 6364136223846793005ull + 1442695040888963407ull;
        arr[i] = (int64_t)(seed >> 16);
    }
}

#endif // SUB_VERIFY_H
