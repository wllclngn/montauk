// fuzz_sort.c -- Differential fuzzer: sublimation vs qsort for all 6 types
//
// Build: clang -std=c2x -O2 -fsanitize=fuzzer -I src/include -I src
//        tests/fuzz_sort.c -L build -lsublimation -lpthread -lm -o build/fuzz_sort
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "../src/include/sublimation.h"

static int cmp_i32(const void *a, const void *b) {
    int32_t va = *(const int32_t *)a, vb = *(const int32_t *)b;
    return (va > vb) - (va < vb);
}
static int cmp_i64(const void *a, const void *b) {
    int64_t va = *(const int64_t *)a, vb = *(const int64_t *)b;
    return (va > vb) - (va < vb);
}
static int cmp_u32(const void *a, const void *b) {
    uint32_t va = *(const uint32_t *)a, vb = *(const uint32_t *)b;
    return (va > vb) - (va < vb);
}
static int cmp_u64(const void *a, const void *b) {
    uint64_t va = *(const uint64_t *)a, vb = *(const uint64_t *)b;
    return (va > vb) - (va < vb);
}
static int cmp_f32(const void *a, const void *b) {
    float va = *(const float *)a, vb = *(const float *)b;
    if (va < vb) return -1;
    if (va > vb) return 1;
    return 0;
}
static int cmp_f64(const void *a, const void *b) {
    double va = *(const double *)a, vb = *(const double *)b;
    if (va < vb) return -1;
    if (va > vb) return 1;
    return 0;
}

// Integer types: differential (must match qsort byte-for-byte)
#define FUZZ_DIFF(T, suffix, cmp_fn, max_n)                          \
do {                                                                 \
    size_t n = size / sizeof(T);                                     \
    if (n < 1 || n > (max_n)) break;                                 \
    T *a = malloc(n * sizeof(T));                                    \
    T *b = malloc(n * sizeof(T));                                    \
    if (!a || !b) { free(a); free(b); break; }                       \
    memcpy(a, data, n * sizeof(T));                                  \
    memcpy(b, data, n * sizeof(T));                                  \
    sublimation_##suffix(a, n);                                      \
    qsort(b, n, sizeof(T), cmp_fn);                                  \
    for (size_t i = 0; i < n; i++) {                                 \
        if (memcmp(&a[i], &b[i], sizeof(T)) != 0) __builtin_trap(); \
    }                                                                \
    free(a);                                                         \
    free(b);                                                         \
} while (0)

// Float types: verify sorted property (NaN makes qsort comparison unreliable)
#define FUZZ_SORTED(T, suffix, max_n)                                \
do {                                                                 \
    size_t n = size / sizeof(T);                                     \
    if (n < 1 || n > (max_n)) break;                                 \
    T *a = malloc(n * sizeof(T));                                    \
    if (!a) break;                                                   \
    memcpy(a, data, n * sizeof(T));                                  \
    sublimation_##suffix(a, n);                                      \
    for (size_t i = 1; i < n; i++) {                                 \
        if (a[i] < a[i-1]) __builtin_trap();                         \
    }                                                                \
    free(a);                                                         \
} while (0)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) return 0;

    // First byte selects type, rest is data
    uint8_t type_sel = data[0] % 6;
    data++;
    size--;

    switch (type_sel) {
    case 0: FUZZ_DIFF(int32_t,  i32, cmp_i32, 100000); break;
    case 1: FUZZ_DIFF(int64_t,  i64, cmp_i64, 100000); break;
    case 2: FUZZ_DIFF(uint32_t, u32, cmp_u32, 100000); break;
    case 3: FUZZ_DIFF(uint64_t, u64, cmp_u64, 100000); break;
    case 4: FUZZ_SORTED(float,  f32, 100000); break;
    case 5: FUZZ_SORTED(double, f64, 100000); break;
    }

    return 0;
}
