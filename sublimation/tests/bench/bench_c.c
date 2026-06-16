// bench_c.c -- Benchmark: sublimation vs qsort for ALL 6 numeric types
//
// Protocol: argv[1]=size argv[2]=pattern argv[3]=runs
// Output: one JSON line per (type, algorithm) pair with ns_per_element
#define _POSIX_C_SOURCE 199309L
#include "../../src/include/sublimation.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <math.h>

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

// ============================================================
// LCG
// ============================================================

static uint64_t _bench_lcg_state;
static void bench_lcg_seed(uint64_t s) { _bench_lcg_state = s; }
static uint64_t bench_lcg_next(void) {
    _bench_lcg_state = _bench_lcg_state * 6364136223846793005ull
                     + 1442695040888963407ull;
    return _bench_lcg_state;
}

// ============================================================
// PATTERN FILL (macro-generated per type)
// ============================================================

#define DEFINE_FILL(T, SUFFIX)                                                 \
                                                                               \
static void fill_random_##SUFFIX(T *arr, size_t n, uint64_t seed) {            \
    bench_lcg_seed(seed);                                                      \
    for (size_t i = 0; i < n; i++)                                             \
        arr[i] = (T)(bench_lcg_next() >> 16);                                 \
}                                                                              \
                                                                               \
static void fill_sorted_##SUFFIX(T *arr, size_t n) {                           \
    for (size_t i = 0; i < n; i++) arr[i] = (T)i;                             \
}                                                                              \
                                                                               \
static void fill_reversed_##SUFFIX(T *arr, size_t n) {                         \
    for (size_t i = 0; i < n; i++) arr[i] = (T)(n - i);                       \
}                                                                              \
                                                                               \
static void fill_nearly_sorted_##SUFFIX(T *arr, size_t n, uint64_t seed) {     \
    fill_sorted_##SUFFIX(arr, n);                                              \
    size_t swaps = n / 100;                                                    \
    if (swaps < 2) swaps = 2;                                                  \
    bench_lcg_seed(seed);                                                      \
    for (size_t k = 0; k < swaps; k++) {                                       \
        size_t i = (size_t)(bench_lcg_next() >> 33) % n;                       \
        size_t j = (size_t)(bench_lcg_next() >> 33) % n;                       \
        T tmp = arr[i]; arr[i] = arr[j]; arr[j] = tmp;                        \
    }                                                                          \
}                                                                              \
                                                                               \
static void fill_few_unique_##SUFFIX(T *arr, size_t n, uint64_t seed) {        \
    bench_lcg_seed(seed);                                                      \
    for (size_t i = 0; i < n; i++)                                             \
        arr[i] = (T)((bench_lcg_next() >> 33) % 5);                           \
}                                                                              \
                                                                               \
static void fill_pipe_organ_##SUFFIX(T *arr, size_t n) {                       \
    size_t half = n / 2;                                                       \
    for (size_t i = 0; i < half; i++) arr[i] = (T)i;                           \
    for (size_t i = half; i < n; i++) arr[i] = (T)(n - i);                    \
}                                                                              \
                                                                               \
static void fill_equal_##SUFFIX(T *arr, size_t n) {                            \
    for (size_t i = 0; i < n; i++) arr[i] = (T)42;                            \
}                                                                              \
                                                                               \
static void fill_zipfian_##SUFFIX(T *arr, size_t n, uint64_t seed) {           \
    /* Zipfian via inverse-CDF over R = max(16, n/4) ranks, s = 1.07. */       \
    bench_lcg_seed(seed);                                                      \
    size_t R = n / 4;                                                          \
    if (R < 16) R = 16;                                                        \
    double *cdf = (double *)malloc(R * sizeof(double));                        \
    if (!cdf) { fill_random_##SUFFIX(arr, n, seed); return; }                  \
    double total = 0.0;                                                        \
    for (size_t k = 0; k < R; k++) {                                           \
        total += 1.0 / pow((double)(k + 1), 1.07);                             \
        cdf[k] = total;                                                        \
    }                                                                          \
    for (size_t k = 0; k < R; k++) cdf[k] /= total;                            \
    for (size_t i = 0; i < n; i++) {                                           \
        double u = (double)(bench_lcg_next() >> 11) * (1.0 / 9007199254740992.0);\
        size_t lo = 0, hi = R;                                                 \
        while (lo < hi) {                                                      \
            size_t mid = lo + (hi - lo) / 2;                                   \
            if (cdf[mid] < u) lo = mid + 1; else hi = mid;                     \
        }                                                                      \
        arr[i] = (T)((int64_t)lo * (int64_t)lo + (int64_t)lo);                 \
    }                                                                          \
    free(cdf);                                                                 \
}                                                                              \
                                                                               \
static void fill_sorted_perturbed_##SUFFIX(T *arr, size_t n, uint64_t seed) {  \
    /* Sorted ascending, then k = max(2, n/100) random pair-swaps. */          \
    fill_sorted_##SUFFIX(arr, n);                                              \
    bench_lcg_seed(seed);                                                      \
    size_t k = n / 100;                                                        \
    if (k < 2) k = 2;                                                          \
    for (size_t i = 0; i < k; i++) {                                           \
        size_t a = (size_t)(bench_lcg_next() >> 33) % n;                       \
        size_t b = (size_t)(bench_lcg_next() >> 33) % n;                       \
        T tmp = arr[a]; arr[a] = arr[b]; arr[b] = tmp;                        \
    }                                                                          \
}                                                                              \
                                                                               \
static void fill_saw_mixed_##SUFFIX(T *arr, size_t n, uint64_t seed) {         \
    /* Alternating ascending/descending chunks of length 8 + (lcg % 57). */    \
    bench_lcg_seed(seed);                                                      \
    size_t i = 0;                                                              \
    while (i < n) {                                                            \
        size_t chunk = 8 + (size_t)(bench_lcg_next() % 57);                    \
        if (chunk > n - i) chunk = n - i;                                      \
        int dir = (int)(bench_lcg_next() & 1u);                                \
        T base = (T)(bench_lcg_next() % (uint64_t)n);                          \
        if (dir == 0) {                                                        \
            for (size_t kk = 0; kk < chunk; kk++) arr[i + kk] = base + (T)kk;  \
        } else {                                                               \
            for (size_t kk = 0; kk < chunk; kk++) arr[i + kk] = base + (T)(chunk - 1 - kk);\
        }                                                                      \
        i += chunk;                                                            \
    }                                                                          \
}                                                                              \
                                                                               \
static void fill_pattern_##SUFFIX(T *arr, size_t n, const char *pattern,       \
                                  uint64_t seed) {                             \
    if (strcmp(pattern, "random") == 0)        fill_random_##SUFFIX(arr,n,seed);\
    else if (strcmp(pattern, "sorted") == 0)   fill_sorted_##SUFFIX(arr, n);   \
    else if (strcmp(pattern, "reversed") == 0) fill_reversed_##SUFFIX(arr, n); \
    else if (strcmp(pattern, "nearly") == 0)   fill_nearly_sorted_##SUFFIX(arr,n,seed);\
    else if (strcmp(pattern, "few_unique") == 0) fill_few_unique_##SUFFIX(arr,n,seed);\
    else if (strcmp(pattern, "pipe_organ") == 0) fill_pipe_organ_##SUFFIX(arr,n);\
    else if (strcmp(pattern, "equal") == 0)    fill_equal_##SUFFIX(arr, n);    \
    else if (strcmp(pattern, "zipfian") == 0)  fill_zipfian_##SUFFIX(arr,n,seed);\
    else if (strcmp(pattern, "sorted_perturbed") == 0) fill_sorted_perturbed_##SUFFIX(arr,n,seed);\
    else if (strcmp(pattern, "saw_mixed") == 0) fill_saw_mixed_##SUFFIX(arr,n,seed);\
    else fill_random_##SUFFIX(arr, n, seed);                                   \
}

DEFINE_FILL(int32_t,  i32)
DEFINE_FILL(int64_t,  i64)
DEFINE_FILL(uint32_t, u32)
DEFINE_FILL(uint64_t, u64)
DEFINE_FILL(float,    f32)
DEFINE_FILL(double,   f64)

// ============================================================
// QSORT COMPARATORS
// ============================================================

#define DEFINE_CMP(T, SUFFIX)                                                  \
static int cmp_##SUFFIX(const void *a, const void *b) {                        \
    T va = *(const T *)a, vb = *(const T *)b;                                 \
    return (va > vb) - (va < vb);                                              \
}

DEFINE_CMP(int32_t,  i32)
DEFINE_CMP(int64_t,  i64)
DEFINE_CMP(uint32_t, u32)
DEFINE_CMP(uint64_t, u64)
DEFINE_CMP(float,    f32)
DEFINE_CMP(double,   f64)

// ============================================================
// INLINE INTROSORT (pdqsort-lite reference, i64 only for backward compat)
// ============================================================

static void intro_insertion(int64_t *arr, size_t n) {
    for (size_t i = 1; i < n; i++) {
        int64_t key = arr[i];
        size_t j = i;
        while (j > 0 && arr[j-1] > key) { arr[j] = arr[j-1]; j--; }
        arr[j] = key;
    }
}

static void intro_siftdown(int64_t *arr, size_t root, size_t n) {
    while (2 * root + 1 < n) {
        size_t child = 2 * root + 1;
        if (child + 1 < n && arr[child] < arr[child + 1]) child++;
        if (arr[root] >= arr[child]) break;
        int64_t tmp = arr[root]; arr[root] = arr[child]; arr[child] = tmp;
        root = child;
    }
}

static void intro_heapsort(int64_t *arr, size_t n) {
    if (n < 2) return;
    for (size_t i = n / 2; i > 0; i--) intro_siftdown(arr, i - 1, n);
    for (size_t i = n - 1; i > 0; i--) {
        int64_t tmp = arr[0]; arr[0] = arr[i]; arr[i] = tmp;
        intro_siftdown(arr, 0, i);
    }
}

static void introsort_impl(int64_t *arr, size_t n, int depth) {
    if (n <= 24) { intro_insertion(arr, n); return; }
    if (depth == 0) { intro_heapsort(arr, n); return; }

    size_t mid = n / 2;
    if (arr[0] > arr[mid]) { int64_t t = arr[0]; arr[0] = arr[mid]; arr[mid] = t; }
    if (arr[mid] > arr[n-1]) { int64_t t = arr[mid]; arr[mid] = arr[n-1]; arr[n-1] = t; }
    if (arr[0] > arr[mid]) { int64_t t = arr[0]; arr[0] = arr[mid]; arr[mid] = t; }

    int64_t pivot = arr[mid];
    size_t i = 0, j = n - 1;
    while (i <= j) {
        while (arr[i] < pivot) i++;
        while (arr[j] > pivot) j--;
        if (i <= j) {
            int64_t t = arr[i]; arr[i] = arr[j]; arr[j] = t;
            i++; if (j == 0) break; j--;
        }
    }
    if (j > 0) introsort_impl(arr, j + 1, depth - 1);
    if (i < n) introsort_impl(arr + i, n - i, depth - 1);
}

static void introsort_i64(int64_t *arr, size_t n) {
    int depth = 0;
    size_t t = n;
    while (t > 1) { t >>= 1; depth++; }
    depth *= 2;
    introsort_impl(arr, n, depth);
}

// ============================================================
// BENCHMARK DRIVER (macro-generated per type)
// ============================================================

#define DEFINE_BENCH(T, SUFFIX, sort_fn, cmp_fn)                               \
                                                                               \
static void qsort_##SUFFIX(T *arr, size_t n) {                                \
    qsort(arr, n, sizeof(T), cmp_fn);                                         \
}                                                                              \
                                                                               \
static double bench_sublimation_##SUFFIX(T *data, T *work, size_t n,           \
                                         const char *pattern, int runs) {      \
    double best = 1e18;                                                        \
    for (int r = 0; r < runs; r++) {                                           \
        fill_pattern_##SUFFIX(work, n, pattern, 42 + (uint64_t)r);            \
        uint64_t t0 = now_ns();                                                \
        sort_fn(work, n);                                                      \
        uint64_t t1 = now_ns();                                                \
        double elapsed = (double)(t1 - t0);                                    \
        if (elapsed < best) best = elapsed;                                    \
    }                                                                          \
    return best / (double)n;                                                   \
}                                                                              \
                                                                               \
static double bench_qsort_##SUFFIX(T *data, T *work, size_t n,                \
                                    const char *pattern, int runs) {           \
    double best = 1e18;                                                        \
    for (int r = 0; r < runs; r++) {                                           \
        fill_pattern_##SUFFIX(work, n, pattern, 42 + (uint64_t)r);            \
        uint64_t t0 = now_ns();                                                \
        qsort_##SUFFIX(work, n);                                              \
        uint64_t t1 = now_ns();                                                \
        double elapsed = (double)(t1 - t0);                                    \
        if (elapsed < best) best = elapsed;                                    \
    }                                                                          \
    return best / (double)n;                                                   \
}                                                                              \
                                                                               \
static void run_bench_##SUFFIX(size_t n, const char *pattern, int runs) {      \
    T *data = (T *)malloc(n * sizeof(T));                                      \
    T *work = (T *)malloc(n * sizeof(T));                                      \
    if (!data || !work) { fprintf(stderr, "OOM\n"); return; }                  \
                                                                               \
    fill_pattern_##SUFFIX(data, n, pattern, 42);                               \
                                                                               \
    /* warm up */                                                              \
    memcpy(work, data, n * sizeof(T));                                         \
    sort_fn(work, n);                                                          \
                                                                               \
    double ns_sub = bench_sublimation_##SUFFIX(data, work, n, pattern, runs);  \
    double ns_qs  = bench_qsort_##SUFFIX(data, work, n, pattern, runs);        \
                                                                               \
    printf("{\"algo\":\"sublimation_" #SUFFIX "\",\"size\":%zu,"               \
           "\"pattern\":\"%s\",\"ns_per_elem\":%.2f}\n",                       \
           n, pattern, ns_sub);                                                \
    printf("{\"algo\":\"qsort_" #SUFFIX "\",\"size\":%zu,"                     \
           "\"pattern\":\"%s\",\"ns_per_elem\":%.2f}\n",                       \
           n, pattern, ns_qs);                                                 \
                                                                               \
    free(data);                                                                \
    free(work);                                                                \
}

DEFINE_BENCH(int32_t,  i32, sublimation_i32, cmp_i32)
DEFINE_BENCH(int64_t,  i64, sublimation_i64, cmp_i64)
DEFINE_BENCH(uint32_t, u32, sublimation_u32, cmp_u32)
DEFINE_BENCH(uint64_t, u64, sublimation_u64, cmp_u64)
DEFINE_BENCH(float,    f32, sublimation_f32, cmp_f32)
DEFINE_BENCH(double,   f64, sublimation_f64, cmp_f64)

// ============================================================
// MAIN
// ============================================================

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <size> <pattern> <runs>\n", argv[0]);
        return 1;
    }

    size_t n = (size_t)atol(argv[1]);
    const char *pattern = argv[2];
    int runs = atoi(argv[3]);
    if (runs < 1) runs = 1;

    // i64 legacy output (sublimation + qsort + introsort) for backward compat
    {
        int64_t *data = malloc(n * sizeof(int64_t));
        int64_t *work = malloc(n * sizeof(int64_t));
        if (!data || !work) { fprintf(stderr, "OOM\n"); return 1; }

        fill_pattern_i64(data, n, pattern, 42);
        memcpy(work, data, n * sizeof(int64_t));
        sublimation_i64(work, n);

        // sublimation_i64
        double best = 1e18;
        for (int r = 0; r < runs; r++) {
            fill_pattern_i64(work, n, pattern, 42 + (uint64_t)r);
            uint64_t t0 = now_ns();
            sublimation_i64(work, n);
            uint64_t t1 = now_ns();
            double elapsed = (double)(t1 - t0);
            if (elapsed < best) best = elapsed;
        }
        double ns_sub = best / (double)n;

        // qsort
        best = 1e18;
        for (int r = 0; r < runs; r++) {
            fill_pattern_i64(work, n, pattern, 42 + (uint64_t)r);
            uint64_t t0 = now_ns();
            qsort(work, n, sizeof(int64_t), cmp_i64);
            uint64_t t1 = now_ns();
            double elapsed = (double)(t1 - t0);
            if (elapsed < best) best = elapsed;
        }
        double ns_qs = best / (double)n;

        // introsort
        best = 1e18;
        for (int r = 0; r < runs; r++) {
            fill_pattern_i64(work, n, pattern, 42 + (uint64_t)r);
            uint64_t t0 = now_ns();
            introsort_i64(work, n);
            uint64_t t1 = now_ns();
            double elapsed = (double)(t1 - t0);
            if (elapsed < best) best = elapsed;
        }
        double ns_intro = best / (double)n;

        printf("{\"algo\":\"sublimation\",\"size\":%zu,\"pattern\":\"%s\","
               "\"ns_per_elem\":%.2f}\n", n, pattern, ns_sub);
        printf("{\"algo\":\"qsort\",\"size\":%zu,\"pattern\":\"%s\","
               "\"ns_per_elem\":%.2f}\n", n, pattern, ns_qs);
        printf("{\"algo\":\"introsort\",\"size\":%zu,\"pattern\":\"%s\","
               "\"ns_per_elem\":%.2f}\n", n, pattern, ns_intro);

        free(data);
        free(work);
    }

    // Per-type benchmarks: sublimation_T vs qsort for all 6 types
    run_bench_i32(n, pattern, runs);
    run_bench_i64(n, pattern, runs);
    run_bench_u32(n, pattern, runs);
    run_bench_u64(n, pattern, runs);
    run_bench_f32(n, pattern, runs);
    run_bench_f64(n, pattern, runs);

    return 0;
}
