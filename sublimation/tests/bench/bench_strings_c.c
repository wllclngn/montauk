// bench_strings_c.c -- sublimation_strings vs qsort+strcmp
//
// Usage:
//   bench_strings_c [n] [pattern] [trials]
//   pattern = random | sorted | common_prefix | deep_prefix
//   trials  = best-of-N samples
#define _POSIX_C_SOURCE 199309L

#include "../../src/include/sublimation_strings.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static uint64_t lcg = 0xC0DEFEEDull;
static uint64_t lcg_next(void) {
    lcg = lcg * 6364136223846793005ull + 1442695040888963407ull;
    return lcg;
}

static int strings_cmp(const void *a, const void *b) {
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

// pattern fillers: each writes n strings of avg length L into buf, then
// fills arr[i] with pointers into buf. Returns the buf so the caller frees it.

static char *fill_random(const char **arr, size_t n, size_t L) {
    char *buf = (char *)malloc(n * (L + 1));
    static const char alpha[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for (size_t i = 0; i < n; i++) {
        char *p = buf + i * (L + 1);
        for (size_t j = 0; j < L; j++) p[j] = alpha[lcg_next() % 62];
        p[L] = '\0';
        arr[i] = p;
    }
    return buf;
}

static char *fill_sorted(const char **arr, size_t n, size_t L) {
    char *buf = fill_random(arr, n, L);
    qsort(arr, n, sizeof(const char *), strings_cmp);
    return buf;
}

static char *fill_common_prefix(const char **arr, size_t n, size_t L) {
    // First half of each string is a fixed prefix; second half is random.
    char *buf = (char *)malloc(n * (L + 1));
    static const char alpha[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    size_t prefix = L / 2;
    for (size_t i = 0; i < n; i++) {
        char *p = buf + i * (L + 1);
        for (size_t j = 0; j < prefix; j++) p[j] = 'X';
        for (size_t j = prefix; j < L; j++) p[j] = alpha[lcg_next() % 36];
        p[L] = '\0';
        arr[i] = p;
    }
    return buf;
}

static char *fill_deep_prefix(const char **arr, size_t n, size_t L) {
    // Worst case: shared prefix is ~3/4 of each string. Stresses MSD radix.
    char *buf = (char *)malloc(n * (L + 1));
    static const char alpha[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    size_t prefix = (L * 3) / 4;
    for (size_t i = 0; i < n; i++) {
        char *p = buf + i * (L + 1);
        for (size_t j = 0; j < prefix; j++) p[j] = 'Y';
        for (size_t j = prefix; j < L; j++) p[j] = alpha[lcg_next() % 36];
        p[L] = '\0';
        arr[i] = p;
    }
    return buf;
}

typedef char *(*fill_fn)(const char **, size_t, size_t);

static fill_fn pick_pattern(const char *name) {
    if (strcmp(name, "random") == 0)         return fill_random;
    if (strcmp(name, "sorted") == 0)         return fill_sorted;
    if (strcmp(name, "common_prefix") == 0)  return fill_common_prefix;
    if (strcmp(name, "deep_prefix") == 0)    return fill_deep_prefix;
    fprintf(stderr, "unknown pattern: %s\n", name);
    exit(1);
}

static uint64_t time_one(void (*sort_fn)(const char **, size_t),
                          const char **arr_orig, char *buf_orig,
                          size_t n, size_t L, fill_fn fill) {
    // Refill so each trial starts identical.
    (void)buf_orig;
    char *buf = fill(arr_orig, n, L);
    uint64_t t0 = now_ns();
    sort_fn(arr_orig, n);
    uint64_t t1 = now_ns();
    free(buf);
    return t1 - t0;
}

static void qsort_wrapper(const char **arr, size_t n) {
    qsort(arr, n, sizeof(const char *), strings_cmp);
}

int main(int argc, char **argv) {
    size_t n = (argc > 1) ? (size_t)strtoull(argv[1], NULL, 10) : 100000;
    const char *pattern_name = (argc > 2) ? argv[2] : "random";
    int trials = (argc > 3) ? atoi(argv[3]) : 3;
    size_t L = 16;

    fill_fn fill = pick_pattern(pattern_name);

    const char **arr = (const char **)malloc(n * sizeof(const char *));

    uint64_t sub_best = (uint64_t)-1;
    for (int t = 0; t < trials; t++) {
        lcg = 0xC0DEFEEDull + (unsigned long long)t;  // identical seed per matched pair
        uint64_t e = time_one(sublimation_strings, arr, NULL, n, L, fill);
        if (e < sub_best) sub_best = e;
    }

    uint64_t qs_best = (uint64_t)-1;
    for (int t = 0; t < trials; t++) {
        lcg = 0xC0DEFEEDull + (unsigned long long)t;
        uint64_t e = time_one(qsort_wrapper, arr, NULL, n, L, fill);
        if (e < qs_best) qs_best = e;
    }

    double sub_ns_elem = (double)sub_best / (double)n;
    double qs_ns_elem  = (double)qs_best  / (double)n;

    printf("# n=%zu pattern=%s L=%zu trials=%d (best-of)\n",
           n, pattern_name, L, trials);
    printf("%-22s ns_per_elem=%8.2f  total_ns=%12lu\n",
           "sublimation_strings", sub_ns_elem, (unsigned long)sub_best);
    printf("%-22s ns_per_elem=%8.2f  total_ns=%12lu\n",
           "qsort+strcmp",        qs_ns_elem,  (unsigned long)qs_best);
    printf("%-22s %.3fx\n",
           "speedup_over_qsort",  qs_ns_elem / sub_ns_elem);

    free(arr);
    return 0;
}
