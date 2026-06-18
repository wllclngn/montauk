// bench_parallel.c -- serial vs parallel sublimation on random int64.
// sublimation_i64 (serial flow model) vs sublimation_i64_parallel (IPS4o-style
// pool). ns/element, best-of-N, plus the parallel speedup. bench-sublimation.py
// covers only the serial path; this is the parallel column of the README table.
//
//   cc -O2 -march=native -I ../src/include bench_parallel.c libsublimation.a -lpthread -lm
//   ./a.out [num_threads]   (default: all hardware threads)
#define _POSIX_C_SOURCE 199309L  // CLOCK_MONOTONIC under strict -std=c2x
#include "sublimation.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

static uint64_t rng = 0x9e3779b97f4a7c15ULL;
static uint64_t xr(void) { rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; return rng; }

static double now_ns(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec * 1e9 + (double)t.tv_nsec;
}

static int is_sorted_i64(const int64_t *a, size_t n) {
    for (size_t i = 1; i < n; i++) if (a[i - 1] > a[i]) return 0;
    return 1;
}

int main(int argc, char **argv) {
    size_t threads = (argc > 1) ? (size_t)atoll(argv[1]) : 0;  // 0 = library default
    const int RUNS = 5;
    size_t sizes[] = {100000, 1000000, 10000000};

    printf("# serial vs parallel sublimation -- random int64, best of %d, threads=%s\n",
           RUNS, threads ? "explicit" : "auto");
    printf("%12s %16s %16s %10s\n", "n", "serial ns/el", "parallel ns/el", "speedup");

    for (int si = 0; si < 3; si++) {
        size_t n = sizes[si];
        int64_t *base = malloc(n * sizeof(int64_t));
        int64_t *work = malloc(n * sizeof(int64_t));
        if (!base || !work) { fprintf(stderr, "oom at n=%zu\n", n); return 1; }
        for (size_t i = 0; i < n; i++) base[i] = (int64_t)xr();

        double best_serial = 1e30, best_par = 1e30;
        for (int r = 0; r < RUNS; r++) {
            memcpy(work, base, n * sizeof(int64_t));
            double t0 = now_ns(); sublimation_i64(work, n); double t1 = now_ns();
            double ns = (t1 - t0) / (double)n; if (ns < best_serial) best_serial = ns;
        }
        if (!is_sorted_i64(work, n)) { fprintf(stderr, "serial NOT sorted at n=%zu\n", n); return 2; }

        for (int r = 0; r < RUNS; r++) {
            memcpy(work, base, n * sizeof(int64_t));
            double t0 = now_ns(); sublimation_i64_parallel(work, n, threads); double t1 = now_ns();
            double ns = (t1 - t0) / (double)n; if (ns < best_par) best_par = ns;
        }
        if (!is_sorted_i64(work, n)) { fprintf(stderr, "parallel NOT sorted at n=%zu\n", n); return 2; }

        printf("%12zu %14.2f   %14.2f   %8.2fx\n", n, best_serial, best_par, best_serial / best_par);
        free(base); free(work);
    }
    return 0;
}
