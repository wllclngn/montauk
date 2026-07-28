// bench_sublimation.c -- the SHIPPED search engine under the search bench.
//
// This replaces search_research (a research scaffold, explicitly "not the
// shipped engine") as the thing the bench labels "sublimation". Every number the
// README attributes to sublimation now comes from libsublimation's public API --
// sublimation_search_compile + sublimation_search_count -- the same entry points
// the CLI and vector call.
//
// One consequence worth stating: the scaffold exposed INTERNAL strategies as
// separate modes (field vs prefiltered, brute vs pigeonhole). The shipped engine
// chooses those internally and offers no way to force one, which is the correct
// API. So the variant modes below resolve to the same shipped dispatch as their
// base mode; they are kept only so the driver's mode names stay stable.
//
//   bench|count      classify PATTERN   literal face (SUBLIMATION_SEARCH_FIXED)
//   benchre|regexcount        PATTERN   regex face (Glushkov field)
//   benchpre|regexpre         PATTERN   == regex face, prefilter is internal
//   benchfz|fuzzycount      K PATTERN   fuzzy face (k-mismatch)
//   benchfzpre|fuzzypre     K PATTERN   == fuzzy face, prefilter is internal
//
// Corpus arrives on stdin. A bench mode prints MB/s (median of 9); a count mode
// prints the match count. One number, no prose, so the driver parses a float.
#define _POSIX_C_SOURCE 199309L
#include "sublimation_text.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define REPS 9

static double now_s(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

static int cmp_double(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

// Slurp stdin whole; the corpora are a few MB and the driver feeds them in one
// shot, so a growing buffer is simpler than any streaming arrangement.
static char *slurp(size_t *out_n) {
    size_t cap = 1 << 22, n = 0;
    char *buf = (char *)malloc(cap);
    if (!buf) return NULL;
    for (;;) {
        if (n == cap) {
            cap *= 2;
            char *nb = (char *)realloc(buf, cap);
            if (!nb) { free(buf); return NULL; }
            buf = nb;
        }
        size_t got = fread(buf + n, 1, cap - n, stdin);
        n += got;
        if (got == 0) break;
    }
    *out_n = n;
    return buf;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: bench_sublimation MODE [K] PATTERN  (corpus on stdin)\n");
        return 2;
    }
    const char *mode = argv[1];

    // Mode -> face. The `classify` sub-argument the driver passes for the
    // literal face is positional noise from the scaffold's interface; accept it.
    int is_count = 0, k = 0;
    unsigned flags = 0;
    const char *pattern = NULL;

    if (!strcmp(mode, "bench") || !strcmp(mode, "count")) {
        is_count = !strcmp(mode, "count");
        flags = SUBLIMATION_SEARCH_FIXED;
        pattern = argv[argc - 1];
    } else if (!strcmp(mode, "benchre") || !strcmp(mode, "regexcount")
            || !strcmp(mode, "benchpre") || !strcmp(mode, "regexpre")) {
        is_count = !strcmp(mode, "regexcount") || !strcmp(mode, "regexpre");
        flags = 0;                      // regex face
        pattern = argv[argc - 1];
    } else if (!strcmp(mode, "benchfz") || !strcmp(mode, "fuzzycount")
            || !strcmp(mode, "benchfzpre") || !strcmp(mode, "fuzzypre")) {
        is_count = !strcmp(mode, "fuzzycount") || !strcmp(mode, "fuzzypre");
        if (argc < 4) { fprintf(stderr, "fuzzy modes need K\n"); return 2; }
        k = atoi(argv[2]);
        flags = SUBLIMATION_SEARCH_FIXED;
        pattern = argv[argc - 1];
    } else {
        fprintf(stderr, "unknown mode '%s'\n", mode);
        return 2;
    }

    size_t n = 0;
    char *hay = slurp(&n);
    if (!hay) { fprintf(stderr, "oom reading corpus\n"); return 1; }

    sublimation_search s;
    sublimation_search_compile(&s, pattern, strlen(pattern), flags, k);
    if (!sublimation_search_valid(&s)) {
        fprintf(stderr, "bad pattern '%s'\n", pattern);
        free(hay);
        return 2;
    }

    if (is_count) {
        printf("%zu\n", sublimation_search_count(&s, hay, n));
        free(hay);
        return 0;
    }

    double mbps[REPS];
    for (int r = 0; r < REPS; r++) {
        double t0 = now_s();
        volatile size_t sink = sublimation_search_count(&s, hay, n);
        double dt = now_s() - t0;
        (void)sink;
        mbps[r] = dt > 0.0 ? ((double)n / dt) / 1e6 : 0.0;
    }
    qsort(mbps, REPS, sizeof(double), cmp_double);
    printf("%.1f\n", mbps[REPS / 2]);
    free(hay);
    return 0;
}
