// Harness for test_stats_oracle.py. Touches only the public sublimation_stats /
// sublimation_text API, reads doubles (or lines, for tally) on stdin, and prints
// results at full precision for the Python side to diff against numpy.
#include "sublimation_stats.h"
#include "sublimation_text.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t read_doubles(double **out) {
    size_t cap = 1024, n = 0;
    double *v = malloc(cap * sizeof(double));
    while (scanf("%lf", &v[n]) == 1) {
        if (++n == cap) {
            cap *= 2;
            v = realloc(v, cap * sizeof(double));
        }
    }
    *out = v;
    return n;
}

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    const char *mode = argv[1];

    if (strcmp(mode, "tally") == 0) {
        // Whole stdin as one buffer; tally counts distinct lines.
        size_t cap = 1 << 16, n = 0;
        char *buf = malloc(cap);
        size_t got;
        while ((got = fread(buf + n, 1, cap - n, stdin)) > 0) {
            n += got;
            if (n == cap) {
                cap *= 2;
                buf = realloc(buf, cap);
            }
        }
        sub_tally_t *t = malloc(sizeof(*t) * (n + 1));
        size_t total = 0;
        size_t k = sublimation_tally(buf, n, t, n + 1, &total);
        printf("%zu\n", total);
        for (size_t i = 0; i < k; i++)
            printf("%llu\t%.*s\n", (unsigned long long)t[i].count,
                   (int)t[i].length, buf + t[i].offset);
        return 0;
    }

    double *v = NULL;
    size_t n = read_doubles(&v);
    if (n == 0) return 2;

    if (strcmp(mode, "reduce") == 0) {
        printf("%.17g\n", sublimation_sum_f64(v, n));
        printf("%.17g\n", sublimation_mean_f64(v, n));
        printf("%.17g\n", sublimation_variance_f64(v, n));
        printf("%.17g\n", sublimation_stdev_f64(v, n));
        printf("%.17g\n", sublimation_min_f64(v, n));
        printf("%.17g\n", sublimation_max_f64(v, n));
    } else if (strcmp(mode, "quantile") == 0) {
        // argv[2] = q, argv[3] = nearest flag. The array is sorted in place, so
        // each call gets its own copy.
        double q = atof(argv[2]);
        int nearest = atoi(argv[3]);
        double *c = malloc(n * sizeof(double));
        memcpy(c, v, n * sizeof(double));
        printf("%.17g\n", sublimation_quantile_f64(c, n, q, nearest));
    } else if (strcmp(mode, "describe") == 0) {
        double *c = malloc(n * sizeof(double));
        memcpy(c, v, n * sizeof(double));
        sub_describe_t d = sublimation_describe_f64(c, n);
        printf("%zu\n%.17g\n%.17g\n%.17g\n%.17g\n%.17g\n%.17g\n%.17g\n",
               d.n, d.mean, d.stdev, d.min, d.q25, d.q50, d.q75, d.max);
    } else if (strcmp(mode, "fences") == 0) {
        double *c = malloc(n * sizeof(double));
        memcpy(c, v, n * sizeof(double));
        double lo = 0, hi = 0;
        sublimation_tukey_fences_f64(c, n, &lo, &hi);
        printf("%.17g\n%.17g\n", lo, hi);
    } else if (strcmp(mode, "histogram") == 0) {
        size_t nbins = (size_t)atoi(argv[2]);
        size_t *counts = calloc(nbins, sizeof(size_t));
        double mn = 0, w = 0;
        sublimation_histogram_f64(v, n, nbins, counts, &mn, &w);
        printf("%.17g\n%.17g\n", mn, w);
        for (size_t i = 0; i < nbins; i++) printf("%zu\n", counts[i]);
    } else {
        return 2;
    }
    return 0;
}
