// test_learn.c -- exercises the shipped sublimation_learn API only.
// Reads "R C\n" then R*C row-major doubles from stdin, a mode from argv, calls
// one public detector and prints its result. The oracle driver (test_learn.py)
// drives this against independent numpy references and a splitmix64-shared
// Half-Space Trees re-implementation.
//
//   test_learn welford                 -> C lines "mean popvar"
//   test_learn standardize             -> R lines x C z-scores
//   test_learn mad                     -> R lines: max modified z
//   test_learn ewma ALPHA              -> R lines: max residual z
//   test_learn mahalanobis RIDGE       -> R lines: squared Mahalanobis distance
//   test_learn hstrees T H PSI SL SEED -> R lines: Half-Space Trees score
#include "sublimation_learn.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static double *read_matrix(size_t *r, size_t *c) {
    long rr, cc;
    if (scanf("%ld %ld", &rr, &cc) != 2 || rr <= 0 || cc <= 0) {
        fprintf(stderr, "test_learn: bad header\n"); exit(2);
    }
    *r = (size_t)rr; *c = (size_t)cc;
    double *x = malloc(*r * *c * sizeof(double));
    for (size_t i = 0; i < *r * *c; i++)
        if (scanf("%lf", &x[i]) != 1) { fprintf(stderr, "test_learn: short read\n"); exit(2); }
    return x;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: test_learn MODE [args]\n"); return 2; }
    size_t n, d;
    double *x = read_matrix(&n, &d);
    const char *m = argv[1];
    if (!strcmp(m, "welford")) {
        double *mean = malloc(d * sizeof(double)), *var = malloc(d * sizeof(double));
        sublimation_col_moments(x, n, d, mean, var);
        for (size_t j = 0; j < d; j++) printf("%.15g %.15g\n", mean[j], var[j]);
        free(mean); free(var);
    } else if (!strcmp(m, "standardize")) {
        double *out = malloc(n * d * sizeof(double));
        sublimation_standardize(x, n, d, out);
        for (size_t i = 0; i < n; i++) {
            for (size_t j = 0; j < d; j++) printf(j ? " %.12g" : "%.12g", out[i * d + j]);
            putchar('\n');
        }
        free(out);
    } else if (!strcmp(m, "mad")) {
        double *s = malloc(n * sizeof(double));
        sublimation_mad_scores(x, n, d, s);
        for (size_t i = 0; i < n; i++) printf("%.12g\n", s[i]);
        free(s);
    } else if (!strcmp(m, "ewma")) {
        double *s = malloc(n * sizeof(double));
        sublimation_ewma_scores(x, n, d, argc > 2 ? atof(argv[2]) : 0.3, s);
        for (size_t i = 0; i < n; i++) printf("%.12g\n", s[i]);
        free(s);
    } else if (!strcmp(m, "mahalanobis")) {
        double *s = malloc(n * sizeof(double));
        if (sublimation_mahalanobis(x, n, d, argc > 2 ? atof(argv[2]) : 1e-6, s)) {
            fprintf(stderr, "test_learn: covariance not PD\n"); return 2;
        }
        for (size_t i = 0; i < n; i++) printf("%.12g\n", s[i]);
        free(s);
    } else if (!strcmp(m, "hstrees")) {
        double *s = malloc(n * sizeof(double));
        int rc = sublimation_hstrees(
            x, n, d, argc > 2 ? (unsigned)atol(argv[2]) : 25,
            argc > 3 ? (unsigned)atol(argv[3]) : 15,
            argc > 4 ? (size_t)atol(argv[4]) : 250,
            argc > 5 ? strtoull(argv[5], NULL, 10) : 25,
            argc > 6 ? strtoull(argv[6], NULL, 10) : 1729ULL, s);
        if (rc) { fprintf(stderr, "test_learn: hstrees failed\n"); return 2; }
        for (size_t i = 0; i < n; i++) printf("%llu\n", (unsigned long long)s[i]);
        free(s);
    } else {
        fprintf(stderr, "test_learn: unknown mode '%s'\n", m); return 2;
    }
    free(x);
    return 0;
}
