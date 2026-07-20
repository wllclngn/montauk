// test_spectral.c -- exercises the shipped sublimation_spectral API only.
// Reads "N N\n" then N*N row-major doubles from stdin, a mode from argv, calls
// one public entry point and prints its result. The oracle driver
// (test_spectral.py) drives this against numpy references.
//
//   test_spectral eigval          -> N eigenvalues, ascending
//   test_spectral recon           -> N*N reconstruction V diag(eval) V^T
//   test_spectral reff            -> N*N effective-resistance matrix
//   test_spectral fiedler         -> "lambda2 partitions"
//   test_spectral cluster K SEED  -> N cluster labels
#include "sublimation_spectral.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static double *read_square(size_t *n) {
    long r, c;
    if (scanf("%ld %ld", &r, &c) != 2 || r <= 0 || c != r) {
        fprintf(stderr, "test_spectral: need a square matrix\n"); exit(2);
    }
    *n = (size_t)r;
    double *a = malloc(*n * *n * sizeof(double));
    for (size_t i = 0; i < *n * *n; i++)
        if (scanf("%lf", &a[i]) != 1) { fprintf(stderr, "test_spectral: short read\n"); exit(2); }
    return a;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: test_spectral MODE [args]\n"); return 2; }
    size_t n;
    double *a = read_square(&n);
    const char *m = argv[1];
    if (!strcmp(m, "eigval")) {
        double *ev = malloc(n * sizeof(double)), *V = malloc(n * n * sizeof(double));
        if (sublimation_eigh(a, n, ev, V)) return 2;
        for (size_t i = 0; i < n; i++) printf("%.12g\n", ev[i]);
        free(ev); free(V);
    } else if (!strcmp(m, "recon")) {
        double *ev = malloc(n * sizeof(double)), *V = malloc(n * n * sizeof(double));
        if (sublimation_eigh(a, n, ev, V)) return 2;
        for (size_t i = 0; i < n; i++) {
            for (size_t j = 0; j < n; j++) {
                double s = 0.0;
                for (size_t k = 0; k < n; k++) s += V[i * n + k] * ev[k] * V[j * n + k];
                printf(j ? " %.12g" : "%.12g", s);
            }
            putchar('\n');
        }
        free(ev); free(V);
    } else if (!strcmp(m, "reff")) {
        double *r = malloc(n * n * sizeof(double));
        if (sublimation_effective_resistance(a, n, r)) return 2;
        for (size_t i = 0; i < n; i++) {
            for (size_t j = 0; j < n; j++) printf(j ? " %.12g" : "%.12g", r[i * n + j]);
            putchar('\n');
        }
        free(r);
    } else if (!strcmp(m, "fiedler")) {
        double l2; size_t parts;
        if (sublimation_fiedler(a, n, &l2, &parts)) return 2;
        printf("%.12g %zu\n", l2, parts);
    } else if (!strcmp(m, "cluster")) {
        size_t k = argc > 2 ? (size_t)atol(argv[2]) : 2;
        uint64_t seed = argc > 3 ? strtoull(argv[3], NULL, 10) : 1729ULL;
        int32_t *lab = malloc(n * sizeof(int32_t));
        if (sublimation_spectral_cluster(a, n, k, seed, lab)) return 2;
        for (size_t i = 0; i < n; i++) printf("%d\n", lab[i]);
        free(lab);
    } else {
        fprintf(stderr, "test_spectral: unknown mode '%s'\n", m); return 2;
    }
    free(a);
    return 0;
}
