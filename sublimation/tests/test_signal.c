// test_signal.c -- exercises the shipped sublimation_signal API only.
// Reads "N\n" then N doubles (a real signal) from stdin, a mode from argv, calls
// one public entry point and prints its result. The oracle driver
// (test_signal.py) drives this against numpy.fft and a Spectral Residual ref.
//
//   test_signal fft            -> N lines "re im" (the forward DFT)
//   test_signal sr Q TAU Z     -> N lines "saliency flag"
//   test_signal mp M           -> (N-M+1) lines "matrix_profile nn_index"
#include "sublimation_signal.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static double *read_signal(size_t *n) {
    long len;
    if (scanf("%ld", &len) != 1 || len <= 0) {
        fprintf(stderr, "test_signal: bad header\n"); exit(2);
    }
    *n = (size_t)len;
    double *s = malloc(*n * sizeof(double));
    for (size_t i = 0; i < *n; i++)
        if (scanf("%lf", &s[i]) != 1) { fprintf(stderr, "test_signal: short read\n"); exit(2); }
    return s;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: test_signal MODE [args]\n"); return 2; }
    size_t n;
    double *sig = read_signal(&n);
    const char *m = argv[1];
    if (!strcmp(m, "fft")) {
        double *re = malloc(n * sizeof(double));
        double *im = calloc(n, sizeof(double));
        for (size_t i = 0; i < n; i++) re[i] = sig[i];
        if (sublimation_fft(re, im, n, 0)) { fprintf(stderr, "fft: n not power of two\n"); return 2; }
        for (size_t i = 0; i < n; i++) printf("%.12g %.12g\n", re[i], im[i]);
        free(re); free(im);
    } else if (!strcmp(m, "sr")) {
        size_t q = argc > 2 ? (size_t)atol(argv[2]) : 3;
        double tau = argc > 3 ? atof(argv[3]) : 3.0;
        size_t z = argc > 4 ? (size_t)atol(argv[4]) : 21;
        double *sal = malloc(n * sizeof(double));
        uint8_t *fl = malloc(n);
        if (sublimation_spectral_residual(sig, n, q, tau, z, sal, fl)) {
            fprintf(stderr, "sr failed\n"); return 2;
        }
        for (size_t i = 0; i < n; i++) printf("%.12g %d\n", sal[i], (int)fl[i]);
        free(sal); free(fl);
    } else if (!strcmp(m, "mp")) {
        size_t win = argc > 2 ? (size_t)atol(argv[2]) : 16;
        if (win < 2 || win > n || n - win + 1 < 2) {
            fprintf(stderr, "mp: series too short for window\n"); return 2;
        }
        size_t Lm = n - win + 1;
        double *mp = malloc(Lm * sizeof(double));
        int64_t *mpi = malloc(Lm * sizeof(int64_t));
        if (sublimation_matrix_profile(sig, n, win, mp, mpi)) {
            fprintf(stderr, "mp failed\n"); return 2;
        }
        for (size_t i = 0; i < Lm; i++)
            printf("%.12g %lld\n", mp[i], (long long)mpi[i]);
        free(mp); free(mpi);
    } else {
        fprintf(stderr, "test_signal: unknown mode '%s'\n", m); return 2;
    }
    free(sig);
    return 0;
}
