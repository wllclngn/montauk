// signal.c -- sublimation signal lane: FFT and Spectral Residual.
//
// Ported from the proven research prototype (tests/research/learn/
// ts_research.c), whose oracle (tests/test_signal.py) proves the FFT against
// numpy.fft and the Spectral Residual saliency and flags against a numpy
// reference of the identical steps, plus injected-spike detection.
#include "sublimation_signal.h"

#include <math.h>
#include <stdlib.h>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

static int is_pow2(size_t n) { return n && (n & (n - 1)) == 0; }

int sublimation_fft(double *re, double *im, size_t n, int inverse) {
    if (!is_pow2(n)) return 1;
    for (size_t i = 1, j = 0; i < n; i++) {          // bit reversal
        size_t bit = n >> 1;
        for (; j & bit; bit >>= 1) j ^= bit;
        j ^= bit;
        if (i < j) {
            double tr = re[i]; re[i] = re[j]; re[j] = tr;
            double ti = im[i]; im[i] = im[j]; im[j] = ti;
        }
    }
    for (size_t len = 2; len <= n; len <<= 1) {
        double ang = (inverse ? 2.0 : -2.0) * M_PI / (double)len;
        double wlr = cos(ang), wli = sin(ang);
        for (size_t i = 0; i < n; i += len) {
            double wr = 1.0, wi = 0.0;
            for (size_t k = 0; k < len / 2; k++) {
                size_t a = i + k, b = i + k + len / 2;
                double ur = re[a], ui = im[a];
                double vr = re[b] * wr - im[b] * wi;
                double vi = re[b] * wi + im[b] * wr;
                re[a] = ur + vr; im[a] = ui + vi;
                re[b] = ur - vr; im[b] = ui - vi;
                double nwr = wr * wlr - wi * wli;
                wi = wr * wli + wi * wlr; wr = nwr;
            }
        }
    }
    if (inverse)
        for (size_t i = 0; i < n; i++) { re[i] /= (double)n; im[i] /= (double)n; }
    return 0;
}

int sublimation_spectral_residual(const double *signal, size_t n, size_t q,
                                  double tau, size_t z, double *saliency,
                                  uint8_t *flags) {
    if (!is_pow2(n)) return 1;
    double *re = malloc(n * sizeof(double));
    double *im = calloc(n, sizeof(double));
    double *L = malloc(n * sizeof(double));
    double *P = malloc(n * sizeof(double));
    if (!re || !im || !L || !P) { free(re); free(im); free(L); free(P); return 1; }
    for (size_t i = 0; i < n; i++) re[i] = signal[i];
    sublimation_fft(re, im, n, 0);
    for (size_t i = 0; i < n; i++) {
        double amp = hypot(re[i], im[i]);
        L[i] = log(amp > 1e-8 ? amp : 1e-8);
        P[i] = atan2(im[i], re[i]);
    }
    size_t hw = q / 2;                               // box filter, edge-clamped mean
    for (size_t i = 0; i < n; i++) {
        size_t lo = i < hw ? 0 : i - hw;
        size_t hi = i + hw >= n ? n - 1 : i + hw;
        double s = 0.0;
        for (size_t k = lo; k <= hi; k++) s += L[k];
        double al = s / (double)(hi - lo + 1);
        double m = exp(L[i] - al);                    // spectral residual, exponentiated
        re[i] = m * cos(P[i]); im[i] = m * sin(P[i]);
    }
    sublimation_fft(re, im, n, 1);
    for (size_t i = 0; i < n; i++) saliency[i] = hypot(re[i], im[i]);
    for (size_t i = 0; i < n; i++) {                 // relative-deviation threshold
        size_t lo = i < z ? 0 : i - z;
        double s = 0.0; size_t cnt = 0;
        for (size_t k = lo; k < i; k++) { s += saliency[k]; cnt++; }
        double sbar = cnt > 0 ? s / (double)cnt : saliency[i];
        flags[i] = (sbar > 0.0 && (saliency[i] - sbar) / sbar > tau) ? 1 : 0;
    }
    free(re); free(im); free(L); free(P);
    return 0;
}
