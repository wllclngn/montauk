// sublimation_signal.h -- Public API for sublimation's signal lane.
//
// The time-series DSP face: a from-scratch radix-2 FFT and the Spectral Residual
// saliency detector (Ren et al., Microsoft, KDD 2019) built on it. Pure
// algorithm, zero weights. The FFT is the one nontrivial kernel and it is shared
// with the matrix-profile family to come. Output buffers are caller-allocated.
#ifndef SUBLIMATION_SIGNAL_H
#define SUBLIMATION_SIGNAL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// In-place radix-2 complex FFT over re[n] and im[n]. inverse != 0 does the
// inverse transform (scaled by 1/n), matching numpy.fft.fft / numpy.fft.ifft;
// forward uses exp(-2pi i/len). n must be a power of two. Returns 0 on success,
// nonzero if n is not a power of two.
int sublimation_fft(double *re, double *im, size_t n, int inverse);

// Spectral Residual saliency detection over a real signal (n a power of two):
// the log-amplitude spectrum minus its box-filtered average, recombined with the
// original phase and taken back to the time domain. Fills saliency[n] and
// flags[n], where flags[i] is 1 when the saliency exceeds the mean of the
// preceding z points by more than tau. q is the box-filter length. Returns 0 on
// success, nonzero if n is not a power of two or on OOM.
int sublimation_spectral_residual(const double *signal, size_t n, size_t q,
                                  double tau, size_t z, double *saliency,
                                  uint8_t *flags);

// Self-join matrix profile over a real series: for every length-m subsequence,
// the z-normalized Euclidean distance to its nearest non-trivial neighbour
// (STOMP -- the first sliding-dot-product row via the FFT above, the rest via
// the O(1) diagonal recurrence). Fills mp[n-m+1] and mpi[n-m+1] (the
// nearest-neighbour subsequence index). argmax(mp) is the discord (the single
// most anomalous window); the smallest-mp pair is the motif (the most
// recurring pattern). A trivial-match exclusion of m/4 each side is applied.
// Returns 0 on success, nonzero if m < 2, m > n, or on OOM.
int sublimation_matrix_profile(const double *series, size_t n, size_t m,
                               double *mp, int64_t *mpi);

#ifdef __cplusplus
}
#endif

#endif  // SUBLIMATION_SIGNAL_H
