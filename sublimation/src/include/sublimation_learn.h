// sublimation_learn.h -- Public API for sublimation's learn lane.
//
// Pure-algorithm, zero-weight anomaly detectors over a feature matrix, the
// classical-ML face of the one engine. Every entry point is reentrant and
// thread-safe on disjoint buffers, with no process-lifetime shared state.
// Matrices are row-major, n rows (samples) by d columns (features). Output
// buffers are caller-allocated. These are the detectors montauk's snapshot
// enrichment and vector's montauk_anomalies tool are built on.
#ifndef SUBLIMATION_LEARN_H
#define SUBLIMATION_LEARN_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Per-column streaming mean and population variance (one Welford pass).
// mean[d] and var_pop[d] are filled.
void sublimation_col_moments(const double *x, size_t n, size_t d,
                             double *mean, double *var_pop);

// Column-wise z-score into out (n*d). A zero-variance column yields zeros.
void sublimation_standardize(const double *x, size_t n, size_t d, double *out);

// Per-row anomaly score: max over columns of the robust modified z-score
// (median + MAD, with a sqrt(pi/2)-scaled mean-absolute-deviation fallback when
// MAD is zero, so a mostly-constant column does not go blind). scores[n] filled.
void sublimation_mad_scores(const double *x, size_t n, size_t d, double *scores);

// Per-row EWMA-residual score over the rows as a stream: max over columns of
// |x - level_prev| / sqrt(var_prev + eps). alpha in (0,1); row 0 scores 0.
// scores[n] filled.
void sublimation_ewma_scores(const double *x, size_t n, size_t d, double alpha,
                             double *scores);

// Per-row squared Mahalanobis distance against the sample mean and population
// covariance with `ridge` added to the diagonal. Returns 0 on success, nonzero
// if the covariance is not positive definite. d2[n] filled.
int sublimation_mahalanobis(const double *x, size_t n, size_t d, double ridge,
                            double *d2);

// Streaming Half-Space Trees anomaly score per row (Tan-Ting-Liu, IJCAI 2011).
// Trees are built with no data; a lower score means more anomalous. Deterministic
// given `seed`. Returns 0 on success, nonzero on allocation failure. scores[n]
// filled.
int sublimation_hstrees(const double *x, size_t n, size_t d, unsigned trees,
                        unsigned depth, size_t window, uint64_t size_limit,
                        uint64_t seed, double *scores);

#ifdef __cplusplus
}
#endif

#endif  // SUBLIMATION_LEARN_H
