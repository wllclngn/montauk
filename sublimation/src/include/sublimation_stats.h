// sublimation_stats.h -- Public API for sublimation's descriptive-statistics
// lane.
//
// The reductions and order statistics the CLI's stat verbs used to compute
// inline. The library owns the numbers and every face formats them -- the CLI,
// a direct FFI caller, the MCP server -- so no two faces can disagree about
// what a mean or a quartile is. Sample (n-1) convention throughout, matching
// the CLI these were lifted from. Callers guard n == 0.
#ifndef SUBLIMATION_STATS_H
#define SUBLIMATION_STATS_H

#include <stddef.h>

#include "internal/c23_compat.h"   // SUB_API

#ifdef __cplusplus
extern "C" {
#endif

// Reductions over v[n], no reordering.
SUB_API double sublimation_sum_f64(const double *v, size_t n);
SUB_API double sublimation_mean_f64(const double *v, size_t n);
// Sample (n-1) variance and its square root; n < 2 has no spread -> 0.0.
// Two-pass for numerical stability.
SUB_API double sublimation_variance_f64(const double *v, size_t n);
SUB_API double sublimation_stdev_f64(const double *v, size_t n);
SUB_API double sublimation_min_f64(const double *v, size_t n);
SUB_API double sublimation_max_f64(const double *v, size_t n);

// Quantile of arr[n]; sorts arr in place. nearest == 0 uses the estimator
// index floor(q*n); nearest != 0 uses nearest-rank ceil(q*n)-1, the convention
// a percentile() drop-in wants. q is assumed in 0..1, the index is clamped.
SUB_API double sublimation_quantile_f64(double *arr, size_t n, double q, int nearest);

// count/mean/stdev/min/quartiles/max in one shot; sorts arr in place. The
// moments are taken over the sorted array and the quartiles use the same
// estimator index as sublimation_quantile_f64 with nearest == 0.
typedef struct {
    size_t n;
    double mean, stdev, min, q25, q50, q75, max;
} sub_describe_t;
SUB_API sub_describe_t sublimation_describe_f64(double *arr, size_t n);

// Tukey IQR fences (q1 - 1.5*IQR, q3 + 1.5*IQR) -- robust, so the outliers
// cannot corrupt the threshold the way a mean +/- k*sigma rule lets them.
// Sorts arr in place.
SUB_API void sublimation_tukey_fences_f64(double *arr, size_t n, double *lo, double *hi);

// Fixed-bin histogram over v[n], no reordering. Writes nbins counts plus the
// minimum and the bin width. A zero range (every value equal) yields width 0
// with the whole population in bin 0.
SUB_API void sublimation_histogram_f64(const double *v, size_t n, size_t nbins,
                                       size_t *counts, double *out_min,
                                       double *out_width);

#ifdef __cplusplus
}
#endif

#endif  // SUBLIMATION_STATS_H
