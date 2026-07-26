// Descriptive statistics: the reductions and order statistics that used to sit
// inline in the CLI's stat verbs. Lifted verbatim so the numbers are unchanged;
// the CLI keeps every byte of formatting and now only asks for values.
#include "include/sublimation_stats.h"
#include "include/sublimation.h"

#include <math.h>

double sublimation_sum_f64(const double *v, size_t n) {
    double s = 0.0;
    for (size_t i = 0; i < n; i++) s += v[i];
    return s;
}

double sublimation_mean_f64(const double *v, size_t n) {
    if (n == 0) return 0.0;
    return sublimation_sum_f64(v, n) / (double)n;
}

double sublimation_variance_f64(const double *v, size_t n) {
    if (n < 2) return 0.0;                 // no spread
    double mean = sublimation_sum_f64(v, n) / (double)n;
    double ss = 0.0;
    for (size_t i = 0; i < n; i++) {
        double d = v[i] - mean;
        ss += d * d;
    }
    return ss / (double)(n - 1);
}

double sublimation_stdev_f64(const double *v, size_t n) {
    return sqrt(sublimation_variance_f64(v, n));
}

double sublimation_min_f64(const double *v, size_t n) {
    if (n == 0) return 0.0;
    double m = v[0];
    for (size_t i = 1; i < n; i++) if (v[i] < m) m = v[i];
    return m;
}

double sublimation_max_f64(const double *v, size_t n) {
    if (n == 0) return 0.0;
    double m = v[0];
    for (size_t i = 1; i < n; i++) if (v[i] > m) m = v[i];
    return m;
}

// The estimator index the default quantile path uses, clamped to the array.
static size_t estimator_index(double q, size_t n) {
    if (q <= 0.0) return 0;  // a negative q casts to a huge size_t (UB); clamp first
    size_t i = (size_t)(q * (double)n);
    return (i >= n) ? n - 1 : i;
}

double sublimation_quantile_f64(double *arr, size_t n, double q, int nearest) {
    if (n == 0) return 0.0;
    sublimation_f64(arr, n);
    size_t idx;
    if (nearest) {
        double kk = ceil(q * (double)n) - 1.0;
        if (kk < 0.0) kk = 0.0;
        idx = (size_t)kk;
        if (idx >= n) idx = n - 1;
    } else {
        idx = estimator_index(q, n);
    }
    return arr[idx];
}

sub_describe_t sublimation_describe_f64(double *arr, size_t n) {
    sub_describe_t d = {0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0};
    d.n = n;
    if (n == 0) return d;
    // Sort first, then take the moments over the sorted array -- the order the
    // verb this was lifted from used, and float addition is order-dependent.
    sublimation_f64(arr, n);
    d.mean  = sublimation_sum_f64(arr, n) / (double)n;
    d.stdev = sublimation_stdev_f64(arr, n);
    d.min   = arr[0];
    d.q25   = arr[estimator_index(0.25, n)];
    d.q50   = arr[estimator_index(0.50, n)];
    d.q75   = arr[estimator_index(0.75, n)];
    d.max   = arr[n - 1];
    return d;
}

void sublimation_tukey_fences_f64(double *arr, size_t n, double *lo, double *hi) {
    if (n == 0) { if (lo) *lo = 0.0; if (hi) *hi = 0.0; return; }
    sublimation_f64(arr, n);
    double q1 = arr[estimator_index(0.25, n)];
    double q3 = arr[estimator_index(0.75, n)];
    double iqr = q3 - q1;
    if (lo) *lo = q1 - 1.5 * iqr;
    if (hi) *hi = q3 + 1.5 * iqr;
}

void sublimation_histogram_f64(const double *v, size_t n, size_t nbins,
                               size_t *counts, double *out_min,
                               double *out_width) {
    if (nbins == 0 || counts == NULL) return;
    for (size_t b = 0; b < nbins; b++) counts[b] = 0;
    if (out_min) *out_min = 0.0;
    if (out_width) *out_width = 0.0;
    if (n == 0) return;

    double mn = v[0], mx = v[0];
    for (size_t i = 1; i < n; i++) {
        if (v[i] < mn) mn = v[i];
        if (v[i] > mx) mx = v[i];
    }
    double range = mx - mn;
    for (size_t i = 0; i < n; i++) {
        size_t b = 0;
        if (range > 0.0) {
            long long bb = (long long)((v[i] - mn) / range * (double)nbins);
            if (bb >= (long long)nbins) bb = (long long)nbins - 1;
            else if (bb < 0) bb = 0;
            b = (size_t)bb;
        }
        counts[b]++;
    }
    if (out_min) *out_min = mn;
    if (out_width) *out_width = range / (double)nbins;
}
