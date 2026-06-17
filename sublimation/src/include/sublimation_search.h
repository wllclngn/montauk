// sublimation_search.h -- structural search: locate where a disorder pattern
// occurs in a numeric stream.
//
// This is the third primitive alongside the sort (ordering) and the classifier
// (what an input *is*). Where grep finds the positions of a TEXT pattern,
// sublimation_locate finds the positions of a STRUCTURAL pattern: it slides the
// flow-model classifier across a stream and returns the windows whose disorder
// class matches a target -- "find every stretch that looks sorted", "where did
// the stream go few-unique", "which windows are random". The classifier is the
// query engine; the window is the line; the disorder class is the pattern.
//
// Two entry points per type:
//   sublimation_profile_*  -- the raw scan: classify every window, in order.
//   sublimation_locate_*   -- the grep-analog: only the windows matching a target.
//
// Read-only: the input is never modified. The classifier runs in place on each
// window (no copy). Window sizes >= 256 get the full Young-tableau treatment;
// smaller windows still yield a disorder class from the cheap profile.
#ifndef SUBLIMATION_SEARCH_H
#define SUBLIMATION_SEARCH_H

#include <stddef.h>
#include <stdint.h>

#include "sublimation.h"          // sub_disorder_t, sub_profile_t
#include "internal/c23_compat.h"

#ifdef __cplusplus
extern "C" {
#endif

// One located window: where it is, and the structure it carries.
typedef struct {
    size_t         start;             // window start index in the input
    size_t         len;              // window length
    sub_disorder_t disorder;         // the window's classified disorder class
    float          inversion_ratio;  // 0 = sorted, ~0.5 = random, 1 = reversed
    size_t         distinct_estimate;// approximate distinct values in the window
} sub_match_t;

// Raw scan. Slide a window of `window` samples with step `stride` across
// arr[0..n), classify each, and write the per-window profile to out[] (caller-
// allocated, capacity out_cap). Returns the number of windows written (the scan
// stops early if out_cap is reached). window>n, window==0, or stride==0 -> 0.
SUB_API size_t sublimation_profile_u64(const uint64_t *arr, size_t n,
                                       size_t window, size_t stride,
                                       sub_match_t *out, size_t out_cap);
SUB_API size_t sublimation_profile_i64(const int64_t *arr, size_t n,
                                       size_t window, size_t stride,
                                       sub_match_t *out, size_t out_cap);
SUB_API size_t sublimation_profile_f64(const double *arr, size_t n,
                                       size_t window, size_t stride,
                                       sub_match_t *out, size_t out_cap);

// The grep-analog. Same scan, but only the windows whose disorder class equals
// `target` are written to out[]. Returns the match count.
SUB_API size_t sublimation_locate_u64(const uint64_t *arr, size_t n,
                                      size_t window, size_t stride,
                                      sub_disorder_t target,
                                      sub_match_t *out, size_t out_cap);
SUB_API size_t sublimation_locate_i64(const int64_t *arr, size_t n,
                                      size_t window, size_t stride,
                                      sub_disorder_t target,
                                      sub_match_t *out, size_t out_cap);
SUB_API size_t sublimation_locate_f64(const double *arr, size_t n,
                                      size_t window, size_t stride,
                                      sub_disorder_t target,
                                      sub_match_t *out, size_t out_cap);

// Human-readable name for a disorder class (for printing matches).
SUB_API const char *sublimation_disorder_name(sub_disorder_t d);

#ifdef __cplusplus
}
#endif

#endif // SUBLIMATION_SEARCH_H
