// sublimation.h -- Public API for libsublimation
//
// Flow-model adaptive sorting. C23 core with Python, Rust, Go interfaces.
//
// Memory model: the numeric entry points (`sublimation_<T>`) sort in place
// with no heap allocation. The non-numeric entry points allocate internal
// scratch: `sublimation_strings` needs ~24n bytes, and
// `sublimation_pack_sort_<T>` needs n * sizeof(uint64_t). Both expose
// `_with_scratch` variants for callers that want to manage memory.
//
// Thread safety: every entry point is reentrant and thread-safe on disjoint
// buffers. No process-lifetime shared mutable state. Concurrent calls on
// the SAME buffer are undefined behavior.
#ifndef SUBLIMATION_H
#define SUBLIMATION_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "internal/c23_compat.h"

#ifdef __cplusplus
extern "C" {
#endif

// Release version (source-of-truth for the library tag, pkgbuild, tests).
#define SUBLIMATION_VERSION_MAJOR  3
#define SUBLIMATION_VERSION_MINOR  0
#define SUBLIMATION_VERSION_PATCH  0
#define SUBLIMATION_VERSION_STRING "3.0.0"

// ABI version. Bumped only when the library ABI breaks; independent from
// the release version above. Readers should compare this value at runtime
// against SUBLIMATION_API_VERSION to catch header/shared-object mismatches.
// Advanced to 2 for the 2.0.0 release: the public sublimation_nfa struct gained
// an `icase` field (layout change) -- an ABI break for by-value users.
// Advanced to 3: the generic qsort-compatible `sublimation()` entry point was
// removed. It was a passthrough to glibc qsort, never the engine; libc sorting
// is no longer linked anywhere in the library. Use the typed entry points.
#define SUBLIMATION_API_VERSION 3

// Disorder classification (the classifier's verdict)
typedef enum {
    SUB_SORTED       = 0,   // already sorted, O(n) verified
    SUB_REVERSED     = 1,   // fully reversed, O(n) reverse
    SUB_NEARLY_SORTED = 2,  // low displacement, merge-based
    SUB_FEW_UNIQUE   = 3,   // small distinct count, partition-based
    SUB_RANDOM       = 4,   // no exploitable structure
    SUB_PHASED       = 5,   // phase boundary detected (sorted + random)
    SUB_SPECTRAL     = 6,   // spectral seriation path was used
} sub_disorder_t;

// Classification profile (the initial level graph)
//
// Fill contract -- every classifier return path honors these semantics:
//   inversion_ratio    Fraction of inverted pairs. Analytic on the fast
//                      paths (sorted/all-equal 0.0; reversed 1.0, ties on
//                      the AVX2 non-increasing path may overstate slightly;
//                      rotated 2*rot*(n-rot)/(n*(n-1)), exact for distinct
//                      keys); a 128-pair sampled estimate everywhere else.
//                      Never a placeholder 0.0 on a disordered input.
//   lis_length         Longest increasing subsequence: exact pile count when
//                      the patience tableau ran, n on sorted/all-equal (weak
//                      order), an inversion-derived estimate otherwise.
//   lds_length         Longest decreasing subsequence. All-equal inputs
//                      publish n on every path (an equal run is an LDS of
//                      length n under weak orders, matching the tableau);
//                      strictly sorted publishes 1, reversed publishes n.
//   distinct_estimate  Sampled estimate; exactly 1 on all-equal fast paths.
//                      0 only when not computed (n <= 1).
//   info_theoretic_bound, interleave_k
//                      Filled only when the tableau ran (0 = not computed).
typedef struct {
    size_t n;                    // array size
    size_t run_count;            // ascending runs
    size_t mono_count;           // monotone runs (ascending + descending)
    size_t max_run_len;          // longest natural run
    int64_t max_descent_gap;     // max value gap at descents (arr[i] - arr[i+1] where arr[i] > arr[i+1])
    size_t lis_length;           // longest increasing subsequence (patience sort)
    size_t lds_length;           // longest decreasing subsequence (= number of Young tableau rows)
    float  info_theoretic_bound; // log2(f^lambda) via hook length formula (0 if not computed)
    size_t interleave_k;         // detected k-interleaved sorted sequences (0 if none)
    size_t distinct_estimate;    // approximate distinct values
    float  inversion_ratio;      // estimated inversion fraction (see contract above)
    size_t phase_boundary;       // index of detected regime change (0 = none)
    size_t rotation_point;       // rotation point for rotated sorted arrays (0 = none)
    float  spectral_gap;         // lambda_2 of comparison graph (0 if not computed)
    float  spectral_gap_ratio;   // lambda_2 / lambda_n (0 if not computed)
    sub_disorder_t disorder;      // overall classification
} sub_profile_t;

// Sort statistics (returned from sort calls)
typedef struct {
    uint64_t comparisons;        // total comparisons performed
    uint64_t swaps;              // total element swaps
    uint64_t levels_built;       // level graph constructions
    uint64_t gap_prunes;         // empty-region bulk reclassifications
    uint64_t rescans;            // full classification rescans
    uint64_t spectral_decompositions; // eigendecompositions performed
    double   spectral_gap;       // last spectral gap observed
    double   info_theoretic_bound;  // minimum comparisons needed (from hook length formula)
    double   comparison_efficiency;  // info_bound / actual_comparisons (1.0 = perfect)
    sub_disorder_t disorder;      // detected disorder class
    double   wall_ns;            // wall-clock nanoseconds
} sub_stats_t;

// Type-specific fast paths (no function pointer overhead, no indirection).
// There is deliberately NO generic qsort-compatible entry point: an opaque
// comparator defeats classification and vectorization by construction, so a
// void*/compar shim could only ever delegate to libc -- removed at ABI v3.
SUB_API void sublimation_i32(int32_t *SUB_RESTRICT arr, size_t n);
SUB_API void sublimation_i64(int64_t *SUB_RESTRICT arr, size_t n);
SUB_API void sublimation_u32(uint32_t *SUB_RESTRICT arr, size_t n);
SUB_API void sublimation_u64(uint64_t *SUB_RESTRICT arr, size_t n);
SUB_API void sublimation_f32(float *SUB_RESTRICT arr, size_t n);
SUB_API void sublimation_f64(double *SUB_RESTRICT arr, size_t n);

// Type-specific with stats (comparison_efficiency vs the hook-length bound)
SUB_API void sublimation_i32_stats(int32_t *SUB_RESTRICT arr, size_t n, sub_stats_t *stats);
SUB_API void sublimation_i64_stats(int64_t *SUB_RESTRICT arr, size_t n, sub_stats_t *stats);
SUB_API void sublimation_u32_stats(uint32_t *SUB_RESTRICT arr, size_t n, sub_stats_t *stats);
SUB_API void sublimation_u64_stats(uint64_t *SUB_RESTRICT arr, size_t n, sub_stats_t *stats);
SUB_API void sublimation_f32_stats(float  *SUB_RESTRICT arr, size_t n, sub_stats_t *stats);
SUB_API void sublimation_f64_stats(double *SUB_RESTRICT arr, size_t n, sub_stats_t *stats);

// Classification only (inspect without sorting)
SUB_NODISCARD SUB_API
sub_profile_t sublimation_classify_i32(const int32_t *arr, size_t n) SUB_PURE;
SUB_NODISCARD SUB_API
sub_profile_t sublimation_classify_i64(const int64_t *arr, size_t n) SUB_PURE;
SUB_NODISCARD SUB_API
sub_profile_t sublimation_classify_u32(const uint32_t *arr, size_t n) SUB_PURE;
SUB_NODISCARD SUB_API
sub_profile_t sublimation_classify_u64(const uint64_t *arr, size_t n) SUB_PURE;
SUB_NODISCARD SUB_API
sub_profile_t sublimation_classify_f32(const float  *arr, size_t n) SUB_PURE;
SUB_NODISCARD SUB_API
sub_profile_t sublimation_classify_f64(const double *arr, size_t n) SUB_PURE;

// Selection: the k-th smallest element (0-based) via quickselect on the same
// partition machinery the sort uses -- O(n) average, no full sort. Partitions
// `arr` in place like std::nth_element (arr[k] ends holding the result; the left
// side <= it, the right side >= it) and returns arr[k]. The 1:1 replacement for
// std::nth_element. k is clamped to n-1; n == 0 returns 0.
SUB_API int32_t  sublimation_select_i32(int32_t  *SUB_RESTRICT arr, size_t n, size_t k);
SUB_API int64_t  sublimation_select_i64(int64_t  *SUB_RESTRICT arr, size_t n, size_t k);
SUB_API uint32_t sublimation_select_u32(uint32_t *SUB_RESTRICT arr, size_t n, size_t k);
SUB_API uint64_t sublimation_select_u64(uint64_t *SUB_RESTRICT arr, size_t n, size_t k);
SUB_API float    sublimation_select_f32(float    *SUB_RESTRICT arr, size_t n, size_t k);
SUB_API double   sublimation_select_f64(double   *SUB_RESTRICT arr, size_t n, size_t k);

// Binary search into an already-sorted array: the insertion index of `value`.
// side 0 = lower_bound (first i with sorted[i] >= value); side 1 = upper_bound
// (first i with sorted[i] > value). Returns n when value sits past the end. The
// 1:1 replacement for std::lower_bound / std::upper_bound.
SUB_API size_t sublimation_searchsorted_i32(const int32_t  *sorted, size_t n, int32_t  value, int side);
SUB_API size_t sublimation_searchsorted_i64(const int64_t  *sorted, size_t n, int64_t  value, int side);
SUB_API size_t sublimation_searchsorted_u32(const uint32_t *sorted, size_t n, uint32_t value, int side);
SUB_API size_t sublimation_searchsorted_u64(const uint64_t *sorted, size_t n, uint64_t value, int side);
SUB_API size_t sublimation_searchsorted_f32(const float    *sorted, size_t n, float    value, int side);
SUB_API size_t sublimation_searchsorted_f64(const double   *sorted, size_t n, double   value, int side);

// _Generic dispatch macros: route to the correct type-specific function at
// compile time. Three variants: plain sort, sort+stats, classify.
#define sublimation_typed(arr, n) _Generic((arr),        \
    int32_t *:  sublimation_i32,                         \
    int64_t *:  sublimation_i64,                         \
    uint32_t *: sublimation_u32,                         \
    uint64_t *: sublimation_u64,                         \
    float *:    sublimation_f32,                         \
    double *:   sublimation_f64                          \
)(arr, n)

#define sublimation_typed_stats(arr, n, stats) _Generic((arr), \
    int32_t *:  sublimation_i32_stats,                   \
    int64_t *:  sublimation_i64_stats,                   \
    uint32_t *: sublimation_u32_stats,                   \
    uint64_t *: sublimation_u64_stats,                   \
    float *:    sublimation_f32_stats,                   \
    double *:   sublimation_f64_stats                    \
)(arr, n, stats)

#define sublimation_typed_classify(arr, n) _Generic((arr), \
    const int32_t *:  sublimation_classify_i32,          \
    const int64_t *:  sublimation_classify_i64,          \
    const uint32_t *: sublimation_classify_u32,          \
    const uint64_t *: sublimation_classify_u64,          \
    const float *:    sublimation_classify_f32,          \
    const double *:   sublimation_classify_f64,          \
    int32_t *:  sublimation_classify_i32,                \
    int64_t *:  sublimation_classify_i64,                \
    uint32_t *: sublimation_classify_u32,                \
    uint64_t *: sublimation_classify_u64,                \
    float *:    sublimation_classify_f32,                \
    double *:   sublimation_classify_f64                 \
)(arr, n)

#define sublimation_typed_select(arr, n, k) _Generic((arr), \
    int32_t *:  sublimation_select_i32,                  \
    int64_t *:  sublimation_select_i64,                  \
    uint32_t *: sublimation_select_u32,                  \
    uint64_t *: sublimation_select_u64,                  \
    float *:    sublimation_select_f32,                  \
    double *:   sublimation_select_f64                   \
)(arr, n, k)

#define sublimation_typed_searchsorted(sorted, n, value, side) _Generic((sorted), \
    const int32_t *:  sublimation_searchsorted_i32,      \
    const int64_t *:  sublimation_searchsorted_i64,      \
    const uint32_t *: sublimation_searchsorted_u32,      \
    const uint64_t *: sublimation_searchsorted_u64,      \
    const float *:    sublimation_searchsorted_f32,      \
    const double *:   sublimation_searchsorted_f64,      \
    int32_t *:  sublimation_searchsorted_i32,            \
    int64_t *:  sublimation_searchsorted_i64,            \
    uint32_t *: sublimation_searchsorted_u32,            \
    uint64_t *: sublimation_searchsorted_u64,            \
    float *:    sublimation_searchsorted_f32,            \
    double *:   sublimation_searchsorted_f64             \
)(sorted, n, value, side)

// Parallel sort (explicit thread count). i64-only in v1.2.0 -- the IPS4o
// bucket pool is hard-coded for int64_t. Other types will be added in a
// later release; for now use the serial `sublimation_<T>` entries.
SUB_API void sublimation_i64_parallel(int64_t *SUB_RESTRICT arr, size_t n, size_t num_threads);

// Version queries. `sublimation_api_version()` returns SUBLIMATION_API_VERSION
// (ABI). `sublimation_version()` returns the release string (e.g. "1.2.0").
SUB_API int sublimation_api_version(void) SUB_CONST;
SUB_API const char *sublimation_version(void) SUB_CONST;

#ifdef __cplusplus
}
#endif

// Non-numeric entry points. Pulled in as an umbrella so callers including
// just `sublimation.h` get the strings API without a second include.
#include "sublimation_strings.h"

#endif // SUBLIMATION_H
