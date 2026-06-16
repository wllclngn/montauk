// sort_internal.h -- Internal types and constants for the flow-model sort
#ifndef SUB_SORT_INTERNAL_H
#define SUB_SORT_INTERNAL_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdatomic.h>

#include "c23_compat.h"
#include "../sublimation.h"
#include "spectral.h"

// Thresholds (analogues of flow solver constants)
SUB_CONSTEXPR size_t SUB_SMALL_THRESHOLD     = 32;   // base case: insertion sort / SIMD network
SUB_CONSTEXPR size_t SUB_MEDIUM_THRESHOLD    = 128;   // switch from simple to block partition
SUB_CONSTEXPR size_t SUB_PARALLEL_THRESHOLD  = 250000; // spawn parallel workers (below this, serial PCF/adaptive is faster than thread spin-up)
SUB_CONSTEXPR size_t SUB_CLASSIFY_SAMPLE     = 128;   // sample size for inversion estimation
SUB_CONSTEXPR size_t SUB_PATIENCE_THRESHOLD  = 256;   // minimum n for patience sorting in classify
SUB_CONSTEXPR size_t SUB_TABLEAU_MAX_N      = 10000;  // max n for full Young tableau computation
SUB_CONSTEXPR size_t SUB_TABLEAU_MAX_LIS    = 256;    // max LIS length for hook length computation

// Adaptive control constants
SUB_CONSTEXPR float  SUB_EWMA_ALPHA         = 0.25f;  // EWMA smoothing factor
SUB_CONSTEXPR float  SUB_CUSUM_K            = 0.25f;  // CUSUM slack parameter
SUB_CONSTEXPR float  SUB_CUSUM_H            = 2.0f;   // CUSUM trigger threshold
SUB_CONSTEXPR float  SUB_RESCAN_GROWTH      = 1.5f;   // global rescan trigger growth rate

// Depth-adaptive DFS
SUB_CONSTEXPR int    SUB_STACK_LIMIT        = 48;     // max recursion before iterative (log2-based)

// Subarray reclassification interval (periodic global relabel)
SUB_CONSTEXPR int    SUB_RECLASSIFY_INTERVAL = 8;     // reclassify every N recursion levels

// Damped oscillator constants
SUB_CONSTEXPR float  SUB_OSC_PULL           = 0.1f;   // impulse magnitude on degradation
SUB_CONSTEXPR float  SUB_OSC_RELAX          = 0.02f;  // relax impulse when stable
SUB_CONSTEXPR float  SUB_OSC_DAMPING        = 0.125f; // velocity decay (v -= v * damping)

// Type-generic swap
#define SUB_SWAP(T, a, b) do { T _sub_tmp = (a); (a) = (b); (b) = _sub_tmp; } while (0)

// Type-generic function naming (macro template instantiation)
#define SUB_CONCAT2(a, b) a ## b
#define SUB_CONCAT(a, b) SUB_CONCAT2(a, b)
#define SUB_TYPED(name) SUB_CONCAT(name, SUB_SUFFIX)

// Adaptive state tracked across recursion levels
typedef struct sub_adaptive_tag {
    float  partition_quality_ewma;  // EWMA of pivot rank / partition size
    float  cusum_s;                // CUSUM accumulator
    size_t levels_built;           // total level constructions
    size_t gap_prunes;             // empty-region prunes
    size_t rescans;                // full reclassification rescans
    size_t rescan_trigger;         // current rescan trigger threshold
    int    depth;                  // current recursion depth
    uint64_t comparisons;
    uint64_t swaps;
    bool     spectral_attempted;   // has spectral path been tried this sort?
    float    last_spectral_gap;    // last observed spectral gap ratio
    // damped oscillator state
    float    osc_velocity;         // current velocity
    float    osc_position;         // current position (normalized threshold)
    // equal element tracking
    int64_t  last_pivot;           // pivot value from previous partition
    bool     has_last_pivot;       // whether last_pivot is valid
} sub_adaptive_t;

// Initialize adaptive state
SUB_INLINE void sub_adaptive_init(sub_adaptive_t *a, size_t n) {
    memset(a, 0, sizeof(*a));
    a->partition_quality_ewma = 0.5f;
    a->osc_position = 0.5f; // midpoint: balanced sensitivity
    a->rescan_trigger = n / 8;
    if (a->rescan_trigger < 64) a->rescan_trigger = 64;
}

// EWMA update
SUB_INLINE void sub_ewma_update(float *ewma, float sample) {
    *ewma = SUB_EWMA_ALPHA * sample + (1.0f - SUB_EWMA_ALPHA) * (*ewma);
}

// CUSUM update with oscillator-controlled threshold
// The oscillator position (0..1) scales the CUSUM trigger:
//   position near 0 = tightened = trigger at low CUSUM (sensitive)
//   position near 1 = relaxed = trigger at high CUSUM (permissive)
// This replaces the hardcoded SUB_CUSUM_H constant.
SUB_INLINE bool sub_cusum_update(float *cusum_s, float sample,
                                  float baseline, float osc_position) {
    float deviation = sample - baseline - SUB_CUSUM_K;
    if (deviation > 0.0f) {
        *cusum_s += deviation;
    } else {
        *cusum_s *= 0.5f; // decay
    }
    // threshold driven by oscillator: range [0.5, 3.0]
    float threshold = 0.5f + osc_position * 2.5f;
    return *cusum_s > threshold;
}

// Damped oscillator update.
// Drives the CUSUM threshold: tightens on degradation, relaxes when stable.
SUB_INLINE void sub_oscillator_update(float *position, float *velocity,
                                       bool degraded) {
    float impulse = degraded ? -SUB_OSC_PULL : SUB_OSC_RELAX;
    *velocity += impulse;
    *velocity -= *velocity * SUB_OSC_DAMPING; // decay
    *position += *velocity;
    if (*position < 0.0f) *position = 0.0f;
    if (*position > 1.0f) *position = 1.0f;
}

// AVX2 random-data sort path (i64 only).
//
// sub_random_sort_i64 is the production SUB_RANDOM entry point: a
// linear-PCF top-level bucketer (Sato-Matsui 2024, static B per workload)
// feeding AVX2 quicksort with sort-network leaves.
// sub_avx2_random_quicksort_i64 is the underlying engine, exported because
// sub_random_sort_i64 also calls it to sort its training sample.
#ifdef __AVX2__
void sub_random_sort_i64(int64_t *arr, size_t n);
void sub_avx2_random_quicksort_i64(int64_t *arr, size_t n);

// BMI2 PEXT-based in-place block partition (Edelkamp-Weiss + AVX2/PEXT).
// Partitions arr[lo..hi) around `pivot`. Returns p such that
// arr[lo..p) < pivot and arr[p..hi) >= pivot. Output is a permutation of input.
// Exposed for standalone unit testing in tests/test_pext_partition.c.
size_t block_partition_pext_i64(int64_t *arr, size_t lo, size_t hi, int64_t pivot);
#endif

// Internal sort functions -- all types
// Names follow template pattern: base_name + type suffix
void sub_sort_internal_i32(int32_t *restrict arr, size_t n, sub_adaptive_t *state);
void sub_sort_internal_i64(int64_t *restrict arr, size_t n, sub_adaptive_t *state);
void sub_sort_internal_u32(uint32_t *restrict arr, size_t n, sub_adaptive_t *state);
void sub_sort_internal_u64(uint64_t *restrict arr, size_t n, sub_adaptive_t *state);
void sub_sort_internal_f32(float *restrict arr, size_t n, sub_adaptive_t *state);
void sub_sort_internal_f64(double *restrict arr, size_t n, sub_adaptive_t *state);

void sub_small_sort_i32(int32_t *arr, size_t n, uint64_t *comparisons, uint64_t *swaps);
void sub_small_sort_i64(int64_t *arr, size_t n, uint64_t *comparisons, uint64_t *swaps);
void sub_small_sort_u32(uint32_t *arr, size_t n, uint64_t *comparisons, uint64_t *swaps);
void sub_small_sort_u64(uint64_t *arr, size_t n, uint64_t *comparisons, uint64_t *swaps);
void sub_small_sort_f32(float *arr, size_t n, uint64_t *comparisons, uint64_t *swaps);
void sub_small_sort_f64(double *arr, size_t n, uint64_t *comparisons, uint64_t *swaps);

// Classification -- all types
sub_profile_t sub_classify_internal_i32(const int32_t *arr, size_t n);
sub_profile_t sub_classify_internal_i64(const int64_t *arr, size_t n);
sub_profile_t sub_classify_internal_u32(const uint32_t *arr, size_t n);
sub_profile_t sub_classify_internal_u64(const uint64_t *arr, size_t n);
sub_profile_t sub_classify_internal_f32(const float *arr, size_t n);
sub_profile_t sub_classify_internal_f64(const double *arr, size_t n);

// Spectral merge tree -- all types
void sub_spectral_merge_i32(int32_t *arr, size_t n, uint64_t *comparisons);
void sub_spectral_merge_i64(int64_t *arr, size_t n, uint64_t *comparisons);
void sub_spectral_merge_u32(uint32_t *arr, size_t n, uint64_t *comparisons);
void sub_spectral_merge_u64(uint64_t *arr, size_t n, uint64_t *comparisons);
void sub_spectral_merge_f32(float *arr, size_t n, uint64_t *comparisons);
void sub_spectral_merge_f64(double *arr, size_t n, uint64_t *comparisons);

#endif // SUB_SORT_INTERNAL_H
