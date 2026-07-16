// sort_internal.h -- Internal types and constants for the adaptive sort
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
SUB_CONSTEXPR float  SUB_RESCAN_GROWTH      = 1.5f;   // global rescan trigger growth rate

// Depth-adaptive DFS
SUB_CONSTEXPR int    SUB_STACK_LIMIT        = 48;     // max recursion before iterative (log2-based)

// Subarray reclassification interval (periodic global relabel)
SUB_CONSTEXPR int    SUB_RECLASSIFY_INTERVAL = 8;     // reclassify every N recursion levels

// Damped oscillator constants. Second-order critically-damped form, the
// float analog of PANDEMONIUM's fixed-point reference (main.bpf.c, the
// Idle Quiescence Envelope): damping 1/8 with spring 1/128 gives the
// Butterworth-optimal damping ratio (zeta ~ 0.707, damping/(2*sqrt(spring))),
// deliberate ~4 percent overshoot, fastest settle without ringing.
SUB_CONSTEXPR float  SUB_OSC_DAMPING        = 0.125f;     // velocity decay (-2*gamma*v)
SUB_CONSTEXPR float  SUB_OSC_SPRING         = 0.0078125f; // restore toward the signal (1/128)
SUB_CONSTEXPR float  SUB_OSC_ENERGY_DECAY   = 0.125f;     // energy reservoir leak per step
// Dead band: displacement inside the slack is measurement jitter and
// contributes NO energy -- the noise floor is modeled before anything is
// detected against it, the property the CUSUM this replaced lacked (a
// literal change-point accumulator chatters on the floor). Park/release
// form a Schmitt trigger: release needs 2x the park energy, so the
// detector cannot flap at the threshold.
SUB_CONSTEXPR float  SUB_OSC_SLACK          = 0.25f;
SUB_CONSTEXPR float  SUB_OSC_ENERGY_PARK    = 0.125f;     // 2 * SLACK^2
SUB_CONSTEXPR float  SUB_OSC_ENERGY_RELEASE = 0.25f;      // 2 * PARK

// Type-generic swap
#define SUB_SWAP(T, a, b) do { T _sub_tmp = (a); (a) = (b); (b) = _sub_tmp; } while (0)

// Type-generic function naming (macro template instantiation)
#define SUB_CONCAT2(a, b) a ## b
#define SUB_CONCAT(a, b) SUB_CONCAT2(a, b)
#define SUB_TYPED(name) SUB_CONCAT(name, SUB_SUFFIX)

// Damped-oscillator regime detector. One primitive serves both detection
// sites (partition-quality degradation in the sort, phase boundaries in the
// classifier), replacing the EWMA baseline + CUSUM accumulator pair that
// lived here before: the position IS the tracked signal level (the spring
// pulls it toward each sample, so no separate baseline), and detection is
// energy-based with a dead band and a Schmitt trigger, so a single-sample
// spike decays and never fires while a sustained regime shift pumps the
// reservoir past release. This is PANDEMONIUM's Idle Quiescence Envelope
// primitive in float form; EWMA/CUSUM survive only in tests, as oracles.
typedef struct {
    float position;   // tracked signal level (the oscillator's own baseline)
    float velocity;
    float energy;     // leaky displacement+velocity reservoir
    bool  primed;     // position seeded from the first sample
    bool  excited;    // Schmitt state: fired and not yet re-parked
} sub_osc_t;

// Feed one sample; returns true exactly once per detected regime shift
// (on the parked -> released transition).
SUB_INLINE bool sub_osc_detect(sub_osc_t *o, float sample) {
    if (!o->primed) {
        o->position = sample;
        o->primed = true;
        return false;
    }
    float disp = sample - o->position;
    o->velocity += disp * SUB_OSC_SPRING;              // spring toward the signal
    o->velocity -= o->velocity * SUB_OSC_DAMPING;      // damping
    o->position += o->velocity;
    // Dead-banded energy: displacement inside the slack is jitter and
    // contributes nothing; only a genuine level shift pumps the reservoir.
    float pump = (disp > SUB_OSC_SLACK || disp < -SUB_OSC_SLACK) ? disp * disp : 0.0f;
    o->energy -= o->energy * SUB_OSC_ENERGY_DECAY;
    o->energy += pump + o->velocity * o->velocity;
    if (o->excited) {
        if (o->energy < SUB_OSC_ENERGY_PARK) o->excited = false;  // re-park
        return false;
    }
    if (o->energy > SUB_OSC_ENERGY_RELEASE) {
        o->excited = true;
        return true;
    }
    return false;
}

// Adaptive state tracked across recursion levels
typedef struct sub_adaptive_tag {
    sub_osc_t partition_osc;       // partition-badness regime detector
    size_t levels_built;           // total level constructions
    size_t gap_prunes;             // empty-region prunes
    size_t rescans;                // full reclassification rescans
    size_t rescan_trigger;         // current rescan trigger threshold
    int    depth;                  // current recursion depth
    uint64_t comparisons;
    uint64_t swaps;
    bool     spectral_attempted;   // has spectral path been tried this sort?
    float    last_spectral_gap;    // last observed spectral gap ratio
    // equal element tracking
    int64_t  last_pivot;           // pivot value from previous partition
    bool     has_last_pivot;       // whether last_pivot is valid
} sub_adaptive_t;

// Initialize adaptive state
SUB_INLINE void sub_adaptive_init(sub_adaptive_t *a, size_t n) {
    memset(a, 0, sizeof(*a));
    // Seed the badness level at the balanced midpoint rather than priming
    // from the first partition, so one early bad pivot reads as
    // displacement, not as the baseline.
    a->partition_osc.position = 0.5f;
    a->partition_osc.primed = true;
    a->rescan_trigger = n / 8;
    if (a->rescan_trigger < 64) a->rescan_trigger = 64;
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
