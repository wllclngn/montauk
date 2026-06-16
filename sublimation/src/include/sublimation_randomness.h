// sublimation_randomness.h -- fused randomness-confidence battery
//
// Pure randomness is not positively certifiable (Kolmogorov: randomness =
// incompressibility, and compressibility is uncomputable; no finite test
// proves randomness, only fails to reject it). What this battery returns is the
// honest object: a confidence that an input is at maximum entropy, formed as a
// MEET over several ORTHOGONAL structure-detectors. Each lens projects the
// input onto a different mathematical basis with a known maximum-entropy fixed
// point. A sequence that hides structure in one basis betrays it in another, so
// the determination is the simultaneous collapse of every projection to its
// max-entropy value -- and confidence rises with the number of independent
// bases that agree, but never reaches 1.
//
// The six lenses (mutually orthogonal foundations):
//   HOOK         representation theory  -- Frame-Robinson-Thrall hook-length
//                                          entropy of the Young-tableau shape
//   LIS          RSK / random matrix    -- longest increasing subseq -> 2*sqrt(n)
//                                          (Baik-Deift-Johansson, Tracy-Widom)
//   INVERSION    order statistics       -- inversion fraction -> 1/2
//   DISTINCT     cardinality            -- distinct-value ratio -> 1
//   HVG          visibility topology    -- horizontal-visibility mean degree -> 4
//                                          (Luque-Lacasa)
//   BANDT_POMPE  ordinal dynamics       -- d=3 permutation entropy -> 1
//
// Read-only: the input array is never modified. Thread-safe on disjoint inputs.
#ifndef SUBLIMATION_RANDOMNESS_H
#define SUBLIMATION_RANDOMNESS_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "internal/c23_compat.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SUB_RANDOMNESS_LENSES 6

// Stable indices into sub_randomness_t.lens[] / lens_available[].
enum {
    SUB_LENS_HOOK        = 0,  // hook-length entropy ratio (representation theory)
    SUB_LENS_LIS         = 1,  // LIS proximity to 2*sqrt(n) (RSK / Tracy-Widom)
    SUB_LENS_INVERSION   = 2,  // inversion ratio proximity to 1/2 (order statistics)
    SUB_LENS_DISTINCT    = 3,  // distinct-value ratio (cardinality)
    SUB_LENS_HVG         = 4,  // horizontal-visibility mean degree -> 4 (topology)
    SUB_LENS_BANDT_POMPE = 5,  // d=3 permutation entropy -> 1 (ordinal dynamics)
};

// Battery result.
//   confidence       fused meet over the available lenses, in [0,1). Approaches
//                    but never reaches 1 (randomness is not positively
//                    certifiable). 0 when no lens is available or any lens
//                    finds clear structure.
//   lens[i]          per-projection max-entropy score in [0,1] (1 = fully
//                    consistent with maximum entropy on basis i).
//   lens_available[i] false when a lens could not be evaluated (the tableau
//                    lenses HOOK/LIS are only available for 256 <= n <= 10000).
//   lens_count       number of available lenses (the N in "k of N agree").
//   agree_count      number of available lenses scoring at/above the agreement
//                    threshold (the k). Confidence is capped at 1 - 2^-k.
typedef struct {
    float    confidence;
    float    lens[SUB_RANDOMNESS_LENSES];
    bool     lens_available[SUB_RANDOMNESS_LENSES];
    uint32_t lens_count;
    uint32_t agree_count;
} sub_randomness_t;

// Evaluate the battery. Cost is O(n) for the visibility/ordinal lenses plus the
// classify pass (which runs the Young-tableau shape for 256 <= n <= 10000).
// Returns a zeroed result (confidence 0) for n < 2.
SUB_API sub_randomness_t sublimation_randomness_u64(const uint64_t *arr, size_t n);
SUB_API sub_randomness_t sublimation_randomness_i64(const int64_t  *arr, size_t n);
SUB_API sub_randomness_t sublimation_randomness_f64(const double   *arr, size_t n);

#ifdef __cplusplus
}
#endif

#endif // SUBLIMATION_RANDOMNESS_H
