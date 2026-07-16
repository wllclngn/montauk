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
// The eight lenses (mutually orthogonal foundations):
//   HOOK         representation theory  -- Frame-Robinson-Thrall hook-length
//                                          entropy of the Young-tableau shape
//   LIS          RSK / random matrix    -- longest increasing subseq -> 2*sqrt(n)
//                                          (Baik-Deift-Johansson, Tracy-Widom)
//   INVERSION    order statistics       -- inversion fraction -> 1/2
//   DISTINCT     cardinality            -- distinct-value ratio -> 1
//   HVG          visibility topology    -- horizontal-visibility mean degree -> 4
//                                          (Luque-Lacasa)
//   BANDT_POMPE  ordinal dynamics       -- d=3 permutation entropy -> 1
//   RQA          recurrence dynamics    -- recurrence-plot determinism (DET) at
//                                          ~10% recurrence rate -> IID baseline
//                                          rr*(2-rr) (Webber-Zbilut). Determinism
//                                          (chaos included) stacks recurrences
//                                          into diagonal lines and vetoes.
//   SPECTRAL     spectral graph theory  -- flatness of the comparison-Laplacian
//                                          spectrum: gap_ratio lambda_2/lambda_max
//                                          holds a calibrated IID level; value
//                                          clustering collapses algebraic
//                                          connectivity against the spectral
//                                          radius and vetoes.
//
// Fusion: confidence = (1 - 2^-k) * meet, where meet is the MINIMUM score over
// the available lenses (structure anywhere vetoes) and k is the number of
// available lenses scoring at/above the agreement threshold (0.70). The verdict
// summarizes k against the available count N:
//   MAX_ENTROPY   k == N          every basis agrees it is random
//   CONSISTENT    k >= N - 1      all but one agree
//   MIXED         k >= N / 2      split reading
//   STRUCTURED    otherwise       structure found in most bases
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

#define SUB_RANDOMNESS_LENSES 8

// Stable indices into sub_randomness_t.lens[] / lens_available[].
enum {
    SUB_LENS_HOOK        = 0,  // hook-length entropy ratio (representation theory)
    SUB_LENS_LIS         = 1,  // LIS proximity to 2*sqrt(n) (RSK / Tracy-Widom)
    SUB_LENS_INVERSION   = 2,  // inversion ratio proximity to 1/2 (order statistics)
    SUB_LENS_DISTINCT    = 3,  // distinct-value ratio (cardinality)
    SUB_LENS_HVG         = 4,  // horizontal-visibility mean degree -> 4 (topology)
    SUB_LENS_BANDT_POMPE = 5,  // d=3 permutation entropy -> 1 (ordinal dynamics)
    SUB_LENS_RQA         = 6,  // recurrence determinism -> IID baseline (dynamics)
    SUB_LENS_SPECTRAL    = 7,  // comparison-Laplacian spectral flatness (graphs)
};

// Fused verdict: how many of the available bases agree the input is random.
typedef enum {
    SUB_RAND_STRUCTURED  = 0,  // k < N/2: structure found in most bases
    SUB_RAND_MIXED       = 1,  // k >= N/2: split reading
    SUB_RAND_CONSISTENT  = 2,  // k >= N-1: all but one basis agree
    SUB_RAND_MAX_ENTROPY = 3,  // k == N: every available basis agrees
} sub_rand_verdict_t;

// Battery result.
//   confidence       fused meet over the available lenses, in [0,1). Approaches
//                    but never reaches 1 (randomness is not positively
//                    certifiable). 0 when no lens is available or any lens
//                    finds clear structure.
//   verdict          k-of-N agreement class (see sub_rand_verdict_t). Structured
//                    when no lens is available.
//   lens[i]          per-projection max-entropy score in [0,1] (1 = fully
//                    consistent with maximum entropy on basis i).
//   lens_available[i] false when a lens could not be evaluated (the tableau
//                    lenses HOOK/LIS are only available for 256 <= n <= 10000;
//                    RQA and SPECTRAL require n >= 64, RQA additionally needs a
//                    non-degenerate distance distribution and SPECTRAL a
//                    converged Jacobi eigendecomposition; DISTINCT is
//                    unavailable when classify's fast path skipped the
//                    estimate).
//   lens_count       number of available lenses (the N in "k of N agree").
//   agree_count      number of available lenses scoring at/above the agreement
//                    threshold (the k). Confidence is capped at 1 - 2^-k.
typedef struct {
    float              confidence;
    sub_rand_verdict_t verdict;
    float              lens[SUB_RANDOMNESS_LENSES];
    bool               lens_available[SUB_RANDOMNESS_LENSES];
    uint32_t           lens_count;
    uint32_t           agree_count;
} sub_randomness_t;

// Evaluate the battery. Cost is O(n) for the visibility/ordinal lenses plus the
// classify pass (which runs the Young-tableau shape for 256 <= n <= 10000), a
// bounded RQA pass over a 512-point leading window and a bounded Jacobi
// eigendecomposition over a 64-point strided sample.
// Returns a zeroed result (confidence 0, verdict structured) for n < 2.
SUB_API sub_randomness_t sublimation_randomness_u64(const uint64_t *arr, size_t n);
SUB_API sub_randomness_t sublimation_randomness_i64(const int64_t  *arr, size_t n);
SUB_API sub_randomness_t sublimation_randomness_f64(const double   *arr, size_t n);

#ifdef __cplusplus
}
#endif

#endif // SUBLIMATION_RANDOMNESS_H
