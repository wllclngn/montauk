// randomness.c -- fused randomness-confidence battery (sublimation_randomness.h)
//
// Gathers six orthogonal-basis lenses and fuses them into a single confidence.
// Four lenses are read off sublimation_classify (hook-length entropy, LIS,
// inversion ratio, distinct ratio); two are computed directly from the values
// (HVG mean degree, Bandt-Pompe entropy) via randomness_impl.h. The fusion is a
// MEET: any basis that finds structure vetoes via the minimum, and confidence
// is capped at 1 - 2^-k where k is the number of bases that agree it is random.
#include "sublimation_randomness.h"
#include "sublimation.h"
#include "include/internal/sort_internal.h"

#include <math.h>

// Per-type lens helpers (HVG, Bandt-Pompe).
#define SUB_TYPE uint64_t
#define SUB_SUFFIX _u64
#include "randomness_impl.h"
#undef SUB_TYPE
#undef SUB_SUFFIX

#define SUB_TYPE int64_t
#define SUB_SUFFIX _i64
#include "randomness_impl.h"
#undef SUB_TYPE
#undef SUB_SUFFIX

#define SUB_TYPE double
#define SUB_SUFFIX _f64
#include "randomness_impl.h"
#undef SUB_TYPE
#undef SUB_SUFFIX

// A lens "agrees it is random" at or above this max-entropy score.
#define SUB_RAND_AGREE_TAU 0.70f

static inline float sub_clampf(float x) {
    if (x < 0.0f) return 0.0f;
    if (x > 1.0f) return 1.0f;
    return x;
}

// log2(n!) via Stirling (same approximation classify uses for the hook bound).
static double sub_log2_factorial(size_t n) {
    if (n <= 1) return 0.0;
    double dn = (double)n;
    return dn * log2(dn) - dn * 1.4426950408889634 + 0.5 * log2(6.283185307179586 * dn);
}

// Fuse per-lens scores into a confidence. meet = min over available lenses
// (structure anywhere vetoes); ceiling = 1 - 2^-k caps confidence by the number
// of independent agreeing bases and keeps it strictly below 1 (Kolmogorov).
static sub_randomness_t sub_fuse(const float score[SUB_RANDOMNESS_LENSES],
                                 const bool avail[SUB_RANDOMNESS_LENSES]) {
    sub_randomness_t r;
    r.confidence = 0.0f;
    r.lens_count = 0;
    r.agree_count = 0;
    float meet = 1.0f;
    for (int i = 0; i < SUB_RANDOMNESS_LENSES; i++) {
        r.lens[i] = score[i];
        r.lens_available[i] = avail[i];
        if (!avail[i]) continue;
        r.lens_count++;
        if (score[i] < meet) meet = score[i];
        if (score[i] >= SUB_RAND_AGREE_TAU) r.agree_count++;
    }
    if (r.lens_count == 0) return r;
    float ceiling = 1.0f - ldexpf(1.0f, -(int)r.agree_count);  // 1 - 2^-k; k=0 -> 0
    r.confidence = ceiling * meet;
    return r;
}

// Map the classify profile + the two value-domain lenses to scores. Shared
// across the typed entry points; deg and bph are precomputed per type.
static sub_randomness_t sub_randomness_from(const sub_profile_t *p, size_t n,
                                            double deg, double bph) {
    float score[SUB_RANDOMNESS_LENSES];
    bool  avail[SUB_RANDOMNESS_LENSES];

    // The Young-tableau lenses are computed only in the patience window; outside
    // it they are honestly unavailable, not "structured".
    bool tableau = (n >= SUB_PATIENCE_THRESHOLD && n <= SUB_TABLEAU_MAX_N);

    // HOOK: hook-length entropy of the Young-tableau shape. The single-shape
    // standard-tableau count f^lambda is MAXIMIZED at the Plancherel-typical
    // shape, where log2(f^lambda) -> (1/2) log2(n!) (Vershik-Kerov); no shape
    // reaches log2(n!). So the achievable ceiling of the ratio is ~1/2, and a
    // maximally-disordered permutation lands near it. Normalize against that
    // ceiling (x2): random -> ~1, sorted/reversed (one row/column, f^lambda=1,
    // log2=0) -> 0.
    if (tableau && p->info_theoretic_bound > 0.0f) {
        double frac = (double)p->info_theoretic_bound / sub_log2_factorial(n);
        score[SUB_LENS_HOOK] = sub_clampf((float)(2.0 * frac));
        avail[SUB_LENS_HOOK] = true;
    } else {
        score[SUB_LENS_HOOK] = 0.0f;
        avail[SUB_LENS_HOOK] = false;
    }

    // LIS: proximity of the longest increasing subsequence to 2*sqrt(n).
    if (tableau && p->lis_length > 0) {
        double target = 2.0 * sqrt((double)n);
        double dev = fabs((double)p->lis_length - target) / target;
        score[SUB_LENS_LIS] = sub_clampf(1.0f - (float)dev);
        avail[SUB_LENS_LIS] = true;
    } else {
        score[SUB_LENS_LIS] = 0.0f;
        avail[SUB_LENS_LIS] = false;
    }

    // INVERSION: proximity of the inversion fraction to 1/2. Random -> 1/2.
    score[SUB_LENS_INVERSION] = sub_clampf(1.0f - 2.0f * fabsf(p->inversion_ratio - 0.5f));
    avail[SUB_LENS_INVERSION] = true;

    // DISTINCT: distinct-value ratio. Few-unique data vetoes here.
    score[SUB_LENS_DISTINCT] = sub_clampf((float)((double)p->distinct_estimate / (double)n));
    avail[SUB_LENS_DISTINCT] = true;

    // HVG: mean degree mapped from [2 (periodic), 4 (IID)] onto [0,1].
    score[SUB_LENS_HVG] = sub_clampf((float)((deg - 2.0) / 2.0));
    avail[SUB_LENS_HVG] = true;

    // BANDT_POMPE: normalized d=3 permutation entropy, already in [0,1].
    score[SUB_LENS_BANDT_POMPE] = sub_clampf((float)bph);
    avail[SUB_LENS_BANDT_POMPE] = true;

    return sub_fuse(score, avail);
}

sub_randomness_t sublimation_randomness_u64(const uint64_t *arr, size_t n) {
    if (n < 2) { sub_randomness_t z = {0}; return z; }
    sub_profile_t p = sublimation_classify_u64(arr, n);
    return sub_randomness_from(&p, n, sub_hvg_mean_degree_u64(arr, n),
                               sub_bandt_pompe_h_u64(arr, n));
}

sub_randomness_t sublimation_randomness_i64(const int64_t *arr, size_t n) {
    if (n < 2) { sub_randomness_t z = {0}; return z; }
    sub_profile_t p = sublimation_classify_i64(arr, n);
    return sub_randomness_from(&p, n, sub_hvg_mean_degree_i64(arr, n),
                               sub_bandt_pompe_h_i64(arr, n));
}

sub_randomness_t sublimation_randomness_f64(const double *arr, size_t n) {
    if (n < 2) { sub_randomness_t z = {0}; return z; }
    sub_profile_t p = sublimation_classify_f64(arr, n);
    return sub_randomness_from(&p, n, sub_hvg_mean_degree_f64(arr, n),
                               sub_bandt_pompe_h_f64(arr, n));
}
