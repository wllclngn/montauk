// randomness.c -- fused randomness-confidence battery (sublimation_randomness.h)
//
// Gathers eight orthogonal-basis lenses and fuses them into a single
// confidence. Four lenses are read off sublimation_classify (hook-length
// entropy, LIS, inversion ratio, distinct ratio); two are computed directly
// from the values (HVG mean degree, Bandt-Pompe entropy) via randomness_impl.h;
// two more run on bounded type-erased samples (RQA determinism over a leading
// window, spectral flatness over a strided sample fed through spectral.c's
// comparison Laplacian). The fusion is a MEET: any basis that finds structure
// vetoes via the minimum, and confidence is capped at 1 - 2^-k where k is the
// number of bases that agree it is random; the verdict classifies k against
// the available count.
#include "sublimation_randomness.h"
#include "sublimation.h"
#include "include/internal/sort_internal.h"

#include <stdlib.h>
#include <math.h>

// Per-type lens helpers (HVG, Bandt-Pompe, samplers).
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

// RQA lens: leading-window size, minimum n, target recurrence rate.
#define SUB_RAND_RQA_WINDOW 512
#define SUB_RAND_RQA_MIN_N  64
#define SUB_RAND_RQA_RATE   0.10

// Spectral lens: gap_ratio (lambda_2 / lambda_max) an IID series holds on the
// 64-point comparison Laplacian. Calibrated on seeded uniform noise: observed
// [0.044, 0.073] over 20 seeds (plus full-range-u64 and small-n runs); the
// baseline sits at the low end so IID reliably scores >= the agreement
// threshold while clustering (few-unique 0.009, tight cycles 0.021) vetoes.
#define SUB_RAND_SPECTRAL_FLAT_BASELINE 0.05

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

// RQA determinism (Webber-Zbilut DET) over a type-erased sample, dimension-1
// embedding. eps is the ~10th-percentile pairwise distance (deterministic
// selection: sort the m(m-1)/2 distances with the library's own f64 sort and
// index at 10%), so the recurrence rate is pinned near 10%. DET = fraction of
// recurrence points lying on diagonal segments of length >= 2, main diagonal
// excluded, computed over the upper triangle (the plot is symmetric and DET is
// a ratio). Baseline: for an IID series a recurrence point extends a diagonal
// iff either diagonal neighbor is also recurrent, each independently with
// probability rr, so E[DET] = 1 - (1-rr)^2 = rr*(2-rr) -- verified on 20
// seeded uniform runs (DET in [0.181, 0.199] against 0.19 analytic at
// rr = 0.10). Score = 1 - max(0, (DET - base) / (1 - base)): IID sits near 1,
// determinism (chaos included: continuity stacks recurrences into diagonals)
// drives DET up and the score toward 0.
// Returns availability; unavailable when the distance distribution is
// degenerate (eps = 0, e.g. heavy ties) or no recurrence point exists.
static bool sub_rqa_score(const double *s, size_t m, float *score) {
    *score = 0.0f;
    if (m < 2) return false;
    size_t npairs = m * (m - 1) / 2;
    double *dist = (double *)malloc(npairs * sizeof(double));
    if (!dist) return false;
    size_t k = 0;
    for (size_t i = 0; i < m; i++)
        for (size_t j = i + 1; j < m; j++)
            dist[k++] = fabs(s[i] - s[j]);
    sublimation_f64(dist, npairs);
    double eps = dist[(size_t)(SUB_RAND_RQA_RATE * (double)npairs)];
    free(dist);
    if (!(eps > 0.0)) return false;

    unsigned char *R = (unsigned char *)calloc(m * m, 1);
    if (!R) return false;
    size_t rec = 0;
    for (size_t i = 0; i < m; i++)
        for (size_t j = i + 1; j < m; j++)
            if (fabs(s[i] - s[j]) < eps) { R[i * m + j] = 1; rec++; }
    size_t on_lines = 0;
    for (size_t off = 1; off < m; off++) {
        size_t run = 0;
        for (size_t i = 0; i + off < m; i++) {
            if (R[i * m + (i + off)]) run++;
            else { if (run >= 2) on_lines += run; run = 0; }
        }
        if (run >= 2) on_lines += run;
    }
    free(R);
    if (rec == 0) return false;

    double rr = (double)rec / (double)npairs;
    double det = (double)on_lines / (double)rec;
    double base = rr * (2.0 - rr);           // analytic IID expectation
    if (base >= 1.0) return false;
    double excess = (det - base) / (1.0 - base);
    if (excess < 0.0) excess = 0.0;
    *score = sub_clampf(1.0f - (float)excess);
    return true;
}

// Spectral flatness over spectral.c's comparison Laplacian. The sample is
// mapped order- and proximity-preserving onto an int64 grid (spectral.c's
// builder takes int64 and reweights edges by value proximity), the Laplacian
// is built with the same deterministic seed recipe spectral sort uses, and
// Jacobi (spectral.c) yields the spectrum. gap_ratio = lambda_2 / lambda_max:
// an IID sample's graph stays uniformly connected (flat spectrum, ratio at the
// calibrated baseline); value clustering builds heavy intra-cluster edges,
// inflating lambda_max while algebraic connectivity lambda_2 stalls, and the
// ratio collapses. Score = clamp(gap_ratio / baseline). Note the lens reads
// value-distribution structure; a sorted series has a flat comparison spectrum
// too and passes here (the order lenses veto it).
// Returns availability; unavailable when Jacobi fails to converge (honored
// from spectral.c's 0 return) or the spectrum is degenerate.
static bool sub_spectral_flat_score(const double *s, size_t m, float *score) {
    *score = 0.0f;
    if (m < SUB_SPECTRAL_MIN_N) return false;

    double lo = s[0], hi = s[0];
    for (size_t i = 1; i < m; i++) {
        if (s[i] < lo) lo = s[i];
        if (s[i] > hi) hi = s[i];
    }
    double range = hi - lo;

    int64_t *grid = (int64_t *)malloc(m * sizeof(int64_t));
    double  *L    = (double *)malloc(m * m * sizeof(double));
    double  *work = (double *)malloc(m * m * sizeof(double));
    double  *ev   = (double *)malloc(m * sizeof(double));
    bool ok = grid && L && work && ev;
    if (ok) {
        for (size_t i = 0; i < m; i++)
            grid[i] = range > 0.0 ? (int64_t)(((s[i] - lo) / range) * 1e9) : 0;
        sub_build_comparison_laplacian(grid, m, L, 0x12345678ull ^ (uint64_t)m);
        size_t iters = sub_jacobi_eigendecompose(L, ev, m, work);
        if (iters == 0) {
            ok = false;                       // Jacobi did not converge
        } else {
            double lmax = ev[m - 1];
            if (lmax <= SUB_EIGENVALUE_ZERO_THRESH) {
                ok = false;                   // degenerate spectrum
            } else {
                double ratio = sub_spectral_gap(ev, m) / lmax;
                *score = sub_clampf((float)(ratio / SUB_RAND_SPECTRAL_FLAT_BASELINE));
            }
        }
    }
    free(grid);
    free(L);
    free(work);
    free(ev);
    return ok;
}

// Fuse per-lens scores into a confidence. meet = min over available lenses
// (structure anywhere vetoes); ceiling = 1 - 2^-k caps confidence by the number
// of independent agreeing bases and keeps it strictly below 1 (Kolmogorov).
// The verdict classifies k against the available count N: k == N max-entropy,
// k >= N-1 consistent, k >= N/2 mixed, else structured.
static sub_randomness_t sub_fuse(const float score[SUB_RANDOMNESS_LENSES],
                                 const bool avail[SUB_RANDOMNESS_LENSES]) {
    sub_randomness_t r;
    r.confidence = 0.0f;
    r.verdict = SUB_RAND_STRUCTURED;
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
    if (r.agree_count == r.lens_count)          r.verdict = SUB_RAND_MAX_ENTROPY;
    else if (r.agree_count + 1 >= r.lens_count) r.verdict = SUB_RAND_CONSISTENT;
    else if (r.agree_count >= r.lens_count / 2) r.verdict = SUB_RAND_MIXED;
    float ceiling = 1.0f - ldexpf(1.0f, -(int)r.agree_count);  // 1 - 2^-k; k=0 -> 0
    r.confidence = ceiling * meet;
    return r;
}

// Map the classify profile + the value-domain lenses to scores. Shared across
// the typed entry points; deg, bph and the RQA/spectral readings are
// precomputed per type.
static sub_randomness_t sub_randomness_from(const sub_profile_t *p, size_t n,
                                            double deg, double bph,
                                            float rqa, bool rqa_avail,
                                            float spec, bool spec_avail) {
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

    // DISTINCT: distinct-value ratio. Few-unique data vetoes here. Every
    // classify path with n >= 2 fills distinct_estimate (fast paths included);
    // 0 survives only as "not computed" (trivial n), where the lens is
    // honestly unavailable.
    if (p->distinct_estimate > 0) {
        score[SUB_LENS_DISTINCT] = sub_clampf((float)((double)p->distinct_estimate / (double)n));
        avail[SUB_LENS_DISTINCT] = true;
    } else {
        score[SUB_LENS_DISTINCT] = 0.0f;
        avail[SUB_LENS_DISTINCT] = false;
    }

    // HVG: mean degree mapped from [2 (periodic), 4 (IID)] onto [0,1].
    score[SUB_LENS_HVG] = sub_clampf((float)((deg - 2.0) / 2.0));
    avail[SUB_LENS_HVG] = true;

    // BANDT_POMPE: normalized d=3 permutation entropy, already in [0,1].
    score[SUB_LENS_BANDT_POMPE] = sub_clampf((float)bph);
    avail[SUB_LENS_BANDT_POMPE] = true;

    // RQA: recurrence-plot determinism against the IID baseline.
    score[SUB_LENS_RQA] = rqa;
    avail[SUB_LENS_RQA] = rqa_avail;

    // SPECTRAL: comparison-Laplacian spectral flatness.
    score[SUB_LENS_SPECTRAL] = spec;
    avail[SUB_LENS_SPECTRAL] = spec_avail;

    return sub_fuse(score, avail);
}

#define SUB_RANDOMNESS_BODY(SUFFIX)                                             \
    if (n < 2) { sub_randomness_t z = {0}; return z; }                          \
    sub_profile_t p = sublimation_classify##SUFFIX(arr, n);                     \
    float rqa = 0.0f, spec = 0.0f;                                              \
    bool rqa_avail = false, spec_avail = false;                                 \
    double sample[SUB_RAND_RQA_WINDOW];                                         \
    if (n >= SUB_RAND_RQA_MIN_N) {                                              \
        size_t m = sub_rand_window_f64##SUFFIX(arr, n, sample,                  \
                                               SUB_RAND_RQA_WINDOW);            \
        rqa_avail = sub_rqa_score(sample, m, &rqa);                             \
    }                                                                           \
    if (n >= SUB_SPECTRAL_MIN_N) {                                              \
        size_t m = sub_rand_stride_f64##SUFFIX(arr, n, sample,                  \
                                               SUB_SPECTRAL_MIN_N);             \
        spec_avail = sub_spectral_flat_score(sample, m, &spec);                 \
    }                                                                           \
    return sub_randomness_from(&p, n, sub_hvg_mean_degree##SUFFIX(arr, n),      \
                               sub_bandt_pompe_h##SUFFIX(arr, n),               \
                               rqa, rqa_avail, spec, spec_avail)

sub_randomness_t sublimation_randomness_u64(const uint64_t *arr, size_t n) {
    SUB_RANDOMNESS_BODY(_u64);
}

sub_randomness_t sublimation_randomness_i64(const int64_t *arr, size_t n) {
    SUB_RANDOMNESS_BODY(_i64);
}

sub_randomness_t sublimation_randomness_f64(const double *arr, size_t n) {
    SUB_RANDOMNESS_BODY(_f64);
}
