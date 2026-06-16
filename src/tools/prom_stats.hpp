// prom_stats — pure statistics + special functions for montauk_analyze's
// .prom population analysis (cross-run / cross-version inference) and the
// raw-event fractality report. No I/O, no Prometheus, no trace types: just
// numerics over std::vector<double>, so it is unit-testable in isolation and
// shared by the population reports (Path A + Path B) and the fractal report.
//
// All randomized procedures take an explicit seeded Rng so a run is
// reproducible. Deterministic procedures (Cliff's delta, Welch t, Student-t
// and studentized-range tail probabilities) carry no Rng and match scipy /
// the published critical-value tables exactly -- the parity oracle.
#pragma once

#include <cstdint>
#include <vector>

namespace montauk::stats {

// Deterministic PRNG (splitmix64-seeded xoshiro256**). Same seed -> same
// stream on every platform, unlike a library default whose internals drift.
struct Rng {
  uint64_t s[4];
  explicit Rng(uint64_t seed);
  uint64_t next_u64();
  double next_unit();        // [0, 1)
  uint64_t below(uint64_t n); // uniform [0, n), Lemire-debiased
};

// numpy-compatible linear-interpolation percentile (method="linear"), q in
// [0, 100]. Takes the vector by value (sorts a copy via sublimation).
double percentile(std::vector<double> v, double q);
double mean(const std::vector<double>& v);
double variance(const std::vector<double>& v);  // sample variance, ddof=1

// Cliff's delta in [-1, 1]. >0: `a` tends to exceed `b`. Tie-corrected,
// O((n+m) log m) via a sorted-b search. Deterministic.
double cliffs_delta(const std::vector<double>& a, const std::vector<double>& b);
const char* cliff_magnitude(double d);  // negligible/small/medium/large

// Two-sided permutation test on |stat(a) - stat(b)|, distribution-free.
// stat selects the test statistic. Returns p = (ge + 1) / (n_perm + 1).
enum class Stat { Mean, Percentile };
double perm_test(const std::vector<double>& a, const std::vector<double>& b,
                 Stat stat, double q, Rng& rng, int n_perm = 2000);

// MC power: sweep run-count n in [2, nmax]; at each, draw B experiments of n
// per-run statistics from each pool and test with a Welch t. Returns the
// smallest n reaching `target` power (0 if none within nmax). `curve`, if
// non-null, is filled with power at each n.
int mc_power(const std::vector<double>& pa, const std::vector<double>& pb,
             Rng& rng, double alpha = 0.05, double target = 0.8,
             int nmax = 20, int B = 2000, std::vector<double>* curve = nullptr);

// Hsu's MCB via bootstrap simultaneous CIs on theta_i - best-of-rest.
// verdict: 1 = best, 0 = tied-for-best, -1 = not best.
struct McbResult { double lo, hi; int verdict; };
std::vector<McbResult> bootstrap_mcb(
    const std::vector<std::vector<double>>& groups,
    bool lower_is_better, Rng& rng, int B = 2000);

// Student-t upper-tail P(T > t) for t >= 0, via the regularized incomplete
// beta. Deterministic; matches scipy.stats.t.sf.
double student_t_sf(double t, double df);
// Two-sided Welch t-test p-value for unequal variance / n. 1.0 if degenerate.
double welch_t_p(const std::vector<double>& a, const std::vector<double>& b);

// Studentized-range upper tail P(Q > q) for k groups and df error d.o.f.,
// via Gauss-Legendre quadrature of the Tukey range integral. Deterministic;
// matches scipy.stats.studentized_range.sf and the Tukey critical tables.
double studentized_range_sf(double q, int k, double df);

// Games-Howell pairwise comparison (unequal variance/n) on the studentized
// range. mean_diff = mean_i - mean_j; p is the two-sided studentized-range p.
struct GhPair { int i, j; double mean_diff, p; };
std::vector<GhPair> games_howell(const std::vector<std::vector<double>>& groups);

// FRACTALITY (raw-event rate series).
// Detrended fluctuation analysis Hurst exponent. Fills *se with the slope
// standard error and *decades with the log10 span of fitted scales. NaN if
// too short / degenerate.
double dfa_hurst(const std::vector<double>& x, double* se, double* decades);
// Rescaled-range (R/S) Hurst, dyadic windows. Cross-check for DFA. NaN if short.
double rs_hurst(const std::vector<double>& x);
// Migration-avalanche tail: maximal runs above the active-interval median;
// size = value summed over the run. Returns the run count and (if >=5 runs)
// the CCDF log-log slope in *slope (NaN otherwise).
int avalanche_tail(const std::vector<double>& rate, double* slope);

}  // namespace montauk::stats
