// prom_stats — implementation. See prom_stats.hpp.
//
// Sorting goes through sublimation_f64 (montauk's in-tree flow-model sort),
// the same primitive every other ordering in the analyzer uses. Special
// functions (incomplete beta for Student-t, Gauss/Simpson quadrature for the
// studentized range) are self-contained: no scipy, no GSL.
#include "prom_stats.hpp"

#include "sublimation.h"  // sublimation_f64: ascending double sort

#include <algorithm>
#include <cmath>
#include <cstddef>

namespace montauk::stats {

namespace {

void sort_asc(std::vector<double>& v) {
  if (v.size() > 1) sublimation_f64(v.data(), v.size());
}

constexpr double kInvSqrt2 = 0.7071067811865476;
constexpr double kInvSqrt2Pi = 0.3989422804014327;

double norm_pdf(double x) { return kInvSqrt2Pi * std::exp(-0.5 * x * x); }
double norm_cdf(double x) { return 0.5 * std::erfc(-x * kInvSqrt2); }

// Regularized incomplete beta I_x(a,b) via the Lentz continued fraction.
double betacf(double a, double b, double x) {
  const int kMaxIter = 300;
  const double kEps = 3.0e-12;
  const double kFpMin = 1.0e-300;
  double qab = a + b, qap = a + 1.0, qam = a - 1.0;
  double c = 1.0;
  double d = 1.0 - qab * x / qap;
  if (std::fabs(d) < kFpMin) d = kFpMin;
  d = 1.0 / d;
  double h = d;
  for (int m = 1; m <= kMaxIter; ++m) {
    double m2 = 2.0 * m;
    double aa = m * (b - m) * x / ((qam + m2) * (a + m2));
    d = 1.0 + aa * d;
    if (std::fabs(d) < kFpMin) d = kFpMin;
    c = 1.0 + aa / c;
    if (std::fabs(c) < kFpMin) c = kFpMin;
    d = 1.0 / d;
    h *= d * c;
    aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2));
    d = 1.0 + aa * d;
    if (std::fabs(d) < kFpMin) d = kFpMin;
    c = 1.0 + aa / c;
    if (std::fabs(c) < kFpMin) c = kFpMin;
    d = 1.0 / d;
    double del = d * c;
    h *= del;
    if (std::fabs(del - 1.0) < kEps) break;
  }
  return h;
}

double betai(double a, double b, double x) {
  if (x <= 0.0) return 0.0;
  if (x >= 1.0) return 1.0;
  double lbeta = std::lgamma(a + b) - std::lgamma(a) - std::lgamma(b);
  double bt = std::exp(lbeta + a * std::log(x) + b * std::log(1.0 - x));
  if (x < (a + 1.0) / (a + b + 2.0))
    return bt * betacf(a, b, x) / a;
  return 1.0 - bt * betacf(b, a, 1.0 - x) / b;
}

// CDF of the range of k iid standard normals at w: k ∫ φ(x)[Φ(x+w)-Φ(x)]^{k-1}.
double range_cdf(double w, int k) {
  if (w <= 0.0) return 0.0;
  const int kN = 400;             // Simpson intervals (even)
  const double lo = -8.0 - w, hi = 8.0;
  const double h = (hi - lo) / kN;
  double acc = 0.0;
  for (int i = 0; i <= kN; ++i) {
    double x = lo + i * h;
    double inner = norm_cdf(x + w) - norm_cdf(x);
    double f = (inner <= 0.0) ? 0.0
                              : norm_pdf(x) * std::pow(inner, k - 1);
    double wgt = (i == 0 || i == kN) ? 1.0 : (i & 1 ? 4.0 : 2.0);
    acc += wgt * f;
  }
  return std::min(1.0, std::max(0.0, k * acc * h / 3.0));
}

}  // namespace

// splitmix64-seeded xoshiro256**.
static uint64_t splitmix64(uint64_t& x) {
  uint64_t z = (x += 0x9E3779B97F4A7C15ULL);
  z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
  z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
  return z ^ (z >> 31);
}
static uint64_t rotl(uint64_t x, int k) { return (x << k) | (x >> (64 - k)); }

Rng::Rng(uint64_t seed) {
  uint64_t sm = seed;
  for (int i = 0; i < 4; ++i) s[i] = splitmix64(sm);
}
uint64_t Rng::next_u64() {
  uint64_t result = rotl(s[1] * 5, 7) * 9;
  uint64_t t = s[1] << 17;
  s[2] ^= s[0];
  s[3] ^= s[1];
  s[1] ^= s[2];
  s[0] ^= s[3];
  s[2] ^= t;
  s[3] = rotl(s[3], 45);
  return result;
}
double Rng::next_unit() {
  return (next_u64() >> 11) * (1.0 / 9007199254740992.0);
}
uint64_t Rng::below(uint64_t n) {
  if (n == 0) return 0;
  // Lemire's debiased multiply-shift.
  __uint128_t m = static_cast<__uint128_t>(next_u64()) * n;
  uint64_t low = static_cast<uint64_t>(m);
  if (low < n) {
    uint64_t thresh = (-n) % n;
    while (low < thresh) {
      m = static_cast<__uint128_t>(next_u64()) * n;
      low = static_cast<uint64_t>(m);
    }
  }
  return static_cast<uint64_t>(m >> 64);
}

double mean(const std::vector<double>& v) {
  if (v.empty()) return 0.0;
  double s = 0.0;
  for (double x : v) s += x;
  return s / v.size();
}

double variance(const std::vector<double>& v) {
  if (v.size() < 2) return 0.0;
  double m = mean(v), s = 0.0;
  for (double x : v) s += (x - m) * (x - m);
  return s / (v.size() - 1);
}

double percentile(std::vector<double> v, double q) {
  if (v.empty()) return 0.0;
  if (v.size() == 1) return v[0];
  sort_asc(v);
  double rank = q / 100.0 * (v.size() - 1);
  double flo = std::floor(rank);
  size_t lo = static_cast<size_t>(flo);
  double frac = rank - flo;
  if (lo + 1 < v.size()) return v[lo] + frac * (v[lo + 1] - v[lo]);
  return v[lo];
}

double cliffs_delta(const std::vector<double>& a, const std::vector<double>& b) {
  if (a.empty() || b.empty()) return 0.0;
  std::vector<double> bs = b;
  sort_asc(bs);
  long long acc = 0;
  const size_t nb = bs.size();
  for (double x : a) {
    size_t less = sublimation_searchsorted_f64(bs.data(), bs.size(), x, 0);  // lower_bound
    size_t gt = nb - sublimation_searchsorted_f64(bs.data(), bs.size(), x, 1);  // upper_bound
    acc += static_cast<long long>(less) - static_cast<long long>(gt);
  }
  return static_cast<double>(acc) /
         (static_cast<double>(a.size()) * static_cast<double>(nb));
}

const char* cliff_magnitude(double d) {
  double a = std::fabs(d);
  if (a < 0.147) return "negligible";
  if (a < 0.33) return "small";
  if (a < 0.474) return "medium";
  return "large";
}

namespace {
double slice_stat(const std::vector<double>& pool, size_t begin, size_t end,
                  Stat stat, double q) {
  if (stat == Stat::Mean) {
    double s = 0.0;
    for (size_t i = begin; i < end; ++i) s += pool[i];
    return (end > begin) ? s / (end - begin) : 0.0;
  }
  std::vector<double> tmp(pool.begin() + begin, pool.begin() + end);
  return percentile(std::move(tmp), q);
}
}  // namespace

double perm_test(const std::vector<double>& a, const std::vector<double>& b,
                 Stat stat, double q, Rng& rng, int n_perm) {
  if (a.empty() || b.empty()) return 1.0;
  const size_t na = a.size();
  std::vector<double> pool;
  pool.reserve(na + b.size());
  pool.insert(pool.end(), a.begin(), a.end());
  pool.insert(pool.end(), b.begin(), b.end());
  double obs = std::fabs(slice_stat(pool, 0, na, stat, q) -
                         slice_stat(pool, na, pool.size(), stat, q));
  int ge = 0;
  const size_t n = pool.size();
  for (int p = 0; p < n_perm; ++p) {
    for (size_t i = n - 1; i > 0; --i) {  // Fisher-Yates
      size_t j = rng.below(i + 1);
      std::swap(pool[i], pool[j]);
    }
    double d = std::fabs(slice_stat(pool, 0, na, stat, q) -
                         slice_stat(pool, na, n, stat, q));
    if (d >= obs) ++ge;
  }
  return static_cast<double>(ge + 1) / (n_perm + 1);
}

int mc_power(const std::vector<double>& pa, const std::vector<double>& pb,
             Rng& rng, double alpha, double target, int nmax, int B,
             std::vector<double>* curve) {
  if (curve) curve->assign(nmax + 1, 0.0);
  if (pa.empty() || pb.empty()) return 0;
  int chosen = 0;
  std::vector<double> xa, xb;
  for (int n = 2; n <= nmax; ++n) {
    xa.resize(n);
    xb.resize(n);
    int hits = 0;
    for (int b = 0; b < B; ++b) {
      for (int i = 0; i < n; ++i) {
        xa[i] = pa[rng.below(pa.size())];
        xb[i] = pb[rng.below(pb.size())];
      }
      double va = variance(xa) / n, vb = variance(xb) / n;
      double se = std::sqrt(va + vb);
      double pval = 1.0;
      if (se > 0.0) {
        double t = std::fabs(mean(xa) - mean(xb)) / se;
        double df = (va + vb) * (va + vb) /
                    (va * va / (n - 1) + vb * vb / (n - 1));
        pval = 2.0 * student_t_sf(t, df);
      }
      if (pval < alpha) ++hits;
    }
    double power = static_cast<double>(hits) / B;
    if (curve) (*curve)[n] = power;
    if (chosen == 0 && power >= target) chosen = n;
  }
  return chosen;
}

std::vector<McbResult> bootstrap_mcb(
    const std::vector<std::vector<double>>& groups, bool lower_is_better,
    Rng& rng, int B) {
  const size_t g = groups.size();
  std::vector<McbResult> out(g, {0.0, 0.0, 0});
  if (g < 2) return out;
  std::vector<std::vector<double>> boot(g, std::vector<double>(B, 0.0));
  std::vector<double> s(g, 0.0);
  for (int b = 0; b < B; ++b) {
    for (size_t k = 0; k < g; ++k) {
      const auto& grp = groups[k];
      double acc = 0.0;
      for (size_t i = 0; i < grp.size(); ++i) acc += grp[rng.below(grp.size())];
      s[k] = grp.empty() ? 0.0 : acc / grp.size();
    }
    for (size_t k = 0; k < g; ++k) {
      double ref = 0.0;
      bool seen = false;
      for (size_t o = 0; o < g; ++o) {
        if (o == k) continue;
        ref = !seen ? s[o]
                    : (lower_is_better ? std::min(ref, s[o])
                                       : std::max(ref, s[o]));
        seen = true;
      }
      boot[k][b] = s[k] - ref;
    }
  }
  for (size_t k = 0; k < g; ++k) {
    double lo = percentile(boot[k], 2.5);
    double hi = percentile(boot[k], 97.5);
    int verdict;
    if (lower_is_better)
      verdict = hi < 0.0 ? 1 : (lo > 0.0 ? -1 : 0);
    else
      verdict = lo > 0.0 ? 1 : (hi < 0.0 ? -1 : 0);
    out[k] = {lo, hi, verdict};
  }
  return out;
}

double student_t_sf(double t, double df) {
  if (df <= 0.0) return 0.5;
  double x = df / (df + t * t);
  double p = 0.5 * betai(0.5 * df, 0.5, x);  // P(T > |t|)
  return t >= 0.0 ? p : 1.0 - p;
}

double welch_t_p(const std::vector<double>& a, const std::vector<double>& b) {
  if (a.size() < 2 || b.size() < 2) return 1.0;
  double va = variance(a) / a.size(), vb = variance(b) / b.size();
  double se = std::sqrt(va + vb);
  if (se == 0.0) return 1.0;
  double t = (mean(a) - mean(b)) / se;
  double df = (va + vb) * (va + vb) /
              (va * va / (a.size() - 1) + vb * vb / (b.size() - 1));
  return std::min(1.0, 2.0 * student_t_sf(std::fabs(t), df));
}

double studentized_range_sf(double q, int k, double df) {
  if (q <= 0.0 || k < 2) return 1.0;
  // df very large -> the sd estimate is exact (s == 1): Q is just the range.
  if (df > 25000.0) return std::min(1.0, std::max(0.0, 1.0 - range_cdf(q, k)));
  // P(Q<=q) = ∫_0^∞ range_cdf(q*c, k) g(c) dc, c = s/sigma,
  // g(c) = 2 (df/2)^{df/2}/Γ(df/2) c^{df-1} e^{-df c^2/2}.
  const double half = 0.5 * df;
  const double logc0 = half * std::log(half) - std::lgamma(half) + std::log(2.0);
  const double cmax = 1.0 + 8.0 / std::sqrt(df);  // density is negligible past
  const int kN = 200;                              // Simpson intervals (even)
  const double h = cmax / kN;
  double acc = 0.0;
  for (int i = 0; i <= kN; ++i) {
    double c = i * h;
    double f = 0.0;
    if (c > 0.0) {
      double logg = logc0 + (df - 1.0) * std::log(c) - half * c * c;
      f = range_cdf(q * c, k) * std::exp(logg);
    }
    double wgt = (i == 0 || i == kN) ? 1.0 : (i & 1 ? 4.0 : 2.0);
    acc += wgt * f;
  }
  double cdf = acc * h / 3.0;
  return std::min(1.0, std::max(0.0, 1.0 - cdf));
}

std::vector<GhPair> games_howell(
    const std::vector<std::vector<double>>& groups) {
  std::vector<GhPair> out;
  const int k = static_cast<int>(groups.size());
  for (int i = 0; i < k; ++i) {
    for (int j = i + 1; j < k; ++j) {
      const auto& x = groups[i];
      const auto& y = groups[j];
      double md = mean(x) - mean(y);
      if (x.size() < 2 || y.size() < 2) {
        out.push_back({i, j, md, 1.0});
        continue;
      }
      double vi = variance(x) / x.size(), vj = variance(y) / y.size();
      double se = std::sqrt(vi + vj);
      if (se == 0.0) {
        out.push_back({i, j, md, 1.0});
        continue;
      }
      double t = std::fabs(md) / se;
      double dfw = (vi + vj) * (vi + vj) /
                   (vi * vi / (x.size() - 1) + vj * vj / (y.size() - 1));
      double p = studentized_range_sf(t * std::sqrt(2.0), k, dfw);
      out.push_back({i, j, md, std::min(1.0, p)});
    }
  }
  return out;
}

// FRACTALITY.

namespace {
// Order-1 least squares on (x,y); returns slope, fills *intercept.
double linfit(const std::vector<double>& xs, const std::vector<double>& ys,
              double* intercept, double* slope_se) {
  size_t n = xs.size();
  double sx = 0, sy = 0, sxx = 0, sxy = 0;
  for (size_t i = 0; i < n; ++i) {
    sx += xs[i];
    sy += ys[i];
    sxx += xs[i] * xs[i];
    sxy += xs[i] * ys[i];
  }
  double denom = n * sxx - sx * sx;
  if (denom == 0.0) {
    if (intercept) *intercept = 0.0;
    if (slope_se) *slope_se = NAN;
    return NAN;
  }
  double slope = (n * sxy - sx * sy) / denom;
  double icpt = (sy - slope * sx) / n;
  if (intercept) *intercept = icpt;
  if (slope_se && n > 2) {
    double sse = 0.0;
    for (size_t i = 0; i < n; ++i) {
      double r = ys[i] - (slope * xs[i] + icpt);
      sse += r * r;
    }
    double s2 = sse / (n - 2);
    *slope_se = std::sqrt(s2 * n / denom);
  } else if (slope_se) {
    *slope_se = NAN;
  }
  return slope;
}
}  // namespace

double dfa_hurst(const std::vector<double>& x, double* se, double* decades) {
  if (se) *se = NAN;
  if (decades) *decades = 0.0;
  const size_t n = x.size();
  if (n < 16) return NAN;
  double m = mean(x);
  std::vector<double> y(n);
  double run = 0.0;
  for (size_t i = 0; i < n; ++i) {
    run += x[i] - m;
    y[i] = run;
  }
  size_t smax = std::max<size_t>(8, n / 4);
  std::vector<int> scales;
  for (int j = 0; j < 14; ++j) {
    double lg = std::log10(4.0) +
                (std::log10(static_cast<double>(smax)) - std::log10(4.0)) *
                    j / 13.0;
    int s = static_cast<int>(std::floor(std::pow(10.0, lg)));
    if (s >= 4 && (scales.empty() || scales.back() != s)) scales.push_back(s);
  }
  std::vector<double> lx, ly;
  std::vector<double> tt;
  for (int s : scales) {
    size_t nseg = n / s;
    if (nseg < 1) continue;
    tt.resize(s);
    for (int i = 0; i < s; ++i) tt[i] = i;
    double rms_sum = 0.0;
    for (size_t v = 0; v < nseg; ++v) {
      std::vector<double> seg(y.begin() + v * s, y.begin() + v * s + s);
      double icpt, slope = linfit(tt, seg, &icpt, nullptr);
      double e = 0.0;
      for (int i = 0; i < s; ++i) {
        double r = seg[i] - (slope * i + icpt);
        e += r * r;
      }
      rms_sum += e / s;
    }
    double F = std::sqrt(rms_sum / nseg);
    if (F > 0.0) {
      lx.push_back(std::log(static_cast<double>(s)));
      ly.push_back(std::log(F));
    }
  }
  if (lx.size() < 3) return NAN;
  double slope_se, slope = linfit(lx, ly, nullptr, &slope_se);
  if (se) *se = slope_se;
  if (decades) {
    double mn = lx.front(), mx = lx.front();
    for (double v : lx) {
      mn = std::min(mn, v);
      mx = std::max(mx, v);
    }
    *decades = (mx - mn) / std::log(10.0);
  }
  return slope;
}

double rs_hurst(const std::vector<double>& x) {
  const size_t n = x.size();
  if (n < 16) return NAN;
  std::vector<double> ls, lrs;
  for (size_t s = 8; s <= n / 2; s *= 2) {
    size_t nseg = n / s;
    double acc = 0.0;
    int cnt = 0;
    for (size_t v = 0; v < nseg; ++v) {
      double mu = 0.0;
      for (size_t i = 0; i < s; ++i) mu += x[v * s + i];
      mu /= s;
      double z = 0.0, zmin = 0.0, zmax = 0.0, sd = 0.0;
      for (size_t i = 0; i < s; ++i) {
        double d = x[v * s + i] - mu;
        z += d;
        zmin = std::min(zmin, z);
        zmax = std::max(zmax, z);
        sd += d * d;
      }
      sd = std::sqrt(sd / s);
      if (sd > 0.0) {
        acc += (zmax - zmin) / sd;
        ++cnt;
      }
    }
    if (cnt > 0) {
      ls.push_back(std::log(static_cast<double>(s)));
      lrs.push_back(std::log(acc / cnt));
    }
  }
  if (ls.size() < 3) return NAN;
  return linfit(ls, lrs, nullptr, nullptr);
}

int avalanche_tail(const std::vector<double>& rate, double* slope) {
  if (slope) *slope = NAN;
  std::vector<double> active;
  for (double v : rate)
    if (v > 0.0) active.push_back(v);
  if (active.size() < 8) return 0;
  double thr = percentile(active, 50.0);
  std::vector<double> sizes;
  double r = 0.0;
  for (double v : rate) {
    if (v > thr) {
      r += v;
    } else if (r > 0.0) {
      sizes.push_back(r);
      r = 0.0;
    }
  }
  if (r > 0.0) sizes.push_back(r);
  if (sizes.size() < 5) return static_cast<int>(sizes.size());
  sort_asc(sizes);  // ascending; CCDF rank below uses descending order
  std::vector<double> lx, ly;
  const size_t ns = sizes.size();
  for (size_t i = 0; i < ns; ++i) {
    // sizes ascending: rank from the top = ns - i; CCDF = (ns - i)/ns.
    double s = sizes[i];
    if (s > 0.0) {
      lx.push_back(std::log(s));
      ly.push_back(std::log(static_cast<double>(ns - i) / ns));
    }
  }
  if (slope && lx.size() >= 2) *slope = linfit(lx, ly, nullptr, nullptr);
  return static_cast<int>(ns);
}

}  // namespace montauk::stats
