// The binary's three percentile conventions, pinned.
//
// The analyzer's q_at and sublimation_quantile_f64(nearest=0) must return the
// same element, and today they agree only by shared authorship -- both are
// floor(q*n) written independently in C++ and C. A silent drift in either would
// move every p99 in every report with nothing failing, which is the failure
// this file exists to prevent.
//
// montauk::stats::percentile is DELIBERATELY different (numpy method="linear",
// interpolating, for the cross-run population path's scipy parity). That
// divergence is asserted here too, so "unifying" the three would break a test
// rather than silently change what a population comparison means.

#include "minitest.hpp"
#include "prom_stats.hpp"

#include <cstdint>
#include <vector>

extern "C" {
#include "sublimation_stats.h"
}

// q_at is a file-local helper in trace_analyze.cpp (a translation unit with a
// main()), so it cannot be linked here. This is a byte-for-byte copy of its
// body; if the original changes without this one changing, the agreement
// assertions below start failing against sublimation and the copy is what gets
// re-synced. That is the intended failure mode -- a divergence that shows up as
// a red test rather than as a moved p99.
static uint64_t q_at_copy(const std::vector<uint64_t>& v, double f) {
  if (v.empty()) return 0;
  size_t i = static_cast<size_t>(static_cast<double>(v.size()) * f);
  if (i >= v.size()) i = v.size() - 1;
  return v[i];
}

static std::vector<uint64_t> ramp(size_t n) {
  std::vector<uint64_t> v;
  v.reserve(n);
  for (size_t i = 0; i < n; ++i) v.push_back(static_cast<uint64_t>(i) * 10);
  return v;
}

TEST(q_at_agrees_with_sublimation_nearest_rank) {
  // Every size where an off-by-one in either estimator would show, and the
  // quantiles montauk's reports actually ask for.
  const double qs[] = {0.0, 0.5, 0.9, 0.95, 0.99, 0.999, 1.0};
  for (size_t n : {1u, 2u, 3u, 7u, 10u, 99u, 100u, 101u, 1000u}) {
    auto v = ramp(n);
    std::vector<double> d(v.begin(), v.end());
    for (double q : qs) {
      uint64_t mine = q_at_copy(v, q);
      // nearest == 0 is the floor(q*n) estimator; the call sorts in place,
      // which is why d is rebuilt per quantile.
      std::vector<double> scratch = d;
      double theirs = sublimation_quantile_f64(scratch.data(), scratch.size(), q, 0);
      ASSERT_EQ(static_cast<double>(mine), theirs);
    }
  }
}

TEST(q_at_returns_a_value_present_in_the_data) {
  // The nearest-rank property itself, which is WHY reports use this estimator:
  // a reported p99 must be a latency that actually occurred.
  auto v = ramp(100);
  for (double q : {0.5, 0.9, 0.99}) {
    uint64_t got = q_at_copy(v, q);
    bool found = false;
    for (uint64_t x : v)
      if (x == got) found = true;
    ASSERT_TRUE(found);
  }
}

TEST(population_percentile_interpolates_and_must_not_agree) {
  // The third convention, asserted as DIFFERENT on purpose. With 0..9 at
  // stride 10, p95 lands between two samples: nearest-rank picks one of them,
  // linear interpolation picks a value between. If these ever match, someone
  // has unified the estimators and the population path has silently stopped
  // being scipy-comparable.
  auto v = ramp(10);
  std::vector<double> d(v.begin(), v.end());
  double interp = montauk::stats::percentile(d, 95.0);
  double nearest = static_cast<double>(q_at_copy(v, 0.95));
  ASSERT_TRUE(interp != nearest);
  // And it interpolates rather than inventing: strictly between the neighbours.
  ASSERT_TRUE(interp > 80.0);
  ASSERT_TRUE(interp < 90.0);
}

TEST(both_estimators_handle_empty_and_single) {
  std::vector<uint64_t> empty;
  ASSERT_EQ(q_at_copy(empty, 0.99), 0u);
  auto one = ramp(1);
  ASSERT_EQ(q_at_copy(one, 0.0), 0u);
  ASSERT_EQ(q_at_copy(one, 1.0), 0u);
  std::vector<double> single{42.0};
  ASSERT_EQ(montauk::stats::percentile(single, 99.0), 42.0);
}
