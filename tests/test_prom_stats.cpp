// Characterization tests for the population statistics kernel
// (src/tools/prom_stats.cpp). This is the safety net the stats-kernel
// migration phases land behind: known answers against the oracles the
// header itself names (numpy-linear percentiles, published t and
// studentized-range table values), brute-force references for the
// combinatorial primitives, hand-counted exact-enumeration cases and
// determinism pins for the seeded Monte Carlo paths. Loose semantic bands
// (separated pools give small p, identical pools give large p) make an
// intentional estimator change fail legibly, not mysteriously.
#include "minitest.hpp"
#include "prom_stats.hpp"

#include <cmath>
#include <vector>

using montauk::stats::Rng;
namespace stats = montauk::stats;

static bool near(double a, double b, double tol) { return std::fabs(a - b) <= tol; }

// numpy percentile(method="linear") known answers
TEST(stats_percentile_numpy_linear) {
  std::vector<double> v{1, 2, 3, 4};
  ASSERT_TRUE(near(stats::percentile(v, 0.0), 1.0, 1e-12));
  ASSERT_TRUE(near(stats::percentile(v, 25.0), 1.75, 1e-12));
  ASSERT_TRUE(near(stats::percentile(v, 50.0), 2.5, 1e-12));
  ASSERT_TRUE(near(stats::percentile(v, 100.0), 4.0, 1e-12));
}

TEST(stats_mean_variance_ddof1) {
  std::vector<double> v{1, 2, 3, 4};
  ASSERT_TRUE(near(stats::mean(v), 2.5, 1e-12));
  ASSERT_TRUE(near(stats::variance(v), 5.0 / 3.0, 1e-12));
  ASSERT_TRUE(near(stats::variance({7.0}), 0.0, 1e-12));  // singleton: 0
}

// Cliff's delta against a brute-force O(na*nb) reference
static double cliff_brute(const std::vector<double>& a,
                          const std::vector<double>& b) {
  double gt = 0, lt = 0;
  for (double x : a)
    for (double y : b) {
      if (x > y) ++gt;
      if (x < y) ++lt;
    }
  return (gt - lt) / (static_cast<double>(a.size()) * b.size());
}

TEST(stats_cliffs_delta_reference) {
  ASSERT_TRUE(near(stats::cliffs_delta({1, 2, 3}, {4, 5, 6}), -1.0, 1e-12));
  ASSERT_TRUE(near(stats::cliffs_delta({4, 5, 6}, {1, 2, 3}), 1.0, 1e-12));
  ASSERT_TRUE(near(stats::cliffs_delta({1, 4}, {2, 3}), 0.0, 1e-12));
  // ties and mixed overlap, vs brute force
  std::vector<double> a{1, 2, 2, 5, 9};
  std::vector<double> b{2, 3, 4, 4};
  ASSERT_TRUE(near(stats::cliffs_delta(a, b), cliff_brute(a, b), 1e-12));
}

// Student-t upper tail against published critical values: P(T > t_{0.025,df})
// must be 0.025 at the table point.
TEST(stats_student_t_table_values) {
  ASSERT_TRUE(near(stats::student_t_sf(12.706, 1.0), 0.025, 1e-3));
  ASSERT_TRUE(near(stats::student_t_sf(2.228, 10.0), 0.025, 1e-3));
  ASSERT_TRUE(near(stats::student_t_sf(1.812, 10.0), 0.05, 1e-3));
}

// Studentized range upper tail at a published 5% critical value
// (q_{0.05}(k=3, df=10) = 3.88).
TEST(stats_studentized_range_table_value) {
  ASSERT_TRUE(near(stats::studentized_range_sf(3.88, 3, 10.0), 0.05, 5e-3));
}

// Exact enumeration: hand-counted C(4,2)=6 arrangement set. Pool {1,2,3,4},
// observed |mean({1,2}) - mean({3,4})| = 2; exactly the two extreme splits
// tie-or-exceed it, so p = 2/6.
TEST(stats_perm_exact_hand_counted) {
  Rng rng(1);
  double p = stats::perm_test({1, 2}, {3, 4}, stats::Stat::Mean, 0.0, rng);
  ASSERT_TRUE(near(p, 2.0 / 6.0, 1e-12));
  // C(6,3)=20, extremes again: p = 2/20. No Monte Carlo error, no floor.
  Rng rng2(1);
  double p2 = stats::perm_test({1, 2, 3}, {10, 11, 12}, stats::Stat::Mean,
                               0.0, rng2);
  ASSERT_TRUE(near(p2, 0.1, 1e-12));
}

TEST(stats_perm_identical_pools_p1) {
  Rng rng(7);
  double p = stats::perm_test({1, 2, 3}, {1, 2, 3}, stats::Stat::Mean, 0.0, rng);
  ASSERT_TRUE(near(p, 1.0, 1e-12));  // every split ties obs = 0
}

TEST(stats_perm_singletons_p1) {
  Rng rng(7);
  ASSERT_TRUE(near(stats::perm_test({5}, {900}, stats::Stat::Mean, 0.0, rng),
                   1.0, 1e-12));
}

// MC path (pools too large to enumerate): seeded determinism plus the
// semantic band for a fully separated pair.
TEST(stats_perm_mc_deterministic_and_small_p) {
  std::vector<double> a, b;
  for (int i = 0; i < 12; ++i) {
    a.push_back(i * 0.1);
    b.push_back(100.0 + i * 0.1);
  }
  Rng r1(1729), r2(1729);
  double p1 = stats::perm_test(a, b, stats::Stat::Mean, 0.0, r1);
  double p2 = stats::perm_test(a, b, stats::Stat::Mean, 0.0, r2);
  ASSERT_EQ(p1, p2);            // same seed, same stream, same answer
  ASSERT_TRUE(p1 < 0.01);       // fully separated: at the Monte Carlo floor
}

TEST(stats_power_short_circuits_and_band) {
  Rng rng(1);
  // Two zero-variance pools: power is 0 by construction, no simulation.
  ASSERT_EQ(stats::mc_power({5, 5, 5}, {9, 9, 9}, rng), 0);
  // Huge effect, tiny noise: the smallest sweep value must suffice.
  Rng r1(1729), r2(1729);
  int n1 = stats::mc_power({0, 0.1, 0.2}, {100, 100.1, 100.2}, r1);
  int n2 = stats::mc_power({0, 0.1, 0.2}, {100, 100.1, 100.2}, r2);
  ASSERT_EQ(n1, n2);            // seeded determinism
  ASSERT_TRUE(n1 >= 2 && n1 <= 3);
}

TEST(stats_mcb_all_constant_exact) {
  Rng rng(1);
  auto r = stats::bootstrap_mcb({{1.0}, {2.0}}, /*lower_is_better=*/true, rng);
  ASSERT_EQ(r[0].verdict, 1);
  ASSERT_EQ(r[1].verdict, -1);
  ASSERT_EQ(r[0].lo, r[0].hi);  // deterministic point, not an interval
}
