#include "minitest.hpp"
#include "util/TimSort.hpp"
#include <algorithm>
#include <numeric>
#include <random>
#include <vector>

using namespace montauk::util;

// Verify correctness on random data
TEST(timsort_correctness_random) {
  std::vector<size_t> data(1000);
  std::iota(data.begin(), data.end(), 0);
  std::mt19937 rng(42);
  std::shuffle(data.begin(), data.end(), rng);

  timsort(data.begin(), data.end(), [](size_t a, size_t b) { return a < b; });

  ASSERT_TRUE(std::is_sorted(data.begin(), data.end()));
}

// Verify stability (equal keys maintain relative order)
TEST(timsort_stability) {
  struct Item { int key; int seq; };
  std::vector<Item> items = {{1, 0}, {2, 1}, {1, 2}, {2, 3}, {1, 4}};
  std::vector<size_t> indices = {0, 1, 2, 3, 4};

  timsort(indices.begin(), indices.end(),
    [&](size_t a, size_t b) { return items[a].key < items[b].key; });

  // Equal keys should maintain original relative order
  int last_seq = -1;
  int last_key = -1;
  for (size_t idx : indices) {
    if (items[idx].key == last_key) {
      ASSERT_TRUE(items[idx].seq > last_seq);
    }
    last_key = items[idx].key;
    last_seq = items[idx].seq;
  }
}

// Data pattern that forces galloping: disjoint ranges
TEST(timsort_gallop_trigger) {
  std::vector<size_t> data;
  // [0-99] merged with [1000-1099] - one run always wins
  for (size_t i = 0; i < 100; ++i) data.push_back(i);
  for (size_t i = 1000; i < 1100; ++i) data.push_back(i);
  std::mt19937 rng1(1), rng2(2);
  std::shuffle(data.begin(), data.begin() + 100, rng1);
  std::shuffle(data.begin() + 100, data.end(), rng2);

  timsort(data.begin(), data.end(), [](size_t a, size_t b) { return a < b; });

  ASSERT_TRUE(std::is_sorted(data.begin(), data.end()));
}

// Already sorted - should be O(n) via pattern detection
TEST(timsort_already_sorted) {
  std::vector<size_t> data(1000);
  std::iota(data.begin(), data.end(), 0);

  timsort(data.begin(), data.end(), [](size_t a, size_t b) { return a < b; });

  ASSERT_TRUE(std::is_sorted(data.begin(), data.end()));
}

// Reversed - should be O(n) via pattern detection + reverse
TEST(timsort_reversed) {
  std::vector<size_t> data(1000);
  std::iota(data.begin(), data.end(), 0);
  std::reverse(data.begin(), data.end());

  timsort(data.begin(), data.end(), [](size_t a, size_t b) { return a < b; });

  ASSERT_TRUE(std::is_sorted(data.begin(), data.end()));
}

// All equal elements
TEST(timsort_all_equal) {
  std::vector<size_t> data(100, 42);

  timsort(data.begin(), data.end(), [](size_t a, size_t b) { return a < b; });

  for (auto v : data) ASSERT_EQ(v, 42u);
}

// Empty input
TEST(timsort_empty) {
  std::vector<size_t> data;
  timsort(data.begin(), data.end(), [](size_t a, size_t b) { return a < b; });
  ASSERT_TRUE(data.empty());
}

// Single element
TEST(timsort_single) {
  std::vector<size_t> data = {42};
  timsort(data.begin(), data.end(), [](size_t a, size_t b) { return a < b; });
  ASSERT_EQ(data[0], 42u);
}

// Small array (triggers binary insertion sort path)
TEST(timsort_small) {
  std::vector<size_t> data = {5, 3, 8, 1, 9, 2, 7, 4, 6, 0};
  timsort(data.begin(), data.end(), [](size_t a, size_t b) { return a < b; });
  ASSERT_TRUE(std::is_sorted(data.begin(), data.end()));
}

// Descending comparator
TEST(timsort_descending) {
  std::vector<size_t> data(100);
  std::iota(data.begin(), data.end(), 0);
  std::mt19937 rng(123);
  std::shuffle(data.begin(), data.end(), rng);

  timsort(data.begin(), data.end(), [](size_t a, size_t b) { return a > b; });

  ASSERT_TRUE(std::is_sorted(data.begin(), data.end(), std::greater<size_t>()));
}

// Large dataset simulating process list
TEST(timsort_stress_100k) {
  std::vector<size_t> data(100000);
  std::iota(data.begin(), data.end(), 0);
  std::mt19937 rng(12345);
  std::shuffle(data.begin(), data.end(), rng);

  timsort(data.begin(), data.end(), [](size_t a, size_t b) { return a < b; });

  ASSERT_TRUE(std::is_sorted(data.begin(), data.end()));
}

// Nearly sorted (few inversions) - should detect pattern
TEST(timsort_nearly_sorted) {
  std::vector<size_t> data(1000);
  std::iota(data.begin(), data.end(), 0);
  // Introduce ~2% inversions
  std::mt19937 rng(777);
  for (int i = 0; i < 20; ++i) {
    size_t a = rng() % data.size();
    size_t b = rng() % data.size();
    std::swap(data[a], data[b]);
  }

  timsort(data.begin(), data.end(), [](size_t a, size_t b) { return a < b; });

  ASSERT_TRUE(std::is_sorted(data.begin(), data.end()));
}

// Multiple natural runs (real-world pattern)
TEST(timsort_natural_runs) {
  std::vector<size_t> data;
  // Create 5 ascending runs of 50 elements each, interleaved
  for (int run = 0; run < 5; ++run) {
    for (int i = 0; i < 50; ++i) {
      data.push_back(run * 100 + i);
    }
  }
  // Shuffle runs but keep elements within each run sorted
  std::mt19937 rng(999);
  for (size_t i = 0; i < data.size(); i += 50) {
    // Each block of 50 is already sorted, shuffle blocks
  }
  // Actually interleave by shuffling
  std::shuffle(data.begin(), data.end(), rng);

  timsort(data.begin(), data.end(), [](size_t a, size_t b) { return a < b; });

  ASSERT_TRUE(std::is_sorted(data.begin(), data.end()));
}

// ============================================================================
// GALLOPING VERIFICATION VIA COMPARISON COUNTING
// ============================================================================
// Galloping's purpose is to reduce comparisons. We verify it by comparing
// our timsort against std::stable_sort on disjoint data patterns.
// With disjoint runs, galloping should significantly reduce comparisons.

// Helper: count comparisons for std::stable_sort on same data pattern
static size_t stable_sort_comparisons(std::vector<size_t> data) {
  size_t cmp = 0;
  std::stable_sort(data.begin(), data.end(), [&](size_t a, size_t b) {
    ++cmp;
    return a < b;
  });
  return cmp;
}

// 10K elements with disjoint runs - galloping should beat std::stable_sort
TEST(timsort_gallop_10k_disjoint) {
  // Two disjoint runs: [4999..0] reversed and [10000..14999] ascending
  std::vector<size_t> data;
  for (int i = 4999; i >= 0; --i) data.push_back(i);
  for (int i = 10000; i < 15000; ++i) data.push_back(i);

  size_t timsort_cmp = 0;
  timsort(data.begin(), data.end(), [&](size_t a, size_t b) {
    ++timsort_cmp;
    return a < b;
  });

  ASSERT_TRUE(std::is_sorted(data.begin(), data.end()));

  // Reset data for stable_sort comparison
  data.clear();
  for (int i = 4999; i >= 0; --i) data.push_back(i);
  for (int i = 10000; i < 15000; ++i) data.push_back(i);
  size_t stable_cmp = stable_sort_comparisons(data);

  // Galloping should use significantly fewer comparisons than stable_sort
  // At 10K elements, we expect ~50% reduction or better
  ASSERT_TRUE(timsort_cmp < stable_cmp * 3 / 4);
}

// 100K processes: kernel threads (low PIDs) + user processes (high PIDs)
TEST(timsort_gallop_100k_pid_blocks) {
  std::vector<size_t> data;
  data.reserve(100000);

  // Block 1: Kernel threads PIDs 1-500 (descending, will be reversed)
  for (int i = 500; i >= 1; --i) data.push_back(i);

  // Block 2: User processes PIDs 1000-50000 (descending, will be reversed)
  for (int i = 50000; i >= 1000; --i) data.push_back(i);

  // Block 3: High PIDs 60000-109999 (ascending)
  for (size_t i = 60000; i < 110000; ++i) data.push_back(i);

  size_t timsort_cmp = 0;
  timsort(data.begin(), data.end(), [&](size_t a, size_t b) {
    ++timsort_cmp;
    return a < b;
  });

  ASSERT_TRUE(std::is_sorted(data.begin(), data.end()));

  // With disjoint blocks and galloping, should be much less than O(n log n)
  // O(n log n) for 100K ≈ 1.7M. We expect < 300K with galloping.
  ASSERT_TRUE(timsort_cmp < 300000);
}

// Simulate process list sorted by CPU%: many idle (0%) then few active
TEST(timsort_gallop_cpu_blocks) {
  std::vector<size_t> data;
  data.reserve(10000);

  // 9000 "idle" processes (descending, will be reversed)
  for (int i = 8999; i >= 0; --i) data.push_back(i);

  // 1000 "active" processes (ascending)
  for (size_t i = 100000; i < 101000; ++i) data.push_back(i);

  size_t timsort_cmp = 0;
  timsort(data.begin(), data.end(), [&](size_t a, size_t b) {
    ++timsort_cmp;
    return a < b;
  });

  ASSERT_TRUE(std::is_sorted(data.begin(), data.end()));

  // Compare to stable_sort
  data.clear();
  for (int i = 8999; i >= 0; --i) data.push_back(i);
  for (size_t i = 100000; i < 101000; ++i) data.push_back(i);
  size_t stable_cmp = stable_sort_comparisons(data);

  // Galloping should beat stable_sort by significant margin
  ASSERT_TRUE(timsort_cmp < stable_cmp * 3 / 4);
}

// Worst case for galloping: interleaved data (no run dominates)
// This verifies galloping doesn't HURT performance
TEST(timsort_gallop_interleaved_no_regression) {
  std::vector<size_t> data;
  // Interleaved: 0, 1000, 1, 1001, 2, 1002, ...
  for (size_t i = 0; i < 5000; ++i) {
    data.push_back(i);
    data.push_back(10000 + i);
  }
  std::mt19937 rng(123);
  std::shuffle(data.begin(), data.end(), rng);

  size_t timsort_cmp = 0;
  timsort(data.begin(), data.end(), [&](size_t a, size_t b) {
    ++timsort_cmp;
    return a < b;
  });

  ASSERT_TRUE(std::is_sorted(data.begin(), data.end()));

  // Compare to stable_sort - should be roughly similar (no gallop benefit)
  data.clear();
  for (size_t i = 0; i < 5000; ++i) {
    data.push_back(i);
    data.push_back(10000 + i);
  }
  std::shuffle(data.begin(), data.end(), rng);
  size_t stable_cmp = stable_sort_comparisons(data);

  // Should not be worse than 2x stable_sort (gallop overhead is bounded)
  ASSERT_TRUE(timsort_cmp < stable_cmp * 2);
}

// The ultimate test: 100K with realistic process churn pattern
TEST(timsort_gallop_100k_realistic_churn) {
  std::vector<size_t> data;
  data.reserve(100000);

  // Simulate: mostly sequential PIDs with some gaps (dead processes)
  size_t pid = 1;
  std::mt19937 rng(42);
  while (data.size() < 100000) {
    // Add a run of 100-500 sequential PIDs
    size_t run_len = 100 + (rng() % 400);
    for (size_t i = 0; i < run_len && data.size() < 100000; ++i) {
      data.push_back(pid++);
    }
    pid += rng() % 100; // Gap
  }

  // Shuffle in chunks to preserve some local order
  for (size_t i = 0; i + 1000 < data.size(); i += 500) {
    std::shuffle(data.begin() + i, data.begin() + i + 1000, rng);
  }

  size_t timsort_cmp = 0;
  timsort(data.begin(), data.end(), [&](size_t a, size_t b) {
    ++timsort_cmp;
    return a < b;
  });

  ASSERT_TRUE(std::is_sorted(data.begin(), data.end()));

  // O(n log n) for 100K ≈ 1.7M comparisons
  // Heavy shuffling destroys runs, so expect ~1.3M (still under O(n log n))
  ASSERT_TRUE(timsort_cmp < 1500000);
}
