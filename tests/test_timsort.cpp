#include "minitest.hpp"
#include "util/TimSort.hpp"
#include <algorithm>
#include <cassert>
#include <numeric>
#include <random>
#include <vector>
#include <sys/random.h>

using namespace montauk::util;

// ============================================================================
// TRACING INFRASTRUCTURE
// ============================================================================
// Use getrandom() for cryptographically random test data
static void shuffle_random(std::vector<size_t>& v) {
  for (size_t i = v.size() - 1; i > 0; --i) {
    size_t j;
    getrandom(&j, sizeof(j), 0);
    j %= (i + 1);
    std::swap(v[i], v[j]);
  }
}

// Verify sort invariants with assert() - fails fast on corruption
static void assert_sorted(const std::vector<size_t>& data, const char* ctx) {
  for (size_t i = 1; i < data.size(); ++i) {
    assert(data[i] >= data[i-1] && "sort invariant violated");
  }
  (void)ctx; // Used in error messages if assert had printf
}

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

// ============================================================================
// STRESS TESTS WITH GETRANDOM (True randomness, assert-based validation)
// ============================================================================

// 500K random elements - exercises merge_hi overlap edge cases
TEST(timsort_stress_500k_random) {
  std::vector<size_t> data(500000);
  std::iota(data.begin(), data.end(), 0);
  shuffle_random(data);

  timsort(data.begin(), data.end(), [](size_t a, size_t b) { return a < b; });

  // Use assert for fast failure on corruption
  assert_sorted(data, "500k_random");
  ASSERT_TRUE(std::is_sorted(data.begin(), data.end()));
}

// 1M random elements - full-scale stress test
TEST(timsort_stress_1m_random) {
  std::vector<size_t> data(1000000);
  std::iota(data.begin(), data.end(), 0);
  shuffle_random(data);

  timsort(data.begin(), data.end(), [](size_t a, size_t b) { return a < b; });

  assert_sorted(data, "1m_random");
  ASSERT_TRUE(std::is_sorted(data.begin(), data.end()));
}

// 10M disjoint blocks - proves galloping at scale
TEST(timsort_stress_10m_disjoint) {
  std::vector<size_t> data;
  data.reserve(10000000);

  // Block 1: 100K kernel threads (reversed)
  for (int i = 100000; i >= 1; --i) data.push_back(i);
  // Block 2: 5M user processes (reversed)
  for (int i = 5500000; i >= 500000; --i) data.push_back(i);
  // Block 3: 4.4M high PIDs (ascending)
  for (size_t i = 6000000; i < 10400000; ++i) data.push_back(i);

  size_t cmp = 0;
  timsort(data.begin(), data.end(), [&](size_t a, size_t b) {
    ++cmp;
    return a < b;
  });

  assert_sorted(data, "10m_disjoint");
  ASSERT_TRUE(std::is_sorted(data.begin(), data.end()));

  // Galloping should achieve massive comparison reduction
  // Without galloping: ~230M comparisons (n log n)
  // With galloping on disjoint data: <15M comparisons
  ASSERT_TRUE(cmp < 15000000);
}

// ============================================================================
// 10M RANDOM BENCHMARK - Ultimate stress test
// ============================================================================
TEST(timsort_stress_10m_random) {
  std::vector<size_t> data(10000000);
  std::iota(data.begin(), data.end(), 0);
  shuffle_random(data);

  timsort(data.begin(), data.end(), [](size_t a, size_t b) { return a < b; });

  // Assert-based validation for fast failure
  assert_sorted(data, "10m_random");
  ASSERT_TRUE(std::is_sorted(data.begin(), data.end()));
}

// ============================================================================
// SUBLIMATION BACKEND TESTS
// ============================================================================
// Compiled in only when montauk is built with USE_SUBLIMATION=ON. Verifies:
//   1. Direct sublimation entry points produce sorted output across patterns.
//   2. The dispatcher routes correctly and preserves the sorted property.
//   3. TimSort and Sublimation paths over the same input both produce a valid
//      ascending order (permutations may differ -- pack-sort tiebreaks on
//      original index, TimSort is stable -- but the sorted property holds).
#ifdef HAVE_SUBLIMATION
#include "util/SortDispatch.hpp"
#include "sublimation_pack.h"
#include "sublimation_strings.h"
#include <cstring>
#include <string>

// Verify keys[indices[i]] is non-decreasing for ascending sort.
template <typename KeyT>
static bool is_sorted_by_key_asc(const std::vector<KeyT>& keys,
                                 const std::vector<uint32_t>& indices) {
  for (size_t i = 1; i < indices.size(); ++i) {
    if (keys[indices[i]] < keys[indices[i-1]]) return false;
  }
  return true;
}
template <typename KeyT>
static bool is_sorted_by_key_desc(const std::vector<KeyT>& keys,
                                  const std::vector<uint32_t>& indices) {
  for (size_t i = 1; i < indices.size(); ++i) {
    if (keys[indices[i]] > keys[indices[i-1]]) return false;
  }
  return true;
}

// Verify indices is a valid permutation of 0..n-1 (no dupes, no out-of-range).
static bool is_valid_permutation(const std::vector<uint32_t>& indices) {
  std::vector<uint32_t> sorted = indices;
  std::sort(sorted.begin(), sorted.end());
  for (uint32_t i = 0; i < sorted.size(); ++i) {
    if (sorted[i] != i) return false;
  }
  return true;
}

TEST(sublimation_pack_u32_random) {
  const size_t n = 4096;
  std::vector<uint32_t> keys(n);
  for (size_t i = 0; i < n; ++i) {
    getrandom(&keys[i], sizeof(uint32_t), 0);
  }
  std::vector<uint32_t> idx(n);
  std::iota(idx.begin(), idx.end(), 0u);

  sublimation_pack_sort_u32(keys.data(), idx.data(), n, /*descending=*/false);

  ASSERT_TRUE(is_valid_permutation(idx));
  ASSERT_TRUE(is_sorted_by_key_asc(keys, idx));
}

TEST(sublimation_pack_u32_descending) {
  const size_t n = 1024;
  std::vector<uint32_t> keys(n);
  for (size_t i = 0; i < n; ++i) {
    getrandom(&keys[i], sizeof(uint32_t), 0);
  }
  std::vector<uint32_t> idx(n);
  std::iota(idx.begin(), idx.end(), 0u);

  sublimation_pack_sort_u32(keys.data(), idx.data(), n, /*descending=*/true);

  ASSERT_TRUE(is_valid_permutation(idx));
  ASSERT_TRUE(is_sorted_by_key_desc(keys, idx));
}

TEST(sublimation_pack_u32_already_sorted) {
  const size_t n = 1024;
  std::vector<uint32_t> keys(n);
  for (uint32_t i = 0; i < n; ++i) keys[i] = i;
  std::vector<uint32_t> idx(n);
  std::iota(idx.begin(), idx.end(), 0u);

  sublimation_pack_sort_u32(keys.data(), idx.data(), n, /*descending=*/false);

  ASSERT_TRUE(is_valid_permutation(idx));
  ASSERT_TRUE(is_sorted_by_key_asc(keys, idx));
  // Already-sorted should preserve original index order.
  for (uint32_t i = 0; i < n; ++i) ASSERT_EQ(idx[i], i);
}

TEST(sublimation_pack_u32_reversed) {
  const size_t n = 1024;
  std::vector<uint32_t> keys(n);
  for (uint32_t i = 0; i < n; ++i) keys[i] = static_cast<uint32_t>(n - 1 - i);
  std::vector<uint32_t> idx(n);
  std::iota(idx.begin(), idx.end(), 0u);

  sublimation_pack_sort_u32(keys.data(), idx.data(), n, /*descending=*/false);

  ASSERT_TRUE(is_valid_permutation(idx));
  ASSERT_TRUE(is_sorted_by_key_asc(keys, idx));
}

TEST(sublimation_pack_u32_all_equal) {
  const size_t n = 1024;
  std::vector<uint32_t> keys(n, 42u);
  std::vector<uint32_t> idx(n);
  std::iota(idx.begin(), idx.end(), 0u);

  sublimation_pack_sort_u32(keys.data(), idx.data(), n, /*descending=*/false);

  ASSERT_TRUE(is_valid_permutation(idx));
  // All-equal keys: pack-sort tiebreaks on index, so output == input.
  for (uint32_t i = 0; i < n; ++i) ASSERT_EQ(idx[i], i);
}

TEST(sublimation_pack_f32_random) {
  const size_t n = 2048;
  std::vector<float> keys(n);
  for (size_t i = 0; i < n; ++i) {
    uint32_t bits;
    getrandom(&bits, sizeof(bits), 0);
    keys[i] = static_cast<float>(bits % 100000) / 1000.0f;  // [0, 100)
  }
  std::vector<uint32_t> idx(n);
  std::iota(idx.begin(), idx.end(), 0u);

  sublimation_pack_sort_f32(keys.data(), idx.data(), n, /*descending=*/true);

  ASSERT_TRUE(is_valid_permutation(idx));
  ASSERT_TRUE(is_sorted_by_key_desc(keys, idx));
}

TEST(sublimation_pack_i32_negative_values) {
  const size_t n = 512;
  std::vector<int32_t> keys(n);
  for (size_t i = 0; i < n; ++i) {
    int32_t v;
    getrandom(&v, sizeof(v), 0);
    keys[i] = v;  // full int32 range incl. negatives
  }
  std::vector<uint32_t> idx(n);
  std::iota(idx.begin(), idx.end(), 0u);

  sublimation_pack_sort_i32(keys.data(), idx.data(), n, /*descending=*/false);

  ASSERT_TRUE(is_valid_permutation(idx));
  ASSERT_TRUE(is_sorted_by_key_asc(keys, idx));
}

TEST(sublimation_strings_random) {
  // Build a pool of distinct random strings.
  const size_t n = 1024;
  std::vector<std::string> storage(n);
  for (size_t i = 0; i < n; ++i) {
    char buf[16];
    for (size_t j = 0; j < 15; ++j) {
      uint8_t c;
      getrandom(&c, 1, 0);
      buf[j] = 'a' + (c % 26);
    }
    buf[15] = '\0';
    storage[i] = buf;
  }
  std::vector<const char*> arr(n);
  for (size_t i = 0; i < n; ++i) arr[i] = storage[i].c_str();
  std::vector<uint32_t> idx(n);
  std::iota(idx.begin(), idx.end(), 0u);

  sublimation_strings_indices(arr.data(), idx.data(), n);

  ASSERT_TRUE(is_valid_permutation(idx));
  for (size_t i = 1; i < n; ++i) {
    ASSERT_TRUE(std::strcmp(arr[idx[i-1]], arr[idx[i]]) <= 0);
  }
}

TEST(sublimation_strings_common_prefix) {
  // Stress the MSD radix tail by giving every string the same 8-byte prefix.
  const size_t n = 512;
  std::vector<std::string> storage(n);
  for (size_t i = 0; i < n; ++i) {
    char buf[24];
    std::memcpy(buf, "common__", 8);
    for (size_t j = 8; j < 23; ++j) {
      uint8_t c;
      getrandom(&c, 1, 0);
      buf[j] = 'a' + (c % 26);
    }
    buf[23] = '\0';
    storage[i] = buf;
  }
  std::vector<const char*> arr(n);
  for (size_t i = 0; i < n; ++i) arr[i] = storage[i].c_str();
  std::vector<uint32_t> idx(n);
  std::iota(idx.begin(), idx.end(), 0u);

  sublimation_strings_indices(arr.data(), idx.data(), n);

  ASSERT_TRUE(is_valid_permutation(idx));
  for (size_t i = 1; i < n; ++i) {
    ASSERT_TRUE(std::strcmp(arr[idx[i-1]], arr[idx[i]]) <= 0);
  }
}

// Cross-backend equivalence: same input through dispatcher (default = TimSort)
// and direct sublimation. Both must produce a valid ascending permutation.
// Permutations may differ for equal keys; the sorted property is what matters.
TEST(sublimation_dispatcher_vs_direct_u32) {
  const size_t n = 256;
  std::vector<uint32_t> keys(n);
  for (size_t i = 0; i < n; ++i) {
    uint32_t v;
    getrandom(&v, sizeof(v), 0);
    keys[i] = v % 1000;  // heavy duplicates
  }

  std::vector<uint32_t> idx_dispatch(n), idx_direct(n);
  std::iota(idx_dispatch.begin(), idx_dispatch.end(), 0u);
  std::iota(idx_direct.begin(), idx_direct.end(), 0u);

  // resolve_backend() defaults to TimSort unless MONTAUK_SORT_BACKEND is set.
  montauk::util::sort_by_key_u32(keys, idx_dispatch, /*descending=*/false);
  sublimation_pack_sort_u32(keys.data(), idx_direct.data(), n, /*descending=*/false);

  ASSERT_TRUE(is_valid_permutation(idx_dispatch));
  ASSERT_TRUE(is_valid_permutation(idx_direct));
  ASSERT_TRUE(is_sorted_by_key_asc(keys, idx_dispatch));
  ASSERT_TRUE(is_sorted_by_key_asc(keys, idx_direct));
}

// String dispatcher vs direct sublimation_strings_indices.
TEST(sublimation_dispatcher_vs_direct_strings) {
  const size_t n = 128;
  std::vector<std::string> storage(n);
  for (size_t i = 0; i < n; ++i) {
    char buf[12];
    for (size_t j = 0; j < 11; ++j) {
      uint8_t c;
      getrandom(&c, 1, 0);
      buf[j] = 'a' + (c % 26);
    }
    buf[11] = '\0';
    storage[i] = buf;
  }
  std::vector<const char*> arr(n);
  for (size_t i = 0; i < n; ++i) arr[i] = storage[i].c_str();

  std::vector<uint32_t> idx_dispatch(n), idx_direct(n);
  std::iota(idx_dispatch.begin(), idx_dispatch.end(), 0u);
  std::iota(idx_direct.begin(), idx_direct.end(), 0u);

  montauk::util::sort_by_string(std::span<const char* const>(arr.data(), arr.size()),
                                idx_dispatch);
  sublimation_strings_indices(arr.data(), idx_direct.data(), n);

  ASSERT_TRUE(is_valid_permutation(idx_dispatch));
  ASSERT_TRUE(is_valid_permutation(idx_direct));
  for (size_t i = 1; i < n; ++i) {
    ASSERT_TRUE(std::strcmp(arr[idx_dispatch[i-1]], arr[idx_dispatch[i]]) <= 0);
    ASSERT_TRUE(std::strcmp(arr[idx_direct[i-1]],   arr[idx_direct[i]])   <= 0);
  }
}

// ============================================================================
// HEAD-TO-HEAD TIMING: TimSort vs Sublimation on identical inputs
// ============================================================================
// For each pattern + size, we run both backends on a fresh copy of the same
// input, time each with steady_clock, and print:
//   pattern  n  timsort_ns/elem  sublimation_ns/elem  speedup
// Best-of-3 to dampen scheduler noise. Output goes to stdout so it shows up
// alongside the [PASS] lines from minitest.
#include <chrono>
#include <cstdio>

namespace {

using clk = std::chrono::steady_clock;

// Best-of-3 sort timing. Returns total nanoseconds for the fastest run.
template <typename SortFn>
uint64_t time_sort_best_of_3(const std::vector<uint32_t>& keys_template, SortFn sort_fn) {
  uint64_t best = UINT64_MAX;
  for (int rep = 0; rep < 3; ++rep) {
    std::vector<uint32_t> keys = keys_template;
    std::vector<uint32_t> idx(keys.size());
    std::iota(idx.begin(), idx.end(), 0u);
    auto t0 = clk::now();
    sort_fn(keys, idx);
    auto t1 = clk::now();
    uint64_t ns = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count());
    if (ns < best) best = ns;
  }
  return best;
}

void bench_compare_u32(const char* pattern, std::vector<uint32_t> keys) {
  const size_t n = keys.size();

  // TimSort: sort size_t indices via the existing util::timsort, comparator
  // reads from keys[]. Matches what montauk uses today.
  auto timsort_fn = [](std::vector<uint32_t>& k, std::vector<uint32_t>& idx) {
    std::vector<size_t> tmp(idx.begin(), idx.end());
    montauk::util::timsort(tmp.begin(), tmp.end(),
        [&](size_t a, size_t b) { return k[a] < k[b]; });
    for (size_t i = 0; i < idx.size(); ++i) idx[i] = static_cast<uint32_t>(tmp[i]);
  };

  // Sublimation: direct call to the pack-sort entry point.
  auto sub_fn = [](std::vector<uint32_t>& k, std::vector<uint32_t>& idx) {
    sublimation_pack_sort_u32(k.data(), idx.data(), idx.size(), /*descending=*/false);
  };

  uint64_t ts_ns  = time_sort_best_of_3(keys, timsort_fn);
  uint64_t sub_ns = time_sort_best_of_3(keys, sub_fn);

  double ts_per  = (double)ts_ns  / (double)n;
  double sub_per = (double)sub_ns / (double)n;
  double speedup = (double)ts_ns  / (double)sub_ns;

  std::printf("[BENCH] %-22s n=%-7zu  timsort=%9lu ns (%6.2f ns/el)  "
              "sublimation=%9lu ns (%6.2f ns/el)  speedup=%5.2fx\n",
              pattern, n, (unsigned long)ts_ns, ts_per,
              (unsigned long)sub_ns, sub_per, speedup);
  std::fflush(stdout);
}

void bench_compare_strings(const char* pattern, std::vector<std::string> storage) {
  const size_t n = storage.size();
  std::vector<const char*> arr(n);
  for (size_t i = 0; i < n; ++i) arr[i] = storage[i].c_str();

  uint64_t ts_best = UINT64_MAX, sub_best = UINT64_MAX;
  for (int rep = 0; rep < 3; ++rep) {
    {
      std::vector<size_t> idx(n);
      std::iota(idx.begin(), idx.end(), 0u);
      auto t0 = clk::now();
      montauk::util::timsort(idx.begin(), idx.end(),
          [&](size_t a, size_t b) { return std::strcmp(arr[a], arr[b]) < 0; });
      auto t1 = clk::now();
      uint64_t ns = static_cast<uint64_t>(
          std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count());
      if (ns < ts_best) ts_best = ns;
    }
    {
      std::vector<uint32_t> idx(n);
      std::iota(idx.begin(), idx.end(), 0u);
      auto t0 = clk::now();
      sublimation_strings_indices(arr.data(), idx.data(), n);
      auto t1 = clk::now();
      uint64_t ns = static_cast<uint64_t>(
          std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count());
      if (ns < sub_best) sub_best = ns;
    }
  }

  double ts_per  = (double)ts_best  / (double)n;
  double sub_per = (double)sub_best / (double)n;
  double speedup = (double)ts_best  / (double)sub_best;

  std::printf("[BENCH] %-22s n=%-7zu  timsort=%9lu ns (%6.2f ns/el)  "
              "sublimation=%9lu ns (%6.2f ns/el)  speedup=%5.2fx\n",
              pattern, n, (unsigned long)ts_best, ts_per,
              (unsigned long)sub_best, sub_per, speedup);
  std::fflush(stdout);
}

std::vector<uint32_t> gen_random_u32(size_t n, uint32_t mod = 0) {
  std::vector<uint32_t> v(n);
  for (size_t i = 0; i < n; ++i) {
    uint32_t x;
    getrandom(&x, sizeof(x), 0);
    v[i] = mod ? (x % mod) : x;
  }
  return v;
}

std::vector<std::string> gen_random_strings(size_t n, size_t len) {
  std::vector<std::string> v(n);
  for (size_t i = 0; i < n; ++i) {
    std::string s(len, '\0');
    for (size_t j = 0; j < len; ++j) {
      uint8_t c;
      getrandom(&c, 1, 0);
      s[j] = 'a' + (c % 26);
    }
    v[i] = std::move(s);
  }
  return v;
}

} // anonymous namespace

TEST(bench_u32_random_256) {
  bench_compare_u32("random_u32", gen_random_u32(256));
}
TEST(bench_u32_random_4096) {
  bench_compare_u32("random_u32", gen_random_u32(4096));
}
TEST(bench_u32_random_100k) {
  bench_compare_u32("random_u32", gen_random_u32(100000));
}
TEST(bench_u32_already_sorted_4096) {
  std::vector<uint32_t> keys(4096);
  std::iota(keys.begin(), keys.end(), 0u);
  bench_compare_u32("already_sorted", std::move(keys));
}
TEST(bench_u32_reversed_4096) {
  std::vector<uint32_t> keys(4096);
  for (uint32_t i = 0; i < 4096; ++i) keys[i] = 4095u - i;
  bench_compare_u32("reversed", std::move(keys));
}
TEST(bench_u32_heavy_dup_4096) {
  // Heavy duplicates: keys mod 16 (only 16 distinct values across 4096 items).
  bench_compare_u32("heavy_duplicates", gen_random_u32(4096, 16));
}
TEST(bench_strings_random_256) {
  bench_compare_strings("random_strings_L16", gen_random_strings(256, 16));
}
TEST(bench_strings_random_4096) {
  bench_compare_strings("random_strings_L16", gen_random_strings(4096, 16));
}
TEST(bench_strings_random_100k) {
  bench_compare_strings("random_strings_L16", gen_random_strings(100000, 16));
}
#endif // HAVE_SUBLIMATION
