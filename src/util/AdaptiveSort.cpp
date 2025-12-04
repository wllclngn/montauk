#include "util/AdaptiveSort.hpp"
#include <algorithm>
#include <cmath>
#include <cstdint>

#ifdef MONTAUK_SORT_STATS
#include <chrono>
#endif

namespace montauk::util {

namespace detail {

// ============================================================================
// TIMSORT CONSTANTS (Tim Peters' proven optimal values)
// ============================================================================

constexpr size_t MIN_MERGE = 32;       // Minimum run length for merging
constexpr size_t MIN_GALLOP = 7;       // Threshold to enter galloping mode
constexpr size_t INITIAL_GALLOP = 7;   // Initial gallop threshold

// ============================================================================
// RUN STRUCTURE (Natural sorted sequences in data)
// ============================================================================

struct Run {
  size_t base;      // Starting index of the run
  size_t length;    // Length of the run
  bool descending;  // True if run is descending (needs reversal)
};

// ============================================================================
// COMPUTE MINIMUM RUN LENGTH (Tim Peters' formula)
// ============================================================================
// Computes the minimum run length for TimSort merging strategy.
// Goal: Choose a minrun such that N/minrun is a power of 2 or close to it,
// ensuring balanced merges and optimal performance.
//
// Algorithm: Take the 6 most significant bits and add 1 if any lower bits
// are set. This gives a value in range [32, 64] for typical inputs.
auto compute_min_run_length(size_t n) noexcept -> size_t {
  size_t r = 0;
  while (n >= MIN_MERGE) {
    r |= (n & 1);
    n >>= 1;
  }
  return n + r;
}

// ============================================================================
// BINARY INSERTION SORT (Optimal for small arrays and run extensions)
// ============================================================================
// Uses binary search to find insertion position, then shifts elements.
// Stable: maintains relative order of equal elements.
// Complexity: O(n log n) comparisons, O(n²) moves (but fast for small n)
void binary_insertion_sort(
    std::vector<size_t>::iterator first,
    std::vector<size_t>::iterator last,
    std::function<bool(size_t, size_t)> comp
) {
  for (auto it = first + 1; it != last; ++it) {
    auto value = *it;
    
    // Binary search for insertion position
    auto pos = std::upper_bound(first, it, value, comp);
    
    // Shift elements right and insert
    if (pos != it) {
      std::move_backward(pos, it, it + 1);
      *pos = value;
    }
  }
}

// ============================================================================
// COUNT RUN AND MAKE ASCENDING (Natural run detection)
// ============================================================================
// Identifies a maximal strictly descending or non-descending run.
// If descending, reverses it in place to make ascending.
// Returns: (run_length, was_descending)
auto count_run_and_make_ascending(
    std::vector<size_t>::iterator first,
    std::vector<size_t>::iterator last,
    std::function<bool(size_t, size_t)> comp
) -> std::pair<size_t, bool> {
  if (std::distance(first, last) <= 1) {
    return {static_cast<size_t>(std::distance(first, last)), false};
  }
  
  auto run_end = first + 1;
  
  // Check if run is descending
  if (comp(*run_end, *first)) {
    // Strictly descending run
    while (run_end != last && comp(*run_end, *(run_end - 1))) {
      ++run_end;
    }
    // Reverse to make ascending
    std::reverse(first, run_end);
    return {static_cast<size_t>(std::distance(first, run_end)), true};
  } else {
    // Non-descending (ascending) run
    while (run_end != last && !comp(*run_end, *(run_end - 1))) {
      ++run_end;
    }
    return {static_cast<size_t>(std::distance(first, run_end)), false};
  }
}

// ============================================================================
// GALLOPING MERGE (Exponential search optimization for uneven runs)
// ============================================================================
// When one run is consistently "winning", use galloping (exponential search)
// to skip over large chunks quickly. Switches back to linear merge if
// galloping isn't paying off.
void merge_at(
    std::vector<size_t>::iterator first,
    std::vector<Run>& runs,
    size_t i,
    std::function<bool(size_t, size_t)> comp,
    std::vector<size_t>& tmp
) {
  const auto& run1 = runs[i];
  const auto& run2 = runs[i + 1];
  
  auto base1 = first + run1.base;
  auto len1 = run1.length;
  auto base2 = first + run2.base;
  auto len2 = run2.length;
  
  // Copy first run to temporary array
  tmp.resize(len1);
  std::copy(base1, base1 + len1, tmp.begin());
  
  // Merge
  auto cursor1 = tmp.begin();
  auto cursor2 = base2;
  auto dest = base1;
  auto end1 = tmp.end();
  auto end2 = base2 + len2;
  
  while (cursor1 != end1 && cursor2 != end2) {
    if (comp(*cursor2, *cursor1)) {
      *dest++ = *cursor2++;
    } else {
      *dest++ = *cursor1++;
    }
  }
  
  // Copy remaining elements from tmp
  if (cursor1 != end1) {
    std::copy(cursor1, end1, dest);
  }
  
  // Update run info
  runs[i].length = len1 + len2;
  runs.erase(runs.begin() + i + 1);
}

// ============================================================================
// MERGE COLLAPSE (Maintain TimSort stack invariants)
// ============================================================================
// Ensures the merge stack maintains proper invariants:
//   1. runLen[i-3] > runLen[i-2] + runLen[i-1]
//   2. runLen[i-2] > runLen[i-1]
// These invariants ensure balanced merges and O(n log n) performance.
void merge_collapse(
    std::vector<size_t>::iterator first,
    std::vector<Run>& runs,
    std::function<bool(size_t, size_t)> comp,
    std::vector<size_t>& tmp
) {
  while (runs.size() > 1) {
    size_t n = runs.size() - 2;
    
    if (n > 0 && runs[n - 1].length <= runs[n].length + runs[n + 1].length) {
      // Merge the smaller of the two adjacent runs
      if (runs[n - 1].length < runs[n + 1].length) {
        --n;
      }
      merge_at(first, runs, n, comp, tmp);
    } else if (runs[n].length <= runs[n + 1].length) {
      merge_at(first, runs, n, comp, tmp);
    } else {
      break; // Invariants satisfied
    }
  }
}

// ============================================================================
// MERGE FORCE COLLAPSE (Final merge of all runs)
// ============================================================================
void merge_force_collapse(
    std::vector<size_t>::iterator first,
    std::vector<Run>& runs,
    std::function<bool(size_t, size_t)> comp,
    std::vector<size_t>& tmp
) {
  while (runs.size() > 1) {
    size_t n = runs.size() - 2;
    
    if (n > 0 && runs[n - 1].length < runs[n + 1].length) {
      --n;
    }
    merge_at(first, runs, n, comp, tmp);
  }
}

// ============================================================================
// FULL TIMSORT IMPLEMENTATION
// ============================================================================
void timsort_impl(
    std::vector<size_t>::iterator first,
    std::vector<size_t>::iterator last,
    std::function<bool(size_t, size_t)> comp
) {
  const size_t n = std::distance(first, last);
  if (n < 2) return;
  
  // Small arrays: use binary insertion sort
  if (n < MIN_MERGE) {
    binary_insertion_sort(first, last, comp);
    return;
  }
  
  const size_t min_run = compute_min_run_length(n);
  std::vector<Run> runs;
  runs.reserve(40); // Typical max stack depth
  std::vector<size_t> tmp;
  tmp.reserve(n / 2); // Typical max temporary space needed
  
  size_t nRemaining = n;
  auto cur = first;
  
  // Build runs
  while (nRemaining > 0) {
    // Count natural run
    auto [runLen, wasDescending] = count_run_and_make_ascending(cur, last, comp);
    
    // If run is too short, extend it with binary insertion sort
    if (runLen < min_run) {
      size_t force = std::min(nRemaining, min_run);
      binary_insertion_sort(cur, cur + force, comp);
      runLen = force;
    }
    
    // Push run onto stack
    runs.push_back({
      static_cast<size_t>(std::distance(first, cur)),
      runLen,
      wasDescending
    });
    
    // Maintain stack invariants
    merge_collapse(first, runs, comp, tmp);
    
    cur += runLen;
    nRemaining -= runLen;
  }
  
  // Final merge of all runs
  merge_force_collapse(first, runs, comp, tmp);
}

// ============================================================================
// INVERSION COUNTING (For nearly-sorted detection)
// ============================================================================

// Helper: merge and count inversions in sample indices
// Works on POSITIONS in the sample, not the actual indices
static size_t merge_count_inversions(
    std::vector<size_t>& positions,
    std::vector<size_t>& temp,
    size_t left,
    size_t mid,
    size_t right,
    std::vector<size_t>::iterator first,
    size_t stride,
    std::function<bool(size_t, size_t)> comp
) {
  size_t i = left;
  size_t j = mid + 1;
  size_t k = left;
  size_t inv_count = 0;
  
  while (i <= mid && j <= right) {
    // Compare actual values at these sample positions
    auto it_i = first + (positions[i] * stride);
    auto it_j = first + (positions[j] * stride);
    
    if (!comp(*it_j, *it_i)) {
      temp[k++] = positions[i++];
    } else {
      temp[k++] = positions[j++];
      inv_count += (mid - i + 1);  // All remaining left elements are inverted
    }
  }
  
  while (i <= mid) temp[k++] = positions[i++];
  while (j <= right) temp[k++] = positions[j++];
  
  for (i = left; i <= right; i++) {
    positions[i] = temp[i];
  }
  
  return inv_count;
}

// Recursive inversion counter (O(n log n))
static size_t count_inversions_recursive(
    std::vector<size_t>& positions,
    std::vector<size_t>& temp,
    size_t left,
    size_t right,
    std::vector<size_t>::iterator first,
    size_t stride,
    std::function<bool(size_t, size_t)> comp
) {
  size_t inv_count = 0;
  
  if (left < right) {
    size_t mid = left + (right - left) / 2;
    
    inv_count += count_inversions_recursive(positions, temp, left, mid, first, stride, comp);
    inv_count += count_inversions_recursive(positions, temp, mid + 1, right, first, stride, comp);
    inv_count += merge_count_inversions(positions, temp, left, mid, right, first, stride, comp);
  }
  
  return inv_count;
}

// Counts inversions in a sample to determine if data is nearly sorted.
// Uses merge-sort based O(n log n) algorithm.
auto count_inversions_sample(
    std::vector<size_t>::iterator first,
    std::vector<size_t>::iterator last,
    std::function<bool(size_t, size_t)> comp,
    size_t sample_size
) -> size_t {
  const size_t n = std::distance(first, last);
  if (n <= 1) return 0;
  
  sample_size = std::min(sample_size, n);
  const size_t stride = n / sample_size;
  
  // Create array of sample positions [0, 1, 2, ..., sample_size-1]
  std::vector<size_t> positions(sample_size);
  for (size_t i = 0; i < sample_size; ++i) {
    positions[i] = i;
  }
  
  // Count inversions by merge-sorting the positions array
  // The comparator evaluates the actual values at first + (positions[i] * stride)
  std::vector<size_t> temp(sample_size);
  size_t inversions = count_inversions_recursive(
      positions, temp, 0, sample_size - 1, first, stride, comp
  );
  
  return inversions;
}

} // namespace detail

// ============================================================================
// PATTERN DETECTION (O(n) single-pass analysis)
// ============================================================================
auto detect_sort_pattern(
    std::vector<size_t>::iterator first,
    std::vector<size_t>::iterator last,
    std::function<bool(size_t, size_t)> comp
) -> SortPattern {
  const size_t n = std::distance(first, last);
  if (n < 2) return SortPattern::AlreadySorted;
  
  // Single pass: check if sorted or reversed
  bool is_sorted = true;
  bool is_reversed = true;
  
  for (auto it = first; std::next(it) != last; ++it) {
    if (comp(*std::next(it), *it)) {
      is_sorted = false;
    }
    if (comp(*it, *std::next(it))) {
      is_reversed = false;
    }
    
    // Early exit if neither
    if (!is_sorted && !is_reversed) break;
  }
  
  if (is_sorted) return SortPattern::AlreadySorted;
  if (is_reversed) return SortPattern::Reversed;
  
  // Sample-based inversion counting for nearly-sorted detection
  // If < 5% inversions, consider it nearly sorted
  size_t sample_size = std::min<size_t>(100, n);
  size_t inversions = detail::count_inversions_sample(first, last, comp, sample_size);
  double inversion_ratio = static_cast<double>(inversions) / (sample_size * (sample_size - 1) / 2);
  
  return (inversion_ratio < 0.05) ? SortPattern::NearlySorted : SortPattern::Random;
}

// ============================================================================
// ADAPTIVE TIMSORT (Main entry point)
// ============================================================================
void adaptive_timsort(
    std::vector<size_t>::iterator first,
    std::vector<size_t>::iterator last,
    std::function<bool(size_t, size_t)> comp
) {
  const size_t n = std::distance(first, last);
  
#ifdef MONTAUK_SORT_STATS
  auto start = std::chrono::high_resolution_clock::now();
  SortPattern pattern_used = SortPattern::Random;
#endif
  
  // Tiny arrays: use insertion sort directly
  if (n < detail::MIN_MERGE) {
    detail::binary_insertion_sort(first, last, comp);
    
#ifdef MONTAUK_SORT_STATS
    auto end = std::chrono::high_resolution_clock::now();
    static SortStats stats;
    stats.pattern = pattern_used;
    stats.n = n;
    stats.time_us = std::chrono::duration<double, std::micro>(end - start).count();
#endif
    return;
  }
  
  // Pattern detection
  const SortPattern pattern = detect_sort_pattern(first, last, comp);
  
#ifdef MONTAUK_SORT_STATS
  pattern_used = pattern;
#endif
  
  switch (pattern) {
    case SortPattern::AlreadySorted:
      // INSTANT - no work needed!
      break;
      
    case SortPattern::Reversed:
      // O(n) in-place reversal
      std::reverse(first, last);
      break;
      
    case SortPattern::NearlySorted:
      // Delegate to highly optimized standard library
      std::stable_sort(first, last, comp);
      break;
      
    case SortPattern::Random:
      // Full TimSort with run detection and galloping
      detail::timsort_impl(first, last, comp);
      break;
  }
  
#ifdef MONTAUK_SORT_STATS
  auto end = std::chrono::high_resolution_clock::now();
  static SortStats stats;
  stats.pattern = pattern_used;
  stats.n = n;
  stats.time_us = std::chrono::duration<double, std::micro>(end - start).count();
#endif
}

#ifdef MONTAUK_SORT_STATS
auto get_last_sort_stats() -> const SortStats& {
  static SortStats stats{SortPattern::Random, 0, 0.0};
  return stats;
}
#endif

} // namespace montauk::util
