#include "util/TimSort.hpp"
#include <algorithm>
#include <cmath>
#include <cstdint>

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
  if (std::distance(first, last) < 2) return;
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
// GALLOP LEFT (Find leftmost insertion point via exponential search)
// ============================================================================
// Find position in [base, base+len) where key should insert (leftmost).
// Returns k such that base[k-1] < key <= base[k].
// Starts near 'hint', gallops outward exponentially, then binary searches.
auto gallop_left(
    size_t key,
    std::vector<size_t>::iterator base,
    size_t len,
    size_t hint,
    std::function<bool(size_t, size_t)>& comp
) -> size_t {
  size_t last_ofs = 0;
  size_t ofs = 1;

  if (comp(*(base + hint), key)) {
    // key > base[hint], search right
    size_t max_ofs = len - hint;
    while (ofs < max_ofs && comp(*(base + hint + ofs), key)) {
      last_ofs = ofs;
      ofs = (ofs << 1) + 1;
      if (ofs <= last_ofs) ofs = max_ofs; // overflow
    }
    if (ofs > max_ofs) ofs = max_ofs;

    // Now base[hint + last_ofs] < key <= base[hint + ofs]
    last_ofs += hint;
    ofs += hint;
  } else {
    // key <= base[hint], search left
    size_t max_ofs = hint + 1;
    while (ofs < max_ofs && !comp(*(base + hint - ofs), key)) {
      last_ofs = ofs;
      ofs = (ofs << 1) + 1;
      if (ofs <= last_ofs) ofs = max_ofs;
    }
    if (ofs > max_ofs) ofs = max_ofs;

    // Now base[hint - ofs] < key <= base[hint - last_ofs]
    // Guard against underflow when ofs > hint (searched to beginning)
    size_t tmp = last_ofs;
    last_ofs = (ofs > hint) ? 0 : hint - ofs;
    ofs = hint - tmp;
  }

  // Binary search in [last_ofs, ofs)
  while (last_ofs < ofs) {
    size_t mid = last_ofs + ((ofs - last_ofs) >> 1);
    if (comp(*(base + mid), key)) {
      last_ofs = mid + 1;
    } else {
      ofs = mid;
    }
  }

  return ofs;
}

// ============================================================================
// GALLOP RIGHT (Find rightmost insertion point via exponential search)
// ============================================================================
// Find position in [base, base+len) where key should insert (rightmost).
// Returns k such that base[k-1] <= key < base[k].
auto gallop_right(
    size_t key,
    std::vector<size_t>::iterator base,
    size_t len,
    size_t hint,
    std::function<bool(size_t, size_t)>& comp
) -> size_t {
  size_t last_ofs = 0;
  size_t ofs = 1;

  if (comp(key, *(base + hint))) {
    // key < base[hint], search left
    size_t max_ofs = hint + 1;
    while (ofs < max_ofs && comp(key, *(base + hint - ofs))) {
      last_ofs = ofs;
      ofs = (ofs << 1) + 1;
      if (ofs <= last_ofs) ofs = max_ofs;
    }
    if (ofs > max_ofs) ofs = max_ofs;

    // Guard against underflow when ofs > hint (searched to beginning)
    size_t tmp = last_ofs;
    last_ofs = (ofs > hint) ? 0 : hint - ofs;
    ofs = hint - tmp;
  } else {
    // key >= base[hint], search right
    size_t max_ofs = len - hint;
    while (ofs < max_ofs && !comp(key, *(base + hint + ofs))) {
      last_ofs = ofs;
      ofs = (ofs << 1) + 1;
      if (ofs <= last_ofs) ofs = max_ofs;
    }
    if (ofs > max_ofs) ofs = max_ofs;

    last_ofs += hint;
    ofs += hint;
  }

  // Binary search in [last_ofs, ofs)
  while (last_ofs < ofs) {
    size_t mid = last_ofs + ((ofs - last_ofs) >> 1);
    if (comp(key, *(base + mid))) {
      ofs = mid;
    } else {
      last_ofs = mid + 1;
    }
  }

  return ofs;
}

// ============================================================================
// MERGE LO (Left run smaller - copy left to temp, merge left-to-right)
// ============================================================================
void merge_lo(
    std::vector<size_t>::iterator base,
    size_t left_len,
    size_t right_len,
    std::function<bool(size_t, size_t)>& comp,
    std::vector<size_t>& tmp,
    size_t& min_gallop
) {
  // Copy left run to temp
  tmp.resize(left_len);
  std::move(base, base + left_len, tmp.begin());

  auto cursor1 = tmp.begin();
  auto cursor2 = base + left_len;
  auto dest = base;

  size_t left_remaining = left_len;
  size_t right_remaining = right_len;

  // Main merge loop
  while (left_remaining > 1 && right_remaining > 0) {
    size_t count1 = 0;
    size_t count2 = 0;

    // One-at-a-time mode
    do {
      if (comp(*cursor2, *cursor1)) {
        *dest++ = std::move(*cursor2++);
        --right_remaining;
        ++count2;
        count1 = 0;
        if (right_remaining == 0) goto epilogue;
      } else {
        *dest++ = std::move(*cursor1++);
        --left_remaining;
        ++count1;
        count2 = 0;
        if (left_remaining == 1) goto epilogue;
      }
    } while ((count1 | count2) < min_gallop);

    // Gallop mode
    do {
      // Gallop in left run (find where right[0] goes)
      count1 = gallop_right(*cursor2, cursor1, left_remaining, 0, comp);
      if (count1 > 0) {
        std::move(cursor1, cursor1 + count1, dest);
        dest += count1;
        cursor1 += count1;
        left_remaining -= count1;
        if (left_remaining <= 1) goto epilogue;
      }
      *dest++ = std::move(*cursor2++);
      --right_remaining;
      if (right_remaining == 0) goto epilogue;

      // Gallop in right run (find where left[0] goes)
      count2 = gallop_left(*cursor1, cursor2, right_remaining, 0, comp);
      if (count2 > 0) {
        std::move(cursor2, cursor2 + count2, dest);
        dest += count2;
        cursor2 += count2;
        right_remaining -= count2;
        if (right_remaining == 0) goto epilogue;
      }
      *dest++ = std::move(*cursor1++);
      --left_remaining;
      if (left_remaining == 1) goto epilogue;

      // Adjust threshold
      if (count1 >= MIN_GALLOP || count2 >= MIN_GALLOP) {
        if (min_gallop > 1) --min_gallop;
      } else {
        ++min_gallop;
      }
    } while (count1 >= MIN_GALLOP || count2 >= MIN_GALLOP);

    ++min_gallop; // Penalty for leaving gallop mode
  }

epilogue:
  if (left_remaining == 1) {
    // Copy remaining right elements, then place the single left element
    std::move(cursor2, cursor2 + right_remaining, dest);
    *(dest + right_remaining) = std::move(*cursor1);
  } else if (left_remaining > 0) {
    std::move(cursor1, cursor1 + left_remaining, dest);
  }
}

// ============================================================================
// MERGE HI (Right run smaller - copy right to temp, merge right-to-left)
// ============================================================================
void merge_hi(
    std::vector<size_t>::iterator base,
    size_t left_len,
    size_t right_len,
    std::function<bool(size_t, size_t)>& comp,
    std::vector<size_t>& tmp,
    size_t& min_gallop
) {
  // Copy right run to temp
  tmp.resize(right_len);
  std::move(base + left_len, base + left_len + right_len, tmp.begin());

  auto cursor1 = base + left_len - 1;        // Last element of left run
  auto cursor2 = tmp.begin() + right_len - 1; // Last element of temp
  auto dest = base + left_len + right_len - 1; // Last output position

  size_t left_remaining = left_len;
  size_t right_remaining = right_len;

  // Main merge loop (reversed direction)
  while (left_remaining > 0 && right_remaining > 1) {
    size_t count1 = 0;
    size_t count2 = 0;

    // One-at-a-time mode
    do {
      if (comp(*cursor2, *cursor1)) {
        *dest-- = std::move(*cursor1--);
        --left_remaining;
        ++count1;
        count2 = 0;
        if (left_remaining == 0) goto epilogue;
      } else {
        *dest-- = std::move(*cursor2--);
        --right_remaining;
        ++count2;
        count1 = 0;
        if (right_remaining == 1) goto epilogue;
      }
    } while ((count1 | count2) < min_gallop);

    // Gallop mode (reversed)
    do {
      // Find where right's last goes in left (from end)
      count1 = left_remaining - gallop_right(*cursor2, base, left_remaining, left_remaining - 1, comp);
      if (count1 > 0) {
        dest -= count1;
        cursor1 -= count1;
        left_remaining -= count1;
        // Use move_backward: dest+1 > cursor1+1, ranges may overlap
        std::move_backward(cursor1 + 1, cursor1 + 1 + count1, dest + 1 + count1);
        if (left_remaining == 0) goto epilogue;
      }
      *dest-- = std::move(*cursor2--);
      --right_remaining;
      if (right_remaining == 1) goto epilogue;

      // Find where left's last goes in right (from end)
      count2 = right_remaining - gallop_left(*cursor1, tmp.begin(), right_remaining, right_remaining - 1, comp);
      if (count2 > 0) {
        dest -= count2;
        cursor2 -= count2;
        right_remaining -= count2;
        std::move(cursor2 + 1, cursor2 + 1 + count2, dest + 1);
        if (right_remaining <= 1) goto epilogue;
      }
      *dest-- = std::move(*cursor1--);
      --left_remaining;
      if (left_remaining == 0) goto epilogue;

      // Adjust threshold
      if (count1 >= MIN_GALLOP || count2 >= MIN_GALLOP) {
        if (min_gallop > 1) --min_gallop;
      } else {
        ++min_gallop;
      }
    } while (count1 >= MIN_GALLOP || count2 >= MIN_GALLOP);

    ++min_gallop;
  }

epilogue:
  if (right_remaining == 1) {
    // Move all remaining left elements, then place the single right element
    dest -= left_remaining;
    cursor1 -= left_remaining;
    std::move_backward(cursor1 + 1, cursor1 + 1 + left_remaining, dest + 1 + left_remaining);
    *dest = std::move(*cursor2);
  } else if (right_remaining > 0) {
    std::move(tmp.begin(), tmp.begin() + right_remaining, dest - right_remaining + 1);
  }
}

// ============================================================================
// MERGE WITH GALLOP (Entry point with pre-merge trimming)
// ============================================================================
void merge_with_gallop(
    std::vector<size_t>::iterator first,
    std::vector<Run>& runs,
    size_t i,
    std::function<bool(size_t, size_t)>& comp,
    std::vector<size_t>& tmp,
    size_t& min_gallop
) {
  auto base1 = first + runs[i].base;
  size_t len1 = runs[i].length;
  auto base2 = first + runs[i + 1].base;
  size_t len2 = runs[i + 1].length;

  // Pre-merge trimming: skip elements already in position

  // Skip left elements smaller than right[0]
  size_t k = gallop_right(*base2, base1, len1, 0, comp);
  base1 += k;
  len1 -= k;

  if (len1 == 0) {
    // Left run entirely precedes right; no merge needed
    runs[i].length += runs[i + 1].length;
    runs.erase(runs.begin() + i + 1);
    return;
  }

  // Skip right elements larger than left[last]
  len2 = gallop_left(*(base1 + len1 - 1), base2, len2, len2 - 1, comp);

  if (len2 == 0) {
    // Right run entirely follows left; no merge needed
    runs[i].length += runs[i + 1].length;
    runs.erase(runs.begin() + i + 1);
    return;
  }

  // Merge the trimmed ranges
  if (len1 <= len2) {
    merge_lo(base1, len1, len2, comp, tmp, min_gallop);
  } else {
    merge_hi(base1, len1, len2, comp, tmp, min_gallop);
  }

  // Update run info
  runs[i].length += runs[i + 1].length;
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
    std::function<bool(size_t, size_t)>& comp,
    std::vector<size_t>& tmp,
    size_t& min_gallop
) {
  while (runs.size() > 1) {
    size_t n = runs.size() - 2;

    if (n > 0 && runs[n - 1].length <= runs[n].length + runs[n + 1].length) {
      // Merge the smaller of the two adjacent runs
      if (runs[n - 1].length < runs[n + 1].length) {
        --n;
      }
      merge_with_gallop(first, runs, n, comp, tmp, min_gallop);
    } else if (runs[n].length <= runs[n + 1].length) {
      merge_with_gallop(first, runs, n, comp, tmp, min_gallop);
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
    std::function<bool(size_t, size_t)>& comp,
    std::vector<size_t>& tmp,
    size_t& min_gallop
) {
  while (runs.size() > 1) {
    size_t n = runs.size() - 2;

    if (n > 0 && runs[n - 1].length < runs[n + 1].length) {
      --n;
    }
    merge_with_gallop(first, runs, n, comp, tmp, min_gallop);
  }
}

// ============================================================================
// FULL TIMSORT IMPLEMENTATION
// ============================================================================
void timsort_impl(
    std::vector<size_t>::iterator first,
    std::vector<size_t>::iterator last,
    std::function<bool(size_t, size_t)>& comp
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

  // Adaptive gallop threshold (per-sort state)
  size_t min_gallop = INITIAL_GALLOP;

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
      runLen
    });

    // Maintain stack invariants
    merge_collapse(first, runs, comp, tmp, min_gallop);

    cur += runLen;
    nRemaining -= runLen;
  }

  // Final merge of all runs
  merge_force_collapse(first, runs, comp, tmp, min_gallop);
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
// TIMSORT (Main entry point)
// ============================================================================
void timsort(
    std::vector<size_t>::iterator first,
    std::vector<size_t>::iterator last,
    std::function<bool(size_t, size_t)> comp
) {
  const size_t n = std::distance(first, last);

  // Tiny arrays: use insertion sort directly
  if (n < detail::MIN_MERGE) {
    detail::binary_insertion_sort(first, last, comp);
    return;
  }

  // Pattern detection
  const SortPattern pattern = detect_sort_pattern(first, last, comp);

  switch (pattern) {
    case SortPattern::AlreadySorted:
      // No work needed
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
}

} // namespace montauk::util
