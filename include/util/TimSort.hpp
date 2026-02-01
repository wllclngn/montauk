#pragma once
#include <cstddef>
#include <cstdint>
#include <functional>
#include <iterator>
#include <vector>

namespace montauk::util {

// Pattern detection results for adaptive sorting strategy selection
enum class SortPattern : uint8_t {
  AlreadySorted,  // O(n) detection → instant return (no work needed)
  Reversed,       // O(n) detection → O(n) in-place reversal
  NearlySorted,   // < 5% inversions → delegate to std::stable_sort
  Random          // Full adaptive TimSort with run detection & galloping
};

// TimSort with pattern detection and galloping mode.
//
// Performance characteristics:
//   - Already sorted:  O(n) detection, O(1) operation
//   - Reversed:        O(n) detection, O(n) reverse
//   - Nearly sorted:   O(n) detection, O(n log n) via std::stable_sort
//   - Random/complex:  O(n log n) via TimSort with galloping
//
// Galloping mode uses exponential search to skip large chunks when one
// run dominates during merging - ideal for clustered data (sequential
// PIDs, blocks of idle processes).
//
// Stability guarantee: maintains relative order of equal elements.
void timsort(
    std::vector<size_t>::iterator first,
    std::vector<size_t>::iterator last,
    std::function<bool(size_t, size_t)> comp
);

// Optional: pattern detection for external use (testing, diagnostics)
auto detect_sort_pattern(
    std::vector<size_t>::iterator first,
    std::vector<size_t>::iterator last,
    std::function<bool(size_t, size_t)> comp
) -> SortPattern;

#ifdef MONTAUK_SORT_STATS
// Performance statistics for sort operations (enabled with -DMONTAUK_SORT_STATS)
struct SortStats {
  SortPattern pattern;
  size_t n;
  double time_us;
};

// Retrieve statistics from the most recent sort operation
auto get_last_sort_stats() -> const SortStats&;
#endif

} // namespace montauk::util
