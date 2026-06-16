// sublimation_strings.h -- public string-sort entry points
//
// Sorts arrays of byte-strings in lexicographic order using a hybrid
// pipeline: 4-byte big-endian prefix-pack into uint64 -> sublimation_u64
// (full flow-model pipeline runs on prefixes) -> MSD radix tiebreak on
// suffix bytes within prefix-collision clusters -> pointer permutation.
//
// Stability: NOT stable. Equal-content strings may swap relative order.
//   Matches the convention of std::sort and Rust slice::sort_unstable.
//
// Capacity: n must be < 2^32. Larger inputs trigger a qsort+strcmp
//   fallback with a stderr warning to avoid silent index truncation.
//
// UTF-8: byte-order = code-point order by UTF-8 design, so the sort
//   produces correct lexicographic order on UTF-8 strings without any
//   special handling.
//
// Thread safety: reentrant on disjoint pointer arrays.
#ifndef SUBLIMATION_STRINGS_H
#define SUBLIMATION_STRINGS_H

#include <stddef.h>
#include <stdint.h>
#include "internal/c23_compat.h"

#ifdef __cplusplus
extern "C" {
#endif

// Sort an array of NUL-terminated C strings in lexicographic order.
// Permutes the pointer array in place; string contents are untouched.
SUB_API void sublimation_strings(const char **arr, size_t n);

// Length-explicit variant. Use for strings that may contain embedded NUL
// or are not NUL-terminated. arr[i] is paired with lens[i]; both arrays
// have length n.
SUB_API void sublimation_strings_len(const char **arr, const size_t *lens, size_t n);

// Index-output variant. The input pointer array is READ-ONLY; the output
// is a permutation of 0..n-1 in `indices` such that sorting arr by indices
// produces ascending lex order. Useful when strings live inside a struct
// array (e.g. `std::vector<Process>`) and the caller wants to sort
// indirectly rather than permute a pointer vector.
//
// Caller must pre-allocate `indices` with n slots; contents on entry are
// ignored (the function overwrites with the sorted permutation). Capacity
// n < 2^32.
SUB_API void sublimation_strings_indices(
    const char **arr, uint32_t *indices, size_t n);

// Length-explicit + index-output.
SUB_API void sublimation_strings_indices_len(
    const char **arr, const size_t *lens, uint32_t *indices, size_t n);

#ifdef __cplusplus
}
#endif

#endif // SUBLIMATION_STRINGS_H
