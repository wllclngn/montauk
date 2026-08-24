// sublimation_strings.h -- public string-sort entry points
//
// Sorts arrays of byte-strings in lexicographic order using a hybrid
// pipeline: 4-byte big-endian prefix-pack into uint64 -> sublimation_u64
// (the full adaptive pipeline runs on prefixes) -> MSD radix tiebreak on
// suffix bytes within prefix-collision clusters -> pointer permutation.
//
// Stability: NOT stable. Equal-content strings may swap relative order.
//   Matches the convention of std::sort and Rust slice::sort_unstable.
//
// Capacity: n must be < 2^32. Larger inputs trigger an in-house
//   introsort+strcmp fallback (no libc qsort anywhere in the library)
//   with a stderr warning to avoid silent index truncation.
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

// K-WAY MERGE OF ALREADY-SORTED STRING RUNS. The string half of the merge
// family declared in sublimation.h, with the identical contract: merging k
// already-ordered runs is byte-identical to sorting the concatenation, and the
// merge is stable by run index so equal keys leave in run order. Returns 0 on
// success, -1 if scratch could not be allocated, or whatever nonzero value
// `emit` returned.
//
// `pull` fills at most `cap` pointers for run `run` and returns how many;
// returning 0 ends that run, and a short read does not.
typedef size_t (*sublimation_merge_pull_strings)(void *ctx, size_t run,
                                                 const char **buf, size_t cap);
typedef int (*sublimation_merge_emit_strings)(void *ctx, const char *const *buf,
                                              size_t n);

SUB_API int sublimation_merge_stream_strings(
    size_t k, sublimation_merge_pull_strings pull, void *pull_ctx,
    sublimation_merge_emit_strings emit, void *emit_ctx);

// Span face: k in-memory runs of already-sorted pointers. `out` must hold the
// sum of `lens`. String contents are untouched; only pointers move.
SUB_API int sublimation_merge_strings(const char *const *const *runs,
                                      const size_t *lens, size_t k,
                                      const char **out);

// Index face, for callers holding ROWS rather than keys: `arr` is the caller's
// string array, each run is an already-ordered list of indices into it, and the
// result is one ordered permutation. Not streamed -- an index only means
// something against an array the caller already holds, so there is nothing to
// pull. `out` must hold the sum of `lens`.
SUB_API int sublimation_merge_strings_indices(const char **arr,
                                              const uint32_t *const *runs,
                                              const size_t *lens, size_t k,
                                              uint32_t *out);

#ifdef __cplusplus
}
#endif

#endif // SUBLIMATION_STRINGS_H
