#pragma once
#include <cstdint>
#include <span>

namespace montauk::util {

enum class SortBackend : uint8_t {
  TimSort,
  Sublimation,
};

// Resolved once per process. Reads MONTAUK_SORT_BACKEND env, falls back to
// TimSort when unset / unrecognized / sublimation not compiled in.
SortBackend resolve_backend();

// Sort `indices` by the values in `keys[indices[i]]`. `keys` is read-only;
// `indices` is permuted in place to the new order. When `descending=true`,
// produces highest-key-first.
//
// Stable for equal keys: equal keys retain their original relative index
// order. (Sublimation's pack-sort tiebreaks on the packed index, which is
// initialized from the input order; TimSort fallback is stable by design.)
//
// Backend selection is per-call via resolve_backend(). When backend ==
// Sublimation && HAVE_SUBLIMATION, dispatches to sublimation_pack_sort_<T>.
// Otherwise routes through montauk::util::timsort.
void sort_by_key_f32(std::span<const float>    keys, std::span<uint32_t> indices, bool descending);
void sort_by_key_u32(std::span<const uint32_t> keys, std::span<uint32_t> indices, bool descending);
void sort_by_key_i32(std::span<const int32_t>  keys, std::span<uint32_t> indices, bool descending);

// String sort: indices permuted to the order such that `arr[indices[i]]` is
// ascending lex order. `arr` is read-only.
//
// Sublimation backend dispatches to sublimation_strings_indices (hybrid
// prefix-pack + MSD radix). TimSort fallback uses strcmp through the
// existing montauk::util::timsort.
void sort_by_string(std::span<const char* const> arr, std::span<uint32_t> indices);

} // namespace montauk::util
