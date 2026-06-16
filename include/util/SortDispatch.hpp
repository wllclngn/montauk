#pragma once
#include <cstdint>
#include <span>

namespace montauk::util {

// montauk's sort layer. sublimation IS montauk's sort algorithm — the
// flow-model adaptive sort, system-installed and linked unconditionally
// (there is no runtime backend choice and no fallback). These are the
// typed adapters from montauk's uint32_t-index model onto sublimation's
// pack-sort / string-sort C entry points.
//
// Sort `indices` by the values in `keys[indices[i]]`. `keys` is read-only;
// `indices` is permuted in place. `descending=true` produces
// highest-key-first. Stable for equal keys: sublimation's pack-sort
// tiebreaks on the packed index, which is initialized from the input order.
void sort_by_key_f32(std::span<const float>    keys, std::span<uint32_t> indices, bool descending);
void sort_by_key_u32(std::span<const uint32_t> keys, std::span<uint32_t> indices, bool descending);
void sort_by_key_i32(std::span<const int32_t>  keys, std::span<uint32_t> indices, bool descending);

// String sort: indices permuted so `arr[indices[i]]` is ascending lex
// order. `arr` is read-only. Dispatches to sublimation_strings_indices
// (hybrid prefix-pack + MSD radix).
void sort_by_string(std::span<const char* const> arr, std::span<uint32_t> indices);

} // namespace montauk::util
