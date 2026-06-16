#include "util/SortDispatch.hpp"

#include "sublimation_pack.h"
#include "sublimation_strings.h"

namespace montauk::util {

void sort_by_key_f32(std::span<const float> keys, std::span<uint32_t> indices, bool descending) {
  sublimation_pack_sort_f32(keys.data(), indices.data(), indices.size(), descending);
}

void sort_by_key_u32(std::span<const uint32_t> keys, std::span<uint32_t> indices, bool descending) {
  sublimation_pack_sort_u32(keys.data(), indices.data(), indices.size(), descending);
}

void sort_by_key_i32(std::span<const int32_t> keys, std::span<uint32_t> indices, bool descending) {
  sublimation_pack_sort_i32(keys.data(), indices.data(), indices.size(), descending);
}

void sort_by_string(std::span<const char* const> arr, std::span<uint32_t> indices) {
  // sublimation_strings_indices takes (const char**, ...) — the array is
  // documented read-only despite the non-const signature. Cast away const.
  sublimation_strings_indices(const_cast<const char**>(arr.data()),
                              indices.data(), indices.size());
}

} // namespace montauk::util
