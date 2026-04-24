#include "util/SortDispatch.hpp"
#include "util/TimSort.hpp"

#ifdef HAVE_SUBLIMATION
#include "sublimation_pack.h"
#include "sublimation_strings.h"
#endif

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <vector>

namespace montauk::util {

SortBackend resolve_backend() {
  static const SortBackend cached = []() {
#ifdef HAVE_SUBLIMATION
    // Compiled WITH sublimation = use sublimation by default. The env var is
    // an OPT-OUT switch for users who want to fall back to the legacy
    // TimSort path (e.g. for behavior comparison or bug isolation).
    if (const char* env = std::getenv("MONTAUK_SORT_BACKEND")) {
      if (std::strcmp(env, "timsort") == 0)     return SortBackend::TimSort;
      if (std::strcmp(env, "sublimation") == 0) return SortBackend::Sublimation;
    }
    return SortBackend::Sublimation;
#else
    return SortBackend::TimSort;
#endif
  }();
  return cached;
}

namespace {

// TimSort takes vector<size_t>::iterator. The dispatcher uses uint32_t for
// pack-sort compatibility. Convert at the boundary; cost is O(n) and at the
// process-table sizes (N <= 4096) is invisible.
template <typename Compare>
void timsort_indices(std::span<uint32_t> indices, Compare cmp) {
  std::vector<size_t> tmp(indices.begin(), indices.end());
  montauk::util::timsort(tmp.begin(), tmp.end(),
                         [&](size_t a, size_t b) { return cmp(static_cast<uint32_t>(a),
                                                              static_cast<uint32_t>(b)); });
  for (size_t i = 0; i < indices.size(); ++i) indices[i] = static_cast<uint32_t>(tmp[i]);
}

template <typename KeyT>
void sort_by_key_timsort(std::span<const KeyT> keys, std::span<uint32_t> indices, bool descending) {
  if (descending) {
    timsort_indices(indices, [&](uint32_t a, uint32_t b) { return keys[a] > keys[b]; });
  } else {
    timsort_indices(indices, [&](uint32_t a, uint32_t b) { return keys[a] < keys[b]; });
  }
}

} // anonymous namespace

void sort_by_key_f32(std::span<const float> keys, std::span<uint32_t> indices, bool descending) {
#ifdef HAVE_SUBLIMATION
  if (resolve_backend() == SortBackend::Sublimation) {
    sublimation_pack_sort_f32(keys.data(), indices.data(), indices.size(), descending);
    return;
  }
#endif
  sort_by_key_timsort<float>(keys, indices, descending);
}

void sort_by_key_u32(std::span<const uint32_t> keys, std::span<uint32_t> indices, bool descending) {
#ifdef HAVE_SUBLIMATION
  if (resolve_backend() == SortBackend::Sublimation) {
    sublimation_pack_sort_u32(keys.data(), indices.data(), indices.size(), descending);
    return;
  }
#endif
  sort_by_key_timsort<uint32_t>(keys, indices, descending);
}

void sort_by_key_i32(std::span<const int32_t> keys, std::span<uint32_t> indices, bool descending) {
#ifdef HAVE_SUBLIMATION
  if (resolve_backend() == SortBackend::Sublimation) {
    sublimation_pack_sort_i32(keys.data(), indices.data(), indices.size(), descending);
    return;
  }
#endif
  sort_by_key_timsort<int32_t>(keys, indices, descending);
}

void sort_by_string(std::span<const char* const> arr, std::span<uint32_t> indices) {
#ifdef HAVE_SUBLIMATION
  if (resolve_backend() == SortBackend::Sublimation) {
    // sublimation_strings_indices takes (const char**, ...) -- the array is
    // documented read-only despite the non-const sig. Cast away const.
    sublimation_strings_indices(const_cast<const char**>(arr.data()),
                                indices.data(), indices.size());
    return;
  }
#endif
  timsort_indices(indices, [&](uint32_t a, uint32_t b) {
    return std::strcmp(arr[a], arr[b]) < 0;
  });
}

} // namespace montauk::util
