#include "util/SortDispatch.hpp"

#include "sublimation_pack.h"
#include "sublimation_strings.h"

#include <vector>

namespace montauk::util {

// The pack sorts otherwise malloc an n-slot scratch per call, and these run
// per frame on the process table (several columns per frame). A thread-local
// buffer grown to n reuses that capacity across frames and columns; each
// thread gets its own, so no locking and no cross-thread aliasing. Threads
// that never sort never allocate it.
static uint64_t* frame_scratch(size_t n) {
  thread_local std::vector<uint64_t> buf;
  if (buf.size() < n) buf.resize(n);
  return buf.data();
}

void sort_by_key_f32(std::span<const float> keys, std::span<uint32_t> indices, bool descending) {
  sublimation_pack_sort_f32_with_scratch(keys.data(), indices.data(), indices.size(),
                                         descending, frame_scratch(indices.size()));
}

void sort_by_key_u32(std::span<const uint32_t> keys, std::span<uint32_t> indices, bool descending) {
  sublimation_pack_sort_u32_with_scratch(keys.data(), indices.data(), indices.size(),
                                         descending, frame_scratch(indices.size()));
}

void sort_by_key_i32(std::span<const int32_t> keys, std::span<uint32_t> indices, bool descending) {
  sublimation_pack_sort_i32_with_scratch(keys.data(), indices.data(), indices.size(),
                                         descending, frame_scratch(indices.size()));
}

void sort_by_string(std::span<const char* const> arr, std::span<uint32_t> indices) {
  // sublimation_strings_indices takes (const char**, ...) — the array is
  // documented read-only despite the non-const signature. Cast away const.
  sublimation_strings_indices(const_cast<const char**>(arr.data()),
                              indices.data(), indices.size());
}

} // namespace montauk::util
