#pragma once

#include <cstddef>
#include <vector>

namespace montauk::util {

// Fixed-capacity ring buffer of samples. In-RAM only; not persisted.
//
// Used by the chart pipeline to hold the recent history of a metric so the
// rasterizer can draw a scrolling curve without recomputing the whole window
// each frame. Single-writer (producer) / single-reader (render loop) usage
// pattern; not lock-free, so callers must sequence push/recent appropriately.
// In montauk's architecture the producer writes between snapshot flips and
// the render loop reads after a snapshot is taken — no contention.
//
// `recent(count)` returns up to the last `count` samples in oldest-to-newest
// order as a std::vector (copied out). Returns fewer than `count` entries if
// the buffer has not yet filled. An empty buffer returns an empty vector.
template <typename T>
class History {
 public:
  explicit History(std::size_t capacity)
      : buffer_(capacity), capacity_(capacity) {}

  void push(const T& sample) {
    if (capacity_ == 0) return;
    buffer_[head_] = sample;
    head_ = (head_ + 1) % capacity_;
    if (size_ < capacity_) ++size_;
  }

  [[nodiscard]] std::size_t size() const { return size_; }
  [[nodiscard]] std::size_t capacity() const { return capacity_; }
  [[nodiscard]] bool empty() const { return size_ == 0; }

  // Copy the most recent `count` samples into oldest→newest order.
  // If `count` exceeds available, returns everything available.
  [[nodiscard]] std::vector<T> recent(std::size_t count) const {
    std::vector<T> out;
    if (size_ == 0 || count == 0) return out;
    const std::size_t take = (count < size_) ? count : size_;
    out.reserve(take);
    // Oldest-to-newest walk: start at (head_ - size_ + (size_ - take)) mod cap
    const std::size_t start = (head_ + capacity_ - take) % capacity_;
    for (std::size_t i = 0; i < take; ++i) {
      out.push_back(buffer_[(start + i) % capacity_]);
    }
    return out;
  }

  // Resize capacity (clears the buffer). Use on TOML history_seconds change.
  void resize(std::size_t new_capacity) {
    buffer_.assign(new_capacity, T{});
    capacity_ = new_capacity;
    head_ = 0;
    size_ = 0;
  }

 private:
  std::vector<T> buffer_;
  std::size_t capacity_ = 0;
  std::size_t head_ = 0;
  std::size_t size_ = 0;
};

} // namespace montauk::util
