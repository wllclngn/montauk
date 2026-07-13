#pragma once
#include <atomic>
#include <cstdint>

namespace montauk::app {

// Lock-free double buffer, generic over any T carrying a `uint64_t seq`
// member. Same shape SnapshotBuffers and TraceBuffers each hand-rolled
// independently: a writer fills back(), publish() bumps seq and atomically
// swaps front/back, a reader takes front() without ever blocking the writer.
template <typename T>
class DoubleBuffer {
public:
  DoubleBuffer() { a_.seq = 0; b_.seq = 0; }
  DoubleBuffer(const DoubleBuffer&) = delete;
  DoubleBuffer& operator=(const DoubleBuffer&) = delete;

  [[nodiscard]] T& back() { return *back_; }
  void publish() {
    // increment sequence before publish
    back_->seq = front_.load(std::memory_order_acquire)->seq + 1;
    // swap pointers
    auto* old_front = front_.load(std::memory_order_relaxed);
    front_.store(back_, std::memory_order_release);
    back_ = old_front; // now becomes new back
  }

  [[nodiscard]] const T& front() const {
    return *front_.load(std::memory_order_acquire);
  }
  [[nodiscard]] uint64_t seq() const { return front().seq; }

private:
  alignas(64) T a_{};
  alignas(64) T b_{};
  std::atomic<T*> front_{&a_};
  T* back_{&b_};
};

} // namespace montauk::app
