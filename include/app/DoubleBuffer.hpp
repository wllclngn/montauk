#pragma once
#include <atomic>
#include <cstdint>
#include <shared_mutex>

namespace montauk::app {

// Lock-free-fill double buffer, generic over any T carrying a `uint64_t seq`
// member. Same shape SnapshotBuffers and TraceBuffers each hand-rolled
// independently: a writer fills back(), publish() bumps seq and atomically
// swaps front/back, a reader takes front() without ever blocking the writer.
//
// T here carries non-trivially-copyable payload (vectors, strings), so a bare
// seqlock is unsafe: a reader copying the front buffer while the writer begins
// REUSING that same physical buffer (two publishes after the reader sampled it)
// dereferences a freed heap block, not merely stale bytes. A per-buffer
// shared_mutex closes exactly that reuse window -- read() copies the front under
// a shared lock; begin_write() unique-locks a buffer before the writer refills
// it, waiting out any reader still on it. Readers of the live front never
// contend with the writer (different buffer); the writer only ever waits on a
// reader still holding the buffer it is about to recycle.
template <typename T>
class DoubleBuffer {
public:
  DoubleBuffer() { a_.seq = 0; b_.seq = 0; }
  DoubleBuffer(const DoubleBuffer&) = delete;
  DoubleBuffer& operator=(const DoubleBuffer&) = delete;

  // Single-threaded fill (tests): no reuse guard, matched by publish().
  [[nodiscard]] T& back() { return *back_; }

  // Concurrent fill (the Producer): lock the back buffer against any reader
  // still copying it before handing it over for in-place mutation. Idempotent --
  // the writer accumulates samples into back() across many loop iterations and
  // calls this each one, but holds the buffer's lock continuously until publish()
  // hands it to readers; a second call before that publish is a no-op.
  [[nodiscard]] T& begin_write() {
    if (!write_locked_) {
      mtx_for(back_).lock();
      write_locked_ = true;
    }
    return *back_;
  }

  void publish() {
    // increment sequence before publish
    back_->seq = front_.load(std::memory_order_acquire)->seq + 1;
    // swap pointers
    auto* old_front = front_.load(std::memory_order_relaxed);
    front_.store(back_, std::memory_order_release);
    if (write_locked_) {  // release the just-published buffer for readers
      write_locked_ = false;
      mtx_for(back_).unlock();
    }
    back_ = old_front; // now becomes new back
  }

  // Copy the front buffer under a shared lock so the writer cannot begin reusing
  // it mid-copy. fn receives const T& and returns the caller's snapshot type.
  template <typename Fn>
  [[nodiscard]] auto read(Fn&& fn) const {
    for (;;) {
      T* f = front_.load(std::memory_order_acquire);
      std::shared_lock<std::shared_mutex> lk(mtx_for(f));
      // A swap between the load and the lock means f may now be the writer's
      // fill target; re-read and retry so fn only ever runs on the live front.
      if (front_.load(std::memory_order_acquire) != f) continue;
      return fn(static_cast<const T&>(*f));
    }
  }

  [[nodiscard]] const T& front() const {
    return *front_.load(std::memory_order_acquire);
  }
  [[nodiscard]] uint64_t seq() const { return front().seq; }

private:
  std::shared_mutex& mtx_for(const T* p) const { return p == &a_ ? m_a_ : m_b_; }

  alignas(64) T a_{};
  alignas(64) T b_{};
  std::atomic<T*> front_{&a_};
  T* back_{&b_};
  bool write_locked_{false};
  mutable std::shared_mutex m_a_;
  mutable std::shared_mutex m_b_;
};

} // namespace montauk::app
