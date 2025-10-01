#include "app/SnapshotBuffers.hpp"

namespace lsm::app {

SnapshotBuffers::SnapshotBuffers() {
  a_.seq = 0; b_.seq = 0;
}

lsm::model::Snapshot& SnapshotBuffers::back() { return *back_; }

void SnapshotBuffers::publish() {
  // increment sequence before publish
  back_->seq = front_.load(std::memory_order_acquire)->seq + 1;
  // swap pointers
  auto* old_front = front_.load(std::memory_order_relaxed);
  front_.store(back_, std::memory_order_release);
  back_ = old_front; // now becomes new back
}

const lsm::model::Snapshot& SnapshotBuffers::front() const {
  return *front_.load(std::memory_order_acquire);
}

} // namespace lsm::app

