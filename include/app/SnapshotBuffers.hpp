#pragma once
#include <atomic>
#include <cstdint>
#include "model/Snapshot.hpp"

namespace lsm::app {

// Lock‑free double buffer for Snapshot
class SnapshotBuffers {
public:
  SnapshotBuffers();
  // Non-copyable
  SnapshotBuffers(const SnapshotBuffers&) = delete;
  SnapshotBuffers& operator=(const SnapshotBuffers&) = delete;

  lsm::model::Snapshot& back();
  void publish(); // atomic swap front/back

  const lsm::model::Snapshot& front() const;
  uint64_t seq() const { return front().seq; }

private:
  alignas(64) lsm::model::Snapshot a_{};
  alignas(64) lsm::model::Snapshot b_{};
  std::atomic<lsm::model::Snapshot*> front_{&a_};
  lsm::model::Snapshot* back_{&b_};
};

} // namespace lsm::app

