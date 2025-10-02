#pragma once
#include <atomic>
#include <cstdint>
#include "model/Snapshot.hpp"

namespace montauk::app {

// Lock‑free double buffer for Snapshot
class SnapshotBuffers {
public:
  SnapshotBuffers();
  // Non-copyable
  SnapshotBuffers(const SnapshotBuffers&) = delete;
  SnapshotBuffers& operator=(const SnapshotBuffers&) = delete;

  montauk::model::Snapshot& back();
  void publish(); // atomic swap front/back

  const montauk::model::Snapshot& front() const;
  uint64_t seq() const { return front().seq; }

private:
  alignas(64) montauk::model::Snapshot a_{};
  alignas(64) montauk::model::Snapshot b_{};
  std::atomic<montauk::model::Snapshot*> front_{&a_};
  montauk::model::Snapshot* back_{&b_};
};

} // namespace montauk::app

