#pragma once
#include "app/DoubleBuffer.hpp"
#include "model/Snapshot.hpp"

namespace montauk::app {

// Lock-free double buffer for Snapshot
using SnapshotBuffers = DoubleBuffer<montauk::model::Snapshot>;

static_assert(alignof(SnapshotBuffers) >= 64,
              "SnapshotBuffers must be cache-line aligned for lock-free publishing");

} // namespace montauk::app
