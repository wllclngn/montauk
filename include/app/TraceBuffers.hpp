#pragma once
#include "app/DoubleBuffer.hpp"
#include "model/Trace.hpp"

namespace montauk::app {

// Lock-free double buffer for TraceSnapshot
using TraceBuffers = DoubleBuffer<montauk::model::TraceSnapshot>;

static_assert(alignof(TraceBuffers) >= 64,
              "TraceBuffers must be cache-line aligned for lock-free publishing");

} // namespace montauk::app
