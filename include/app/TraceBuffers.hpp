#pragma once
#include <atomic>
#include <cstdint>
#include "model/Trace.hpp"

namespace montauk::app {

// Lock-free double buffer for TraceSnapshot (same pattern as SnapshotBuffers)
class TraceBuffers {
public:
  TraceBuffers();
  TraceBuffers(const TraceBuffers&) = delete;
  TraceBuffers& operator=(const TraceBuffers&) = delete;

  [[nodiscard]] montauk::model::TraceSnapshot& back();
  void publish(); // atomic swap front/back

  [[nodiscard]] const montauk::model::TraceSnapshot& front() const;
  [[nodiscard]] uint64_t seq() const { return front().seq; }

private:
  alignas(64) montauk::model::TraceSnapshot a_{};
  alignas(64) montauk::model::TraceSnapshot b_{};
  std::atomic<montauk::model::TraceSnapshot*> front_{&a_};
  montauk::model::TraceSnapshot* back_{&b_};
};

static_assert(alignof(TraceBuffers) >= 64,
              "TraceBuffers must be cache-line aligned for lock-free publishing");

} // namespace montauk::app
