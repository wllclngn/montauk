// TraceBuffers: double-buffer publish/seqlock semantics (DoubleBuffer<TraceSnapshot>).
#include "minitest.hpp"
#include "app/TraceBuffers.hpp"

TEST(trace_buffers_publish_swaps_and_increments_seq) {
  montauk::app::TraceBuffers bufs;
  auto& back = bufs.back();
  back.procs_count = 3; back.thread_count = 5;
  bufs.publish();
  const auto& front1 = bufs.front();
  ASSERT_EQ(front1.procs_count, 3);
  auto seq1 = front1.seq;
  auto& back2 = bufs.back();
  back2.thread_count = 7;
  bufs.publish();
  const auto& front2 = bufs.front();
  ASSERT_TRUE(front2.seq == seq1 + 1);
  ASSERT_EQ(front2.thread_count, 7);
}
