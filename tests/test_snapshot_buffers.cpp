// SnapshotBuffers: double-buffer publish/seqlock semantics.
#include "minitest.hpp"
#include "app/SnapshotBuffers.hpp"

TEST(snapshot_buffers_publish_swaps_and_increments_seq) {
  montauk::app::SnapshotBuffers bufs;
  auto& back = bufs.back();
  back.mem.total_kb = 1000; back.mem.used_kb = 500; back.mem.used_pct = 50.0;
  bufs.publish();
  const auto& front1 = bufs.front();
  ASSERT_EQ(front1.mem.total_kb, 1000u);
  auto seq1 = front1.seq;
  auto& back2 = bufs.back();
  back2.mem.used_kb = 600; back2.mem.used_pct = 60.0;
  bufs.publish();
  const auto& front2 = bufs.front();
  ASSERT_TRUE(front2.seq == seq1 + 1);
  ASSERT_EQ(front2.mem.used_kb, 600u);
}


// publish() swaps without copying, so the buffer it hands back holds the state
// from two publishes ago. carry_forward() starts the next fill from what was
// just published: A field the writer does not refill this cycle must reach
// the next publish as it was, not as it was two publishes earlier.
TEST(snapshot_buffers_carry_forward_keeps_unrefilled_state) {
  montauk::app::SnapshotBuffers bufs;
  bufs.back().mem.total_kb = 1000;
  bufs.back().mem.used_kb = 100;
  bufs.publish();
  bufs.carry_forward();
  bufs.back().mem.used_kb = 200;   // total_kb is not refilled this cycle
  bufs.publish();
  ASSERT_EQ(bufs.front().mem.total_kb, 1000u);
  ASSERT_EQ(bufs.front().mem.used_kb, 200u);
  bufs.carry_forward();
  bufs.publish();
  ASSERT_EQ(bufs.front().mem.used_kb, 200u);
}
