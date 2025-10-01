#include "minitest.hpp"
#include "app/SnapshotBuffers.hpp"

TEST(snapshot_buffers_publish_swaps_and_increments_seq) {
  lsm::app::SnapshotBuffers bufs;
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

