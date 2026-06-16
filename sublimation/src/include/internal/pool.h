// pool.h -- Bulk-synchronous parallel sort pool
//
//   - Static chunk assignment (no shared work queue)
//   - Per-worker result arrays (no lock for collection)
//   - Barrier synchronization between phases
//
// No MPMC queue. No work stealing. No atomic head/tail races.
#ifndef SUB_POOL_H
#define SUB_POOL_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <pthread.h>

#include "c23_compat.h"

// Per-worker statistics (no contention)
typedef struct {
    uint64_t comparisons;
    uint64_t swaps;
    uint64_t levels_built;
} sub_worker_stats_t;

// Worker context (one per thread, assigned before launch)
typedef struct {
    int64_t         *arr;           // shared array (workers sort disjoint regions)
    size_t           lo, hi;        // this worker's assigned region
    int              disorder;      // classification hint
    sub_worker_stats_t stats;        // local stats (flushed at end)
    int              worker_id;
} sub_worker_ctx_t;

// Parallel sort entry (BSP model)
// Classifies, partitions into buckets, assigns buckets to workers, barrier.
void sub_parallel_sort_i64(int64_t *arr, size_t n, size_t num_workers,
                           int disorder);

// Get hardware thread count
size_t sub_default_num_workers(void);

#endif // SUB_POOL_H
