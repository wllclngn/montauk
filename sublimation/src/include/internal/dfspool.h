// dfspool.h -- concurrent work-stealing DFS executor (C23)
//
// A generic parallel depth-first driver over sub_dfs_frame_t work items, built
// on the per-worker Chase-Lev deques (wsdeque.h). The owner of each frame runs
// a caller-supplied callback that may split the frame and push children back
// onto its own deque (depth-first, cache-hot); idle workers steal the oldest
// frames from random victims (breadth-first, the largest remaining work).
// Termination is an outstanding-work counter: when it reaches zero, every
// pushed frame has been fully processed and all workers exit.
//
// The sort rehomes its partition tree onto this: process = coarsen-or-partition
// (serial-sort a small frame, else split and push children). Disjoint frames
// own disjoint array regions, so the sorted data itself is never touched
// concurrently -- no atomics on the payload, only on the deques.
#ifndef SUB_DFSPOOL_H
#define SUB_DFSPOOL_H

#include <stddef.h>
#include <stdbool.h>
#include "wsdeque.h"

typedef struct sub_dfs_pool sub_dfs_pool_t;

// Passed to the callback; carries the handle needed to push child frames.
typedef struct {
    sub_dfs_pool_t *pool;
    int             worker_id;
} sub_dfs_ctx_t;

// Per-frame callback. Runs on the worker that owns the frame. May call
// sub_dfs_push to enqueue children onto that same worker's deque.
typedef void (*sub_dfs_fn)(sub_dfs_frame_t frame, sub_dfs_ctx_t *ctx, void *user);

// Push a child frame onto the current worker's deque. Owner-only: call ONLY
// from inside the callback. Accounts the frame in the outstanding-work counter.
void sub_dfs_push(sub_dfs_ctx_t *ctx, sub_dfs_frame_t child);

// Seed `root`, spawn min(num_workers,64) workers, run `fn` per frame until the
// tree drains, then join. num_workers <= 1 drains inline on the calling thread
// (no spawn). Returns false only on setup allocation failure (caller should
// fall back to a serial sort). Blocking.
bool sub_dfs_run(size_t num_workers, sub_dfs_frame_t root,
                 sub_dfs_fn fn, void *user);

// Hardware worker count, honoring cpuset/cgroup affinity. Clamped to [1,64].
size_t sub_default_num_workers(void);

#endif // SUB_DFSPOOL_H
