// dfspool.c -- concurrent work-stealing DFS executor (see dfspool.h)
#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE
#include "internal/dfspool.h"
#include <pthread.h>
#include <sched.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <unistd.h>

size_t sub_default_num_workers(void) {
    // Respect cpuset affinity so taskset/cgroup restrictions cap the pool.
    // Falls back to the online CPU count if the syscall is unavailable.
    cpu_set_t set;
    CPU_ZERO(&set);
    long n;
    if (sched_getaffinity(0, sizeof(set), &set) == 0) n = CPU_COUNT(&set);
    else n = sysconf(_SC_NPROCESSORS_ONLN);
    if (n < 1) n = 1;
    if (n > 64) n = 64;
    return (size_t)n;
}

struct sub_dfs_pool {
    sub_wsdeque_t   *deques;      // [num_workers], each cache-line aligned
    size_t           num_workers;
    _Atomic(int64_t) active;      // outstanding frames (seed + pushes - done)
    sub_dfs_fn       fn;
    void            *user;
};

void sub_dfs_push(sub_dfs_ctx_t *ctx, sub_dfs_frame_t child) {
    sub_dfs_pool_t *pool = ctx->pool;
    atomic_fetch_add_explicit(&pool->active, 1, memory_order_relaxed);
    if (!sub_wsdeque_push(&pool->deques[ctx->worker_id], child)) {
        // Grow OOM: process inline so the frame is never lost, then release
        // its accounting (it will never be popped).
        pool->fn(child, ctx, pool->user);
        atomic_fetch_sub_explicit(&pool->active, 1, memory_order_relaxed);
    }
}

static void run_worker(sub_dfs_pool_t *pool, int id, unsigned rng) {
    sub_dfs_ctx_t ctx = { pool, id };
    size_t nw = pool->num_workers;
    rng |= 1u;
    for (;;) {
        sub_dfs_frame_t f;
        if (sub_wsdeque_take(&pool->deques[id], &f)) {
            pool->fn(f, &ctx, pool->user);
            atomic_fetch_sub_explicit(&pool->active, 1, memory_order_relaxed);
            continue;
        }
        // Own deque empty: try to steal from random victims.
        bool got = false;
        for (size_t tries = 0; nw > 1 && tries < nw * 4; tries++) {
            rng ^= rng << 13; rng ^= rng >> 17; rng ^= rng << 5;   // xorshift32
            int v = (int)(rng % nw);
            if (v == id) continue;
            sub_steal_t r = sub_wsdeque_steal(&pool->deques[v], &f);
            if (r == SUB_STEAL_OK) {
                pool->fn(f, &ctx, pool->user);
                atomic_fetch_sub_explicit(&pool->active, 1, memory_order_relaxed);
                got = true;
                break;
            }
            // SUB_STEAL_ABORT / _EMPTY: try another victim
        }
        if (got) continue;
        // Nothing to take or steal. If no work is outstanding anywhere, done.
        if (atomic_load_explicit(&pool->active, memory_order_acquire) == 0) return;
        sched_yield();
    }
}

typedef struct { sub_dfs_pool_t *pool; int id; } worker_arg_t;

static void *worker_entry(void *arg) {
    worker_arg_t *wa = (worker_arg_t *)arg;
    run_worker(wa->pool, wa->id, (unsigned)wa->id * 2654435761u + 1u);
    return nullptr;
}

bool sub_dfs_run(size_t num_workers, sub_dfs_frame_t root,
                 sub_dfs_fn fn, void *user) {
    if (num_workers < 1) num_workers = 1;
    if (num_workers > 64) num_workers = 64;

    sub_dfs_pool_t pool;
    pool.num_workers = num_workers;
    pool.fn = fn;
    pool.user = user;
    atomic_init(&pool.active, 0);

    pool.deques = aligned_alloc(64, num_workers * sizeof(sub_wsdeque_t));
    if (!pool.deques) return false;

    size_t inited = 0;
    for (; inited < num_workers; inited++)
        if (!sub_wsdeque_init(&pool.deques[inited], 256)) break;
    if (inited < num_workers) {
        for (size_t i = 0; i < inited; i++) sub_wsdeque_destroy(&pool.deques[i]);
        free(pool.deques);
        return false;
    }

    // Seed the root on worker 0's deque.
    atomic_fetch_add_explicit(&pool.active, 1, memory_order_relaxed);
    sub_wsdeque_push(&pool.deques[0], root);

    if (num_workers == 1) {
        run_worker(&pool, 0, 1u);
    } else {
        pthread_t   threads[64];
        worker_arg_t args[64];
        size_t started = 0;
        for (size_t w = 0; w < num_workers; w++) {
            args[w].pool = &pool;
            args[w].id = (int)w;
            if (pthread_create(&threads[w], nullptr, worker_entry, &args[w]) != 0)
                break;
            started++;
        }
        if (started == 0)
            run_worker(&pool, 0, 1u);     // spawn failed entirely: drain inline
        else
            for (size_t w = 0; w < started; w++) pthread_join(threads[w], nullptr);
    }

    for (size_t i = 0; i < num_workers; i++) sub_wsdeque_destroy(&pool.deques[i]);
    free(pool.deques);
    return true;
}

// PUBLIC WRAPPER over the deque: index-only parallel-for. See sublimation.h for
// why this is the shape rather than something richer -- anything that knew about
// the caller's data would drag the caller's concerns into the library.
typedef struct { void (*fn)(size_t, void *); void *user; } sub_pfor_t;

static void sub_pfor_frame(sub_dfs_frame_t f, sub_dfs_ctx_t *ctx, void *user) {
    sub_pfor_t *p = (sub_pfor_t *)user;
    if (f.depth == 0) {          // distributor: one leaf per index
        for (size_t i = 0; i < f.n; i++)
            sub_dfs_push(ctx, (sub_dfs_frame_t){ .base = f.base, .n = i, .depth = 1 });
        return;
    }
    p->fn(f.n, p->user);
}

int sublimation_parallel_for(size_t n, size_t num_threads,
                             void (*fn)(size_t index, void *user), void *user) {
    if (!fn || n == 0) return 1;
    sub_pfor_t p = { fn, user };
    sub_dfs_frame_t root = { .base = &p, .n = n, .depth = 0 };
    size_t w = num_threads ? num_threads : sub_default_num_workers();
    return sub_dfs_run(w, root, sub_pfor_frame, &p) ? 1 : 0;
}

size_t sublimation_default_workers(void) { return sub_default_num_workers(); }
