// pool.c -- IPS4o-style parallel sort
//
//   1. Sample splitters (sequential, O(k * oversample))
//   2. Parallel classification: each worker classifies its chunk
//      and caches bucket assignments. Per-worker bucket counts,
//      no contention.
//   3. Prefix-sum merge: sequential, O(k * num_workers) -- tiny.
//   4. Parallel scatter: each worker scatters its chunk into global
//      bucket positions using cached assignments. Disjoint writes.
//   5. Parallel per-bucket sort: greedy load-balanced assignment,
//      largest bucket to the least-loaded worker.
//
// Thread lifecycle is paid ONCE per sort: the worker threads are spawned a
// single time and held across all phases with a barrier, rather than the
// three create+join waves an earlier version paid. The serial sections
// (prefix-sum merge, scatter-back + greedy assignment) run on worker 0 while
// the others wait at the next barrier. This is deliberately intra-sort, not a
// persistent cross-call pool: sublimation stays a stateless, synchronous
// library that owns no threads between calls. Measured worth it -- at the
// n>=250K threshold the three-wave lifecycle was ~35% of the sort.
#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE
#include "internal/pool.h"
#include "internal/sort_internal.h"
#include <pthread.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// SPLITTER SAMPLING
//
// Oversampled: take oversample * (k-1) candidates from evenly spaced
// positions, sort them, pick quantiles. Better bucket balance.
static void sample_splitters(const int64_t *arr, size_t n,
                              int64_t *splitters, size_t k) {
    if (k <= 1) return;
    size_t num_splitters = k - 1;

    size_t oversample = 16;
    size_t num_candidates = oversample * num_splitters;
    if (num_candidates > n / 2) num_candidates = n / 2;
    if (num_candidates < num_splitters) num_candidates = num_splitters;

    int64_t *candidates = malloc(num_candidates * sizeof(int64_t));
    if (!candidates) {
        // fallback: equidistant
        size_t stride = n / k;
        if (stride < 1) stride = 1;
        for (size_t i = 0; i < num_splitters; i++) {
            splitters[i] = arr[(i + 1) * stride];
        }
        for (size_t i = 1; i < num_splitters; i++) {
            int64_t key = splitters[i];
            size_t j = i;
            while (j > 0 && splitters[j - 1] > key) {
                splitters[j] = splitters[j - 1];
                j--;
            }
            splitters[j] = key;
        }
        return;
    }

    size_t stride = n / num_candidates;
    if (stride < 1) stride = 1;
    for (size_t i = 0; i < num_candidates; i++) {
        size_t idx = i * stride + stride / 2;
        if (idx >= n) idx = n - 1;
        candidates[i] = arr[idx];
    }

    // sort candidates (insertion sort, num_candidates is small)
    for (size_t i = 1; i < num_candidates; i++) {
        int64_t key = candidates[i];
        size_t j = i;
        while (j > 0 && candidates[j - 1] > key) {
            candidates[j] = candidates[j - 1];
            j--;
        }
        candidates[j] = key;
    }

    for (size_t i = 0; i < num_splitters; i++) {
        size_t idx = (i + 1) * num_candidates / k;
        if (idx >= num_candidates) idx = num_candidates - 1;
        splitters[i] = candidates[idx];
    }

    free(candidates);
}

// Find bucket via binary search on splitters
static inline size_t find_bucket(int64_t val, const int64_t *splitters,
                                  size_t num_splitters) {
    size_t lo = 0, hi = num_splitters;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (splitters[mid] <= val) lo = mid + 1;
        else hi = mid;
    }
    return lo;
}

// Start-gate: workers park here until the main thread confirms every worker
// spawned (go) or that one failed (abort), so a create failure never leaves a
// worker deadlocked on a barrier sized for the full set.
typedef struct {
    pthread_mutex_t m;
    pthread_cond_t  c;
    int             state;   // 0 = wait, 1 = go, 2 = abort
} sub_gate_t;

// One worker's view of the sort. All the matrix pointers are shared (identical
// across workers); worker 0 alone reads/writes the global_* arrays and the
// sort assignment during the serial sections, fenced by the barrier.
typedef struct {
    int             worker_id;
    size_t          num_workers;

    int64_t        *arr;
    size_t          n;
    const int64_t  *splitters;
    size_t          num_splitters;
    size_t          k;               // num_buckets
    int64_t        *scratch;

    size_t          chunk_lo;
    size_t          chunk_hi;        // exclusive
    size_t         *my_counts;       // &counts_matrix[w*k]
    uint16_t       *my_buckets;      // &all_buckets[chunk_lo]
    size_t         *my_offsets;      // &offsets_matrix[w*k]

    // shared, worker 0 owns during serial sections
    size_t         *counts_matrix;
    size_t         *offsets_matrix;
    size_t         *global_counts;
    size_t         *global_offsets;
    size_t         *bucket_order;
    size_t         *assign_offsets;  // flattened per-worker bucket start offsets
    size_t         *assign_counts;   // flattened per-worker bucket sizes
    size_t         *worker_sort_start; // [num_workers] slice start in assign_*
    size_t         *worker_sort_n;     // [num_workers] slice length

    pthread_barrier_t *barrier;
    sub_gate_t        *gate;
} sub_pool_worker_t;

// PHASE 2 body: count + cache bucket assignments for this chunk.
static void do_classify(sub_pool_worker_t *c) {
    memset(c->my_counts, 0, c->k * sizeof(size_t));
    size_t len = c->chunk_hi - c->chunk_lo;
    for (size_t i = 0; i < len; i++) {
        size_t b = find_bucket(c->arr[c->chunk_lo + i], c->splitters,
                               c->num_splitters);
        c->my_buckets[i] = (uint16_t)b;
        c->my_counts[b]++;
    }
}

// PHASE 3 body (worker 0): prefix-sum merge over the per-worker counts into
// global bucket counts, global bucket offsets, and each worker's write cursor.
static void do_merge(sub_pool_worker_t *c) {
    size_t k = c->k, nw = c->num_workers;
    for (size_t b = 0; b < k; b++) {
        size_t total = 0;
        for (size_t w = 0; w < nw; w++) total += c->counts_matrix[w * k + b];
        c->global_counts[b] = total;
    }
    c->global_offsets[0] = 0;
    for (size_t b = 1; b < k; b++)
        c->global_offsets[b] = c->global_offsets[b - 1] + c->global_counts[b - 1];
    for (size_t b = 0; b < k; b++) {
        size_t running = c->global_offsets[b];
        for (size_t w = 0; w < nw; w++) {
            c->offsets_matrix[w * k + b] = running;
            running += c->counts_matrix[w * k + b];
        }
    }
}

// PHASE 4 body: scatter this chunk into global bucket positions using cached
// assignments. Disjoint writes across workers.
static void do_scatter(sub_pool_worker_t *c) {
    size_t len = c->chunk_hi - c->chunk_lo;
    for (size_t i = 0; i < len; i++) {
        size_t b = c->my_buckets[i];
        c->scratch[c->my_offsets[b]++] = c->arr[c->chunk_lo + i];
    }
}

// PHASE 5 setup (worker 0): scatter back into arr, then greedily assign
// buckets (largest first) to the least-loaded worker, recording each worker's
// slice of the flattened assignment arrays.
static void do_assign(sub_pool_worker_t *c) {
    memcpy(c->arr, c->scratch, c->n * sizeof(int64_t));

    size_t k = c->k, nw = c->num_workers;
    for (size_t i = 0; i < k; i++) c->bucket_order[i] = i;
    // insertion sort bucket indices by descending count
    for (size_t i = 1; i < k; i++) {
        size_t key = c->bucket_order[i];
        size_t j = i;
        while (j > 0 &&
               c->global_counts[c->bucket_order[j - 1]] < c->global_counts[key]) {
            c->bucket_order[j] = c->bucket_order[j - 1];
            j--;
        }
        c->bucket_order[j] = key;
    }

    size_t load[64] = {0};
    size_t nass[64] = {0};
    for (size_t i = 0; i < k; i++) {
        size_t b = c->bucket_order[i];
        if (c->global_counts[b] <= 1) continue;
        size_t best = 0;
        for (size_t w = 1; w < nw; w++) if (load[w] < load[best]) best = w;
        load[best] += c->global_counts[b];
        nass[best]++;
    }

    size_t off = 0;
    for (size_t w = 0; w < nw; w++) {
        c->worker_sort_start[w] = off;
        off += nass[w];
        c->worker_sort_n[w] = 0;
    }

    size_t load2[64] = {0};
    for (size_t i = 0; i < k; i++) {
        size_t b = c->bucket_order[i];
        if (c->global_counts[b] <= 1) continue;
        size_t best = 0;
        for (size_t w = 1; w < nw; w++) if (load2[w] < load2[best]) best = w;
        load2[best] += c->global_counts[b];
        size_t slot = c->worker_sort_start[best] + c->worker_sort_n[best];
        c->assign_offsets[slot] = c->global_offsets[b];
        c->assign_counts[slot] = c->global_counts[b];
        c->worker_sort_n[best]++;
    }
}

// PHASE 5 body: sort this worker's assigned buckets in place.
static void do_sort(sub_pool_worker_t *c) {
    size_t start = c->worker_sort_start[c->worker_id];
    size_t cnt = c->worker_sort_n[c->worker_id];
    for (size_t j = 0; j < cnt; j++) {
        size_t bn = c->assign_counts[start + j];
        if (bn <= 1) continue;
        sub_adaptive_t state;
        sub_adaptive_init(&state, bn);
        sub_sort_internal_i64(c->arr + c->assign_offsets[start + j], bn,
                              &state, NULL);
    }
}

// Persistent worker: one spawn, all phases, barrier between each.
static void *worker_all(void *arg) {
    sub_pool_worker_t *c = (sub_pool_worker_t *)arg;

    pthread_mutex_lock(&c->gate->m);
    while (c->gate->state == 0) pthread_cond_wait(&c->gate->c, &c->gate->m);
    int go = c->gate->state;
    pthread_mutex_unlock(&c->gate->m);
    if (go == 2) return nullptr;   // a sibling failed to spawn; abort cleanly

    do_classify(c);
    pthread_barrier_wait(c->barrier);                 // (1) all classified
    if (c->worker_id == 0) do_merge(c);
    pthread_barrier_wait(c->barrier);                 // (2) offsets ready
    do_scatter(c);
    pthread_barrier_wait(c->barrier);                 // (3) all scattered
    if (c->worker_id == 0) do_assign(c);
    pthread_barrier_wait(c->barrier);                 // (4) arr + assignment ready
    do_sort(c);
    return nullptr;
}

static void sequential_sort(int64_t *arr, size_t n) {
    sub_adaptive_t state;
    sub_adaptive_init(&state, n);
    sub_sort_internal_i64(arr, n, &state, NULL);
}

// PARALLEL SORT ENTRY POINT
void sub_parallel_sort_i64(int64_t *arr, size_t n, size_t num_workers,
                           int disorder) {
    (void)disorder;   // per-bucket sort is adaptive; kept for ABI stability
    if (n <= 1) return;
    if (num_workers < 2) num_workers = 2;
    if (num_workers > 64) num_workers = 64;

    // Overpartition: more buckets than workers for load balance. Each worker
    // handles multiple buckets in the sort phase via greedy assignment.
    size_t k = num_workers * 4;
    if (k > n / 128) k = n / 128;   // at least 128 elements per bucket
    if (k < num_workers) k = num_workers;
    if (k < 2) k = 2;
    if (k > 256) k = 256;           // cap for uint16_t and sanity

    size_t num_splitters = k - 1;

    // ALLOCATE
    size_t scratch_bytes, buckets_bytes;
    if (ckd_mul(&scratch_bytes, n, sizeof(int64_t)) ||
        ckd_mul(&buckets_bytes, n, sizeof(uint16_t))) {
        return; // overflow: n too large
    }
    int64_t *splitters = malloc(num_splitters * sizeof(int64_t));
    int64_t *scratch = malloc(scratch_bytes);
    size_t *counts_matrix = calloc(num_workers * k, sizeof(size_t));
    size_t *offsets_matrix = malloc(num_workers * k * sizeof(size_t));
    size_t *global_offsets = malloc(k * sizeof(size_t));
    size_t *global_counts = malloc(k * sizeof(size_t));
    uint16_t *all_buckets = malloc(buckets_bytes);
    size_t *bucket_order = malloc(k * sizeof(size_t));
    size_t *assign_offsets = malloc(k * sizeof(size_t));
    size_t *assign_counts = malloc(k * sizeof(size_t));
    size_t *worker_sort_start = malloc(num_workers * sizeof(size_t));
    size_t *worker_sort_n = malloc(num_workers * sizeof(size_t));
    pthread_t *threads = malloc(num_workers * sizeof(pthread_t));
    sub_pool_worker_t *ctxs = malloc(num_workers * sizeof(sub_pool_worker_t));

    if (!splitters || !scratch || !counts_matrix || !offsets_matrix ||
        !global_offsets || !global_counts || !all_buckets || !bucket_order ||
        !assign_offsets || !assign_counts || !worker_sort_start ||
        !worker_sort_n || !threads || !ctxs) {
        if (arr && n > 1) sequential_sort(arr, n);
        goto cleanup;
    }

    // PHASE 1: SAMPLE SPLITTERS
    sample_splitters(arr, n, splitters, k);

    pthread_barrier_t barrier;
    pthread_barrier_init(&barrier, nullptr, (unsigned)num_workers);
    sub_gate_t gate;
    pthread_mutex_init(&gate.m, nullptr);
    pthread_cond_init(&gate.c, nullptr);
    gate.state = 0;

    size_t chunk_size = (n + num_workers - 1) / num_workers;
    for (size_t w = 0; w < num_workers; w++) {
        size_t lo = w * chunk_size;
        size_t hi = lo + chunk_size;
        if (hi > n) hi = n;
        if (lo > n) lo = n;

        ctxs[w].worker_id = (int)w;
        ctxs[w].num_workers = num_workers;
        ctxs[w].arr = arr;
        ctxs[w].n = n;
        ctxs[w].splitters = splitters;
        ctxs[w].num_splitters = num_splitters;
        ctxs[w].k = k;
        ctxs[w].scratch = scratch;
        ctxs[w].chunk_lo = lo;
        ctxs[w].chunk_hi = hi;
        ctxs[w].my_counts = &counts_matrix[w * k];
        ctxs[w].my_buckets = &all_buckets[lo];
        ctxs[w].my_offsets = &offsets_matrix[w * k];
        ctxs[w].counts_matrix = counts_matrix;
        ctxs[w].offsets_matrix = offsets_matrix;
        ctxs[w].global_counts = global_counts;
        ctxs[w].global_offsets = global_offsets;
        ctxs[w].bucket_order = bucket_order;
        ctxs[w].assign_offsets = assign_offsets;
        ctxs[w].assign_counts = assign_counts;
        ctxs[w].worker_sort_start = worker_sort_start;
        ctxs[w].worker_sort_n = worker_sort_n;
        ctxs[w].barrier = &barrier;
        ctxs[w].gate = &gate;
    }

    // Spawn once. Workers park on the gate until we confirm all spawned; a
    // create failure aborts every worker before it touches the barrier, then
    // we sort sequentially -- the same resource-exhaustion fallback the
    // allocation failure above takes. No worker can deadlock on a barrier
    // sized for a set that never fully spawned, and on abort arr is untouched.
    size_t started = 0;
    for (size_t w = 0; w < num_workers; w++) {
        if (pthread_create(&threads[w], nullptr, worker_all, &ctxs[w]) != 0)
            break;
        started++;
    }

    bool all_started = (started == num_workers);
    pthread_mutex_lock(&gate.m);
    gate.state = all_started ? 1 : 2;
    pthread_cond_broadcast(&gate.c);
    pthread_mutex_unlock(&gate.m);

    for (size_t w = 0; w < started; w++)
        pthread_join(threads[w], nullptr);

    pthread_barrier_destroy(&barrier);
    pthread_mutex_destroy(&gate.m);
    pthread_cond_destroy(&gate.c);

    if (!all_started) sequential_sort(arr, n);

cleanup:
    free(splitters);
    free(scratch);
    free(counts_matrix);
    free(offsets_matrix);
    free(global_offsets);
    free(global_counts);
    free(all_buckets);
    free(bucket_order);
    free(assign_offsets);
    free(assign_counts);
    free(worker_sort_start);
    free(worker_sort_n);
    free(threads);
    free(ctxs);
}

size_t sub_default_num_workers(void) {
    // Respect cpuset affinity so taskset/cgroup restrictions actually cap
    // the worker pool. Falls back to system online count if the syscall is
    // unavailable.
    cpu_set_t set;
    CPU_ZERO(&set);
    long n;
    if (sched_getaffinity(0, sizeof(set), &set) == 0) {
        n = CPU_COUNT(&set);
    } else {
        n = sysconf(_SC_NPROCESSORS_ONLN);
    }
    if (n < 1) n = 1;
    if (n > 64) n = 64;
    return (size_t)n;
}
