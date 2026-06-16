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
//      single wave of thread creation.
//
// Classification and scatter are O(n/p), removing the Amdahl bottleneck.
// Thread creation is minimized: 3 barrier phases, num_workers threads each.
#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE
#include "internal/pool.h"
#include "internal/sort_internal.h"
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Forward: sequential sort for each worker's region
extern void sub_sort_internal_i64(int64_t *restrict arr, size_t n,
                                  sub_adaptive_t *state);

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

// Worker context for classify + scatter phases
typedef struct {
    const int64_t *arr;
    size_t         chunk_lo;
    size_t         chunk_hi;       // exclusive
    const int64_t *splitters;
    size_t         num_splitters;
    size_t         num_buckets;
    size_t        *my_counts;      // [num_buckets], worker-local
    uint16_t      *my_buckets;     // cached bucket assignments for this chunk
    int64_t       *scratch;
    size_t        *my_offsets;     // [num_buckets], per-worker write positions
    int            phase;          // 0 = classify, 1 = scatter
} sub_distrib_ctx_t;

static void *worker_distrib_fn(void *arg) {
    sub_distrib_ctx_t *ctx = (sub_distrib_ctx_t *)arg;

    if (ctx->phase == 0) {
        // CLASSIFY: count + cache bucket assignments
        const int64_t *arr = ctx->arr;
        const int64_t *splitters = ctx->splitters;
        size_t ns = ctx->num_splitters;
        size_t *counts = ctx->my_counts;
        uint16_t *buckets = ctx->my_buckets;

        memset(counts, 0, ctx->num_buckets * sizeof(size_t));

        size_t len = ctx->chunk_hi - ctx->chunk_lo;
        for (size_t i = 0; i < len; i++) {
            size_t b = find_bucket(arr[ctx->chunk_lo + i], splitters, ns);
            buckets[i] = (uint16_t)b;
            counts[b]++;
        }
    } else {
        // SCATTER: use cached assignments (no re-classification)
        const int64_t *arr = ctx->arr;
        int64_t *scratch = ctx->scratch;
        size_t *offsets = ctx->my_offsets;
        const uint16_t *buckets = ctx->my_buckets;

        size_t len = ctx->chunk_hi - ctx->chunk_lo;
        for (size_t i = 0; i < len; i++) {
            size_t b = buckets[i];
            scratch[offsets[b]++] = arr[ctx->chunk_lo + i];
        }
    }

    return nullptr;
}

// Worker context for multi-bucket sort phase
typedef struct {
    int64_t       *arr;
    size_t        *bucket_offsets;  // array of start offsets for this worker's buckets
    size_t        *bucket_counts;   // array of sizes for this worker's buckets
    size_t         num_assigned;    // how many buckets assigned to this worker
    int            disorder;
} sub_multi_sort_ctx_t;

static void *worker_multi_sort_fn(void *arg) {
    sub_multi_sort_ctx_t *ctx = (sub_multi_sort_ctx_t *)arg;

    for (size_t i = 0; i < ctx->num_assigned; i++) {
        size_t bn = ctx->bucket_counts[i];
        if (bn <= 1) continue;

        sub_adaptive_t state;
        sub_adaptive_init(&state, bn);
        sub_sort_internal_i64(ctx->arr + ctx->bucket_offsets[i], bn, &state);
    }

    return nullptr;
}

// PARALLEL SORT ENTRY POINT
void sub_parallel_sort_i64(int64_t *arr, size_t n, size_t num_workers,
                           int disorder) {
    if (n <= 1) return;
    if (num_workers < 2) num_workers = 2;
    if (num_workers > 64) num_workers = 64;

    // Overpartition: more buckets than workers for load balance.
    // Each worker handles multiple buckets in the sort phase via
    // greedy assignment (largest-first to least-loaded worker).
    // This is a single wave of thread creation -- no per-wave overhead.
    size_t k = num_workers * 4;
    if (k > n / 128) k = n / 128;   // at least 128 elements per bucket
    if (k < num_workers) k = num_workers;
    if (k < 2) k = 2;
    if (k > 256) k = 256;           // cap for uint16_t and sanity

    size_t num_splitters = k - 1;

    // ===== ALLOCATE =====
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
    pthread_t *threads = malloc(num_workers * sizeof(pthread_t));
    sub_distrib_ctx_t *distrib_ctxs = malloc(num_workers * sizeof(sub_distrib_ctx_t));
    uint16_t *all_buckets = malloc(buckets_bytes);

    if (!splitters || !scratch || !counts_matrix || !offsets_matrix ||
        !global_offsets || !global_counts || !threads || !distrib_ctxs ||
        !all_buckets) {
        free(splitters); free(scratch); free(counts_matrix);
        free(offsets_matrix); free(global_offsets); free(global_counts);
        free(threads); free(distrib_ctxs); free(all_buckets);
        sub_adaptive_t state;
        sub_adaptive_init(&state, n);
        sub_sort_internal_i64(arr, n, &state);
        return;
    }

    // ===== PHASE 1: SAMPLE SPLITTERS =====
    sample_splitters(arr, n, splitters, k);

    // ===== PHASE 2: PARALLEL CLASSIFICATION =====
    size_t chunk_size = (n + num_workers - 1) / num_workers;

    for (size_t w = 0; w < num_workers; w++) {
        size_t lo = w * chunk_size;
        size_t hi = lo + chunk_size;
        if (hi > n) hi = n;

        distrib_ctxs[w].arr = arr;
        distrib_ctxs[w].chunk_lo = lo;
        distrib_ctxs[w].chunk_hi = hi;
        distrib_ctxs[w].splitters = splitters;
        distrib_ctxs[w].num_splitters = num_splitters;
        distrib_ctxs[w].num_buckets = k;
        distrib_ctxs[w].my_counts = &counts_matrix[w * k];
        distrib_ctxs[w].my_buckets = &all_buckets[lo];
        distrib_ctxs[w].scratch = scratch;
        distrib_ctxs[w].my_offsets = &offsets_matrix[w * k];
        distrib_ctxs[w].phase = 0;

        if (pthread_create(&threads[w], nullptr, worker_distrib_fn, &distrib_ctxs[w]) != 0) {
            worker_distrib_fn(&distrib_ctxs[w]);
            threads[w] = (pthread_t){0};
        }
    }

    for (size_t w = 0; w < num_workers; w++) {
        if (threads[w]) pthread_join(threads[w], nullptr);
    }

    // ===== PHASE 3: PREFIX-SUM MERGE (sequential, O(k * num_workers)) =====
    for (size_t b = 0; b < k; b++) {
        size_t total = 0;
        for (size_t w = 0; w < num_workers; w++) {
            total += counts_matrix[w * k + b];
        }
        global_counts[b] = total;
    }

    global_offsets[0] = 0;
    for (size_t b = 1; b < k; b++) {
        global_offsets[b] = global_offsets[b - 1] + global_counts[b - 1];
    }

    for (size_t b = 0; b < k; b++) {
        size_t running = global_offsets[b];
        for (size_t w = 0; w < num_workers; w++) {
            offsets_matrix[w * k + b] = running;
            running += counts_matrix[w * k + b];
        }
    }

    // ===== PHASE 4: PARALLEL SCATTER =====
    for (size_t w = 0; w < num_workers; w++) {
        distrib_ctxs[w].phase = 1;
        if (pthread_create(&threads[w], nullptr, worker_distrib_fn, &distrib_ctxs[w]) != 0) {
            worker_distrib_fn(&distrib_ctxs[w]);
            threads[w] = (pthread_t){0};
        }
    }

    for (size_t w = 0; w < num_workers; w++) {
        if (threads[w]) pthread_join(threads[w], nullptr);
    }

    memcpy(arr, scratch, n * sizeof(int64_t));

    // ===== PHASE 5: PARALLEL PER-BUCKET SORT =====
    // Greedy load-balanced assignment: sort buckets by size descending,
    // assign each bucket to the least-loaded worker.
    // Single wave of num_workers threads.

    // Sort bucket indices by size (descending) using insertion sort
    size_t *bucket_order = malloc(k * sizeof(size_t));
    // Per-worker assignment lists
    size_t *assign_offsets = malloc(k * sizeof(size_t));  // bucket offsets per worker
    size_t *assign_counts = malloc(k * sizeof(size_t));   // bucket counts per worker
    size_t *worker_nassigned = calloc(num_workers, sizeof(size_t));
    size_t *worker_load = calloc(num_workers, sizeof(size_t));
    // Temporary: worker -> list of bucket indices
    size_t *worker_buckets = malloc(k * sizeof(size_t));
    sub_multi_sort_ctx_t *sort_ctxs = malloc(num_workers * sizeof(sub_multi_sort_ctx_t));

    if (!bucket_order || !assign_offsets || !assign_counts || !worker_nassigned ||
        !worker_load || !worker_buckets || !sort_ctxs) {
        // Fallback: sequential
        for (size_t b = 0; b < k; b++) {
            if (global_counts[b] <= 1) continue;
            sub_adaptive_t state;
            sub_adaptive_init(&state, global_counts[b]);
            sub_sort_internal_i64(arr + global_offsets[b], global_counts[b], &state);
        }
        goto cleanup;
    }

    // Initialize bucket order
    for (size_t i = 0; i < k; i++) bucket_order[i] = i;

    // Insertion sort by descending count
    for (size_t i = 1; i < k; i++) {
        size_t key = bucket_order[i];
        size_t j = i;
        while (j > 0 && global_counts[bucket_order[j-1]] < global_counts[key]) {
            bucket_order[j] = bucket_order[j-1];
            j--;
        }
        bucket_order[j] = key;
    }

    // Greedy assignment: for each bucket (largest first), assign to
    // the worker with the smallest current load.
    // First pass: count assignments per worker
    {
        size_t temp_load[64];
        memset(temp_load, 0, num_workers * sizeof(size_t));
        size_t temp_nassigned[64];
        memset(temp_nassigned, 0, num_workers * sizeof(size_t));

        for (size_t i = 0; i < k; i++) {
            size_t b = bucket_order[i];
            if (global_counts[b] <= 1) continue;

            // find least loaded worker
            size_t best_w = 0;
            for (size_t w = 1; w < num_workers; w++) {
                if (temp_load[w] < temp_load[best_w]) best_w = w;
            }
            temp_load[best_w] += global_counts[b];
            temp_nassigned[best_w]++;
        }

        memcpy(worker_nassigned, temp_nassigned, num_workers * sizeof(size_t));
    }

    // Compute per-worker bucket list start offsets in worker_buckets
    {
        size_t offset = 0;
        for (size_t w = 0; w < num_workers; w++) {
            worker_load[w] = offset; // reuse as start index
            offset += worker_nassigned[w];
            worker_nassigned[w] = 0; // reset for second pass
        }
    }

    // Second pass: actually assign bucket indices
    {
        size_t temp_load[64];
        memset(temp_load, 0, num_workers * sizeof(size_t));

        for (size_t i = 0; i < k; i++) {
            size_t b = bucket_order[i];
            if (global_counts[b] <= 1) continue;

            size_t best_w = 0;
            for (size_t w = 1; w < num_workers; w++) {
                if (temp_load[w] < temp_load[best_w]) best_w = w;
            }
            temp_load[best_w] += global_counts[b];

            size_t slot = worker_load[best_w] + worker_nassigned[best_w];
            worker_buckets[slot] = b;
            worker_nassigned[best_w]++;
        }
    }

    // Build per-worker offset/count arrays and launch
    {
        size_t launched = 0;
        size_t running_idx = 0;

        for (size_t w = 0; w < num_workers; w++) {
            size_t na = worker_nassigned[w];
            if (na == 0) continue;

            size_t start = worker_load[w];

            // Fill assign_offsets and assign_counts for this worker
            for (size_t j = 0; j < na; j++) {
                size_t b = worker_buckets[start + j];
                assign_offsets[running_idx + j] = global_offsets[b];
                assign_counts[running_idx + j] = global_counts[b];
            }

            sort_ctxs[launched].arr = arr;
            sort_ctxs[launched].bucket_offsets = &assign_offsets[running_idx];
            sort_ctxs[launched].bucket_counts = &assign_counts[running_idx];
            sort_ctxs[launched].num_assigned = na;
            sort_ctxs[launched].disorder = disorder;

            if (pthread_create(&threads[launched], nullptr, worker_multi_sort_fn,
                               &sort_ctxs[launched]) != 0) {
                worker_multi_sort_fn(&sort_ctxs[launched]);
                threads[launched] = (pthread_t){0};
            }
            launched++;
            running_idx += na;
        }

        for (size_t i = 0; i < launched; i++) {
            if (threads[i]) pthread_join(threads[i], nullptr);
        }
    }

cleanup:
    free(bucket_order);
    free(assign_offsets);
    free(assign_counts);
    free(worker_nassigned);
    free(worker_load);
    free(worker_buckets);
    free(sort_ctxs);
    free(splitters);
    free(scratch);
    free(counts_matrix);
    free(offsets_matrix);
    free(global_offsets);
    free(global_counts);
    free(threads);
    free(distrib_ctxs);
    free(all_buckets);
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
