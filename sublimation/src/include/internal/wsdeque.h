// wsdeque.h -- Chase-Lev work-stealing deque (C23, lock-free)
//
// One deque per worker. The owner pushes and takes from the BOTTOM (LIFO,
// depth-first -- the frame it just produced stays hot in its own cache);
// idle thieves steal from the TOP (FIFO, breadth-first -- the oldest frame,
// which is the largest, most-divisible chunk of remaining work). The stealable
// unit is a sub_dfs_frame_t: one subarray awaiting sort.
//
// Memory ordering follows Le et al., "Correct and Efficient Work-Stealing for
// Weak Memory Models" (PPoPP 2013), and the sublimation flow-sort spec
// (kyng-dinics-suite RESEARCH.md 6.4): push = relaxed slot store + release
// fence; steal = acquire loads + a seq_cst CAS on contention only; take =
// relaxed + a seq_cst CAS only when the deque holds 0-1 elements. On x86 the
// acquire/release traffic is free; only the contended CAS emits a LOCK prefix.
#ifndef SUB_WSDEQUE_H
#define SUB_WSDEQUE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>

// The stealable unit: a subarray to sort. Public POD, passed by value.
typedef struct {
    void    *base;   // first element of the subarray
    size_t   n;      // element count
    uint32_t depth;  // recursion depth (depth-parallel threshold / coarsening)
} sub_dfs_frame_t;

// One ring slot, stored field-atomic. The Chase-Lev fences order slot
// visibility against top/bottom; the per-field relaxed atomics only keep the
// model race-free (a successful steal CAS proves the slot was not reused, so
// the three field reads are coherent -- no torn frame).
typedef struct {
    _Atomic(void *)   base;
    _Atomic(size_t)   n;
    _Atomic(uint32_t) depth;
} sub_wsslot_t;

// Growable ring buffer. Retired (never freed mid-run) on grow so a slow thief
// still holding the old pointer never reads freed memory; all are freed at
// destroy.
typedef struct sub_wsarray {
    int64_t       cap;    // power of two
    int64_t       mask;   // cap - 1
    sub_wsslot_t  buf[];  // flexible array member
} sub_wsarray_t;

// Fields are internal. The struct is cache-line aligned so an array of them
// (one per worker) never false-shares top/bottom across workers.
typedef struct sub_wsdeque {
    alignas(64) _Atomic(int64_t) top;   // steal end (front); monotonic
    _Atomic(int64_t)          bottom;   // owner end (back); monotonic
    _Atomic(sub_wsarray_t *)  array;    // current ring
    sub_wsarray_t           **retired;  // old rings, freed at destroy
    size_t                    retired_len;
    size_t                    retired_cap;
} sub_wsdeque_t;

typedef enum {
    SUB_STEAL_OK,      // *out filled
    SUB_STEAL_EMPTY,   // deque was empty
    SUB_STEAL_ABORT    // lost the CAS to another thief/owner; caller retries
} sub_steal_t;

// Lifecycle: owner-only, single-threaded. init returns false on OOM.
bool sub_wsdeque_init(sub_wsdeque_t *q, size_t initial_cap);
void sub_wsdeque_destroy(sub_wsdeque_t *q);

// Owner-only. Grows on demand; returns false only if a grow allocation fails
// (the deque stays usable with its current capacity).
bool sub_wsdeque_push(sub_wsdeque_t *q, sub_dfs_frame_t f);

// Owner-only. Pops the most-recently-pushed frame (LIFO). Returns true and
// fills *out; false when empty or the last element was lost to a thief.
bool sub_wsdeque_take(sub_wsdeque_t *q, sub_dfs_frame_t *out);

// Any thief. Steals the oldest frame (FIFO). SUB_STEAL_ABORT means retry.
sub_steal_t sub_wsdeque_steal(sub_wsdeque_t *q, sub_dfs_frame_t *out);

// Approximate live count (relaxed; may be stale under concurrency).
size_t sub_wsdeque_size(sub_wsdeque_t *q);

#endif // SUB_WSDEQUE_H
