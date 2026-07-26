// wsdeque.c -- Chase-Lev work-stealing deque (see wsdeque.h)
#define _POSIX_C_SOURCE 200809L
#include "internal/wsdeque.h"
#include <stdlib.h>

static sub_wsarray_t *array_new(int64_t cap) {
    sub_wsarray_t *a = malloc(sizeof(*a) + (size_t)cap * sizeof(sub_wsslot_t));
    if (!a) return nullptr;
    a->cap = cap;
    a->mask = cap - 1;
    return a;
}

// Slot payload transfer. Relaxed atomics only: ordering comes from the
// push release fence and the steal/take acquire loads of top/bottom.
static inline void slot_store(sub_wsslot_t *s, sub_dfs_frame_t f) {
    atomic_store_explicit(&s->base, f.base, memory_order_relaxed);
    atomic_store_explicit(&s->n, f.n, memory_order_relaxed);
    atomic_store_explicit(&s->depth, f.depth, memory_order_relaxed);
}
static inline sub_dfs_frame_t slot_load(sub_wsslot_t *s) {
    sub_dfs_frame_t f;
    f.base = atomic_load_explicit(&s->base, memory_order_relaxed);
    f.n = atomic_load_explicit(&s->n, memory_order_relaxed);
    f.depth = atomic_load_explicit(&s->depth, memory_order_relaxed);
    return f;
}

// Retire an old ring for deferred free. A concurrent thief may still hold the
// pointer, so it is never freed until destroy.
static bool retire(sub_wsdeque_t *q, sub_wsarray_t *old) {
    if (q->retired_len == q->retired_cap) {
        size_t nc = q->retired_cap ? q->retired_cap * 2 : 8;
        sub_wsarray_t **nr = realloc(q->retired, nc * sizeof(*nr));
        if (!nr) return false;
        q->retired = nr;
        q->retired_cap = nc;
    }
    q->retired[q->retired_len++] = old;
    return true;
}

bool sub_wsdeque_init(sub_wsdeque_t *q, size_t initial_cap) {
    int64_t cap = 64;
    while ((size_t)cap < initial_cap) cap <<= 1;
    sub_wsarray_t *a = array_new(cap);
    if (!a) return false;
    atomic_init(&q->top, 0);
    atomic_init(&q->bottom, 0);
    atomic_init(&q->array, a);
    q->retired = nullptr;
    q->retired_len = 0;
    q->retired_cap = 0;
    return true;
}

void sub_wsdeque_destroy(sub_wsdeque_t *q) {
    free(atomic_load_explicit(&q->array, memory_order_relaxed));
    for (size_t i = 0; i < q->retired_len; i++) free(q->retired[i]);
    free(q->retired);
    q->retired = nullptr;
    q->retired_len = q->retired_cap = 0;
}

bool sub_wsdeque_push(sub_wsdeque_t *q, sub_dfs_frame_t f) {
    int64_t b = atomic_load_explicit(&q->bottom, memory_order_relaxed);
    int64_t t = atomic_load_explicit(&q->top, memory_order_acquire);
    sub_wsarray_t *a = atomic_load_explicit(&q->array, memory_order_relaxed);

    if (b - t > a->cap - 1) {                    // full: grow and republish
        sub_wsarray_t *na = array_new(a->cap * 2);
        if (!na) return false;                   // stay at current capacity
        for (int64_t i = t; i < b; i++)
            slot_store(&na->buf[i & na->mask], slot_load(&a->buf[i & a->mask]));
        if (!retire(q, a)) { free(na); return false; }
        atomic_store_explicit(&q->array, na, memory_order_release);
        a = na;
    }

    slot_store(&a->buf[b & a->mask], f);          // slot write, then...
    // ...publish with a RELEASE store of bottom. This orders both the slot
    // fields and everything the owner did before this push (e.g. the parent
    // partition writes) before any thief's acquire-load of bottom -- the
    // happens-before that keeps disjoint stolen frames race-free. A release
    // store (not a standalone release fence) is what ThreadSanitizer models.
    atomic_store_explicit(&q->bottom, b + 1, memory_order_release);
    return true;
}

bool sub_wsdeque_take(sub_wsdeque_t *q, sub_dfs_frame_t *out) {
    int64_t b = atomic_load_explicit(&q->bottom, memory_order_relaxed) - 1;
    sub_wsarray_t *a = atomic_load_explicit(&q->array, memory_order_relaxed);
    atomic_store_explicit(&q->bottom, b, memory_order_relaxed);
    atomic_thread_fence(memory_order_seq_cst);
    int64_t t = atomic_load_explicit(&q->top, memory_order_relaxed);

    bool ok = false;
    if (t <= b) {
        *out = slot_load(&a->buf[b & a->mask]);
        ok = true;
        if (t == b) {
            // last element: a thief may be taking it right now
            if (!atomic_compare_exchange_strong_explicit(
                    &q->top, &t, t + 1,
                    memory_order_seq_cst, memory_order_relaxed))
                ok = false;                       // lost the race
            atomic_store_explicit(&q->bottom, b + 1, memory_order_relaxed);
        }
    } else {
        atomic_store_explicit(&q->bottom, b + 1, memory_order_relaxed);  // empty
    }
    return ok;
}

sub_steal_t sub_wsdeque_steal(sub_wsdeque_t *q, sub_dfs_frame_t *out) {
    int64_t t = atomic_load_explicit(&q->top, memory_order_acquire);
    atomic_thread_fence(memory_order_seq_cst);
    int64_t b = atomic_load_explicit(&q->bottom, memory_order_acquire);
    if (t < b) {
        sub_wsarray_t *a = atomic_load_explicit(&q->array, memory_order_acquire);
        *out = slot_load(&a->buf[t & a->mask]);   // speculative read
        if (!atomic_compare_exchange_strong_explicit(
                &q->top, &t, t + 1,
                memory_order_seq_cst, memory_order_relaxed))
            return SUB_STEAL_ABORT;               // another thief won; retry
        return SUB_STEAL_OK;
    }
    return SUB_STEAL_EMPTY;
}

size_t sub_wsdeque_size(sub_wsdeque_t *q) {
    int64_t b = atomic_load_explicit(&q->bottom, memory_order_relaxed);
    int64_t t = atomic_load_explicit(&q->top, memory_order_relaxed);
    return b > t ? (size_t)(b - t) : 0;
}
