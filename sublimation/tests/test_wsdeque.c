// test_wsdeque.c -- Chase-Lev deque: correctness + concurrent exactly-once.
//
// Single-thread checks first (LIFO take, FIFO steal, grow across a resize),
// then a 1-owner / K-thief stress that pushes ~1M uniquely-tagged frames and
// asserts every frame is consumed EXACTLY once with no torn reads. Built both
// plain and under ThreadSanitizer by run.py; TSan is the real proof.
#define _POSIX_C_SOURCE 200809L
#include "internal/wsdeque.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <sched.h>
#include <unistd.h>

static int failures = 0;
#define CHECK(cond, msg) do { \
    if (!(cond)) { fprintf(stderr, "FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__); failures++; } \
} while (0)

// A frame's tag is redundantly encoded in all three fields so a torn read
// (bytes from two different pushes) is detectable on consume.
static sub_dfs_frame_t make_frame(uint32_t id) {
    return (sub_dfs_frame_t){ .base = (void *)(uintptr_t)id,
                              .n = (size_t)id + 1,
                              .depth = id ^ 0xA5A5A5A5u };
}
static bool frame_ok(sub_dfs_frame_t f, uint32_t *id_out) {
    uint32_t id = (uint32_t)(uintptr_t)f.base;
    *id_out = id;
    return f.n == (size_t)id + 1 && f.depth == (id ^ 0xA5A5A5A5u);
}

static void test_single_thread(void) {
    sub_wsdeque_t q;
    CHECK(sub_wsdeque_init(&q, 4), "init");

    // LIFO: owner push 0,1,2 then take -> 2,1,0
    for (uint32_t i = 0; i < 3; i++) CHECK(sub_wsdeque_push(&q, make_frame(i)), "push");
    for (uint32_t i = 3; i-- > 0;) {
        sub_dfs_frame_t f; uint32_t id;
        CHECK(sub_wsdeque_take(&q, &f), "take");
        CHECK(frame_ok(f, &id) && id == i, "take LIFO order");
    }
    sub_dfs_frame_t f;
    CHECK(!sub_wsdeque_take(&q, &f), "take empty -> false");

    // FIFO steal: push 0,1,2 then steal -> 0,1,2
    for (uint32_t i = 0; i < 3; i++) CHECK(sub_wsdeque_push(&q, make_frame(i)), "push");
    for (uint32_t i = 0; i < 3; i++) {
        sub_dfs_frame_t s; uint32_t id;
        CHECK(sub_wsdeque_steal(&q, &s) == SUB_STEAL_OK, "steal");
        CHECK(frame_ok(s, &id) && id == i, "steal FIFO order");
    }
    CHECK(sub_wsdeque_steal(&q, &f) == SUB_STEAL_EMPTY, "steal empty");

    // Grow: push well past initial cap (4), drain, verify count.
    const uint32_t N = 1000;
    for (uint32_t i = 0; i < N; i++) CHECK(sub_wsdeque_push(&q, make_frame(i)), "push grow");
    uint32_t drained = 0;
    while (sub_wsdeque_take(&q, &f)) drained++;
    CHECK(drained == N, "grow drained all");

    sub_wsdeque_destroy(&q);
}

// Concurrent stress.
#define STRESS_N (1u << 20)
static sub_wsdeque_t g_q;
static _Atomic(uint8_t) g_seen[STRESS_N];
static _Atomic(int) g_pushing_done;
static _Atomic(int) g_all_done;
static _Atomic(uint64_t) g_torn;

static void consume(sub_dfs_frame_t f) {
    uint32_t id;
    if (!frame_ok(f, &id) || id >= STRESS_N) {
        atomic_fetch_add_explicit(&g_torn, 1, memory_order_relaxed);
        return;
    }
    atomic_fetch_add_explicit(&g_seen[id], 1, memory_order_relaxed);
}

static void *thief_main(void *arg) {
    (void)arg;
    for (;;) {
        sub_dfs_frame_t f;
        sub_steal_t r = sub_wsdeque_steal(&g_q, &f);
        if (r == SUB_STEAL_OK) { consume(f); continue; }
        if (r == SUB_STEAL_ABORT) continue;               // lost CAS, retry
        // EMPTY: done only when the owner has finished and nothing remains
        if (atomic_load_explicit(&g_all_done, memory_order_acquire) &&
            sub_wsdeque_size(&g_q) == 0)
            return nullptr;
        sched_yield();
    }
}

static void *owner_main(void *arg) {
    (void)arg;
    for (uint32_t i = 0; i < STRESS_N; i++) {
        while (!sub_wsdeque_push(&g_q, make_frame(i))) sched_yield();  // retry on grow OOM
        // Interleave owner takes so both LIFO-take and steal paths run hot.
        if ((i & 7u) == 0) {
            sub_dfs_frame_t f;
            if (sub_wsdeque_take(&g_q, &f)) consume(f);
        }
    }
    atomic_store_explicit(&g_pushing_done, 1, memory_order_release);
    // Owner drains what thieves have not stolen.
    sub_dfs_frame_t f;
    while (sub_wsdeque_size(&g_q) > 0)
        if (sub_wsdeque_take(&g_q, &f)) consume(f);
    atomic_store_explicit(&g_all_done, 1, memory_order_release);
    return nullptr;
}

static void test_concurrent(void) {
    CHECK(sub_wsdeque_init(&g_q, 64), "stress init");
    for (uint32_t i = 0; i < STRESS_N; i++) atomic_init(&g_seen[i], 0);
    atomic_init(&g_pushing_done, 0);
    atomic_init(&g_all_done, 0);
    atomic_init(&g_torn, 0);

    long cpus = sysconf(_SC_NPROCESSORS_ONLN);
    int nthieves = (int)(cpus > 1 ? cpus - 1 : 1);
    if (nthieves > 16) nthieves = 16;

    pthread_t owner;
    pthread_t thieves[16];
    pthread_create(&owner, nullptr, owner_main, nullptr);
    for (int i = 0; i < nthieves; i++) pthread_create(&thieves[i], nullptr, thief_main, nullptr);
    pthread_join(owner, nullptr);
    for (int i = 0; i < nthieves; i++) pthread_join(thieves[i], nullptr);

    CHECK(atomic_load(&g_torn) == 0, "no torn reads");
    uint64_t consumed = 0, dup = 0, missing = 0;
    for (uint32_t i = 0; i < STRESS_N; i++) {
        uint8_t c = atomic_load(&g_seen[i]);
        if (c == 1) consumed++;
        else if (c == 0) missing++;
        else dup++;
    }
    CHECK(missing == 0, "no frame lost");
    CHECK(dup == 0, "no frame consumed twice");
    CHECK(consumed == STRESS_N, "every frame consumed exactly once");
    if (missing || dup)
        fprintf(stderr, "  consumed=%llu missing=%llu dup=%llu (of %u), thieves=%d\n",
                (unsigned long long)consumed, (unsigned long long)missing,
                (unsigned long long)dup, STRESS_N, nthieves);

    sub_wsdeque_destroy(&g_q);
}

int main(void) {
    test_single_thread();
    test_concurrent();
    if (failures) { fprintf(stderr, "test_wsdeque: %d FAILED\n", failures); return 1; }
    printf("test_wsdeque: OK\n");
    return 0;
}
