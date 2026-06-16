// test_pack.c -- correctness fixtures for sublimation_pack_sort_*
//
// Verifier: sort a mirrored (key, index) pair array with qsort as the
// reference oracle, then compare against the indices produced by
// sublimation_pack_sort_*.
#include "../src/include/sublimation_pack.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static int _pass = 0;
static int _fail = 0;

static uint64_t lcg_state;
static void lcg_seed(uint64_t s) { lcg_state = s; }
static uint64_t lcg_next(void) {
    lcg_state = lcg_state * 6364136223846793005ull + 1442695040888963407ull;
    return lcg_state;
}

// u32 reference
typedef struct { uint32_t key; uint32_t index; } u32_pair_t;
static int u32_pair_asc(const void *a, const void *b) {
    const u32_pair_t *pa = (const u32_pair_t *)a;
    const u32_pair_t *pb = (const u32_pair_t *)b;
    if (pa->key < pb->key) return -1;
    if (pa->key > pb->key) return 1;
    return (pa->index > pb->index) - (pa->index < pb->index);
}
static int u32_pair_desc(const void *a, const void *b) {
    const u32_pair_t *pa = (const u32_pair_t *)a;
    const u32_pair_t *pb = (const u32_pair_t *)b;
    if (pa->key > pb->key) return -1;
    if (pa->key < pb->key) return 1;
    return (pa->index > pb->index) - (pa->index < pb->index);
}

// i32 reference
typedef struct { int32_t key; uint32_t index; } i32_pair_t;
static int i32_pair_asc(const void *a, const void *b) {
    const i32_pair_t *pa = (const i32_pair_t *)a;
    const i32_pair_t *pb = (const i32_pair_t *)b;
    if (pa->key < pb->key) return -1;
    if (pa->key > pb->key) return 1;
    return (pa->index > pb->index) - (pa->index < pb->index);
}
static int i32_pair_desc(const void *a, const void *b) {
    const i32_pair_t *pa = (const i32_pair_t *)a;
    const i32_pair_t *pb = (const i32_pair_t *)b;
    if (pa->key > pb->key) return -1;
    if (pa->key < pb->key) return 1;
    return (pa->index > pb->index) - (pa->index < pb->index);
}

// f32 reference
typedef struct { float key; uint32_t index; } f32_pair_t;
static int f32_pair_asc(const void *a, const void *b) {
    const f32_pair_t *pa = (const f32_pair_t *)a;
    const f32_pair_t *pb = (const f32_pair_t *)b;
    if (pa->key < pb->key) return -1;
    if (pa->key > pb->key) return 1;
    return (pa->index > pb->index) - (pa->index < pb->index);
}
static int f32_pair_desc(const void *a, const void *b) {
    const f32_pair_t *pa = (const f32_pair_t *)a;
    const f32_pair_t *pb = (const f32_pair_t *)b;
    if (pa->key > pb->key) return -1;
    if (pa->key < pb->key) return 1;
    return (pa->index > pb->index) - (pa->index < pb->index);
}

// u64 reference
typedef struct { uint64_t key; uint32_t index; } u64_pair_t;
static int u64_pair_asc(const void *a, const void *b) {
    const u64_pair_t *pa = (const u64_pair_t *)a, *pb = (const u64_pair_t *)b;
    if (pa->key < pb->key) return -1;
    if (pa->key > pb->key) return 1;
    return (pa->index > pb->index) - (pa->index < pb->index);
}
static int u64_pair_desc(const void *a, const void *b) {
    const u64_pair_t *pa = (const u64_pair_t *)a, *pb = (const u64_pair_t *)b;
    if (pa->key > pb->key) return -1;
    if (pa->key < pb->key) return 1;
    return (pa->index > pb->index) - (pa->index < pb->index);
}

// i64 reference
typedef struct { int64_t key; uint32_t index; } i64_pair_t;
static int i64_pair_asc(const void *a, const void *b) {
    const i64_pair_t *pa = (const i64_pair_t *)a, *pb = (const i64_pair_t *)b;
    if (pa->key < pb->key) return -1;
    if (pa->key > pb->key) return 1;
    return (pa->index > pb->index) - (pa->index < pb->index);
}
static int i64_pair_desc(const void *a, const void *b) {
    const i64_pair_t *pa = (const i64_pair_t *)a, *pb = (const i64_pair_t *)b;
    if (pa->key > pb->key) return -1;
    if (pa->key < pb->key) return 1;
    return (pa->index > pb->index) - (pa->index < pb->index);
}

// f64 reference
typedef struct { double key; uint32_t index; } f64_pair_t;
static int f64_pair_asc(const void *a, const void *b) {
    const f64_pair_t *pa = (const f64_pair_t *)a, *pb = (const f64_pair_t *)b;
    if (pa->key < pb->key) return -1;
    if (pa->key > pb->key) return 1;
    return (pa->index > pb->index) - (pa->index < pb->index);
}
static int f64_pair_desc(const void *a, const void *b) {
    const f64_pair_t *pa = (const f64_pair_t *)a, *pb = (const f64_pair_t *)b;
    if (pa->key > pb->key) return -1;
    if (pa->key < pb->key) return 1;
    return (pa->index > pb->index) - (pa->index < pb->index);
}

static void test_u32(size_t n, bool desc, const char *name) {
    uint32_t *keys = (uint32_t *)malloc(n * sizeof(uint32_t));
    uint32_t *indices = (uint32_t *)malloc(n * sizeof(uint32_t));
    u32_pair_t *ref = (u32_pair_t *)malloc(n * sizeof(u32_pair_t));
    for (size_t i = 0; i < n; i++) {
        keys[i] = (uint32_t)lcg_next();
        indices[i] = (uint32_t)i;
        ref[i].key = keys[i];
        ref[i].index = (uint32_t)i;
    }
    qsort(ref, n, sizeof(u32_pair_t), desc ? u32_pair_desc : u32_pair_asc);
    sublimation_pack_sort_u32(keys, indices, n, desc);

    int ok = 1;
    for (size_t i = 0; i < n; i++) {
        if (indices[i] != ref[i].index) {
            fprintf(stderr, "  [FAIL] %s: position %zu: got idx %u key %u; expected idx %u key %u\n",
                    name, i, indices[i], keys[indices[i]], ref[i].index, ref[i].key);
            ok = 0;
            break;
        }
    }
    if (ok) { printf("  %-50s PASS\n", name); _pass++; } else { _fail++; }
    free(keys); free(indices); free(ref);
}

static void test_i32(size_t n, bool desc, const char *name) {
    int32_t *keys = (int32_t *)malloc(n * sizeof(int32_t));
    uint32_t *indices = (uint32_t *)malloc(n * sizeof(uint32_t));
    i32_pair_t *ref = (i32_pair_t *)malloc(n * sizeof(i32_pair_t));
    for (size_t i = 0; i < n; i++) {
        keys[i] = (int32_t)lcg_next();
        indices[i] = (uint32_t)i;
        ref[i].key = keys[i];
        ref[i].index = (uint32_t)i;
    }
    qsort(ref, n, sizeof(i32_pair_t), desc ? i32_pair_desc : i32_pair_asc);
    sublimation_pack_sort_i32(keys, indices, n, desc);

    int ok = 1;
    for (size_t i = 0; i < n; i++) {
        if (indices[i] != ref[i].index) {
            fprintf(stderr, "  [FAIL] %s: position %zu: got idx %u; expected idx %u\n",
                    name, i, indices[i], ref[i].index);
            ok = 0;
            break;
        }
    }
    if (ok) { printf("  %-50s PASS\n", name); _pass++; } else { _fail++; }
    free(keys); free(indices); free(ref);
}

static void test_f32(size_t n, bool desc, const char *name) {
    float *keys = (float *)malloc(n * sizeof(float));
    uint32_t *indices = (uint32_t *)malloc(n * sizeof(uint32_t));
    f32_pair_t *ref = (f32_pair_t *)malloc(n * sizeof(f32_pair_t));
    for (size_t i = 0; i < n; i++) {
        uint64_t r = lcg_next();
        // Mix positive and negative floats; avoid NaN.
        int32_t ri = (int32_t)(r & 0xFFFFFFFFu);
        keys[i] = (float)ri / 1000000.0f;
        indices[i] = (uint32_t)i;
        ref[i].key = keys[i];
        ref[i].index = (uint32_t)i;
    }
    qsort(ref, n, sizeof(f32_pair_t), desc ? f32_pair_desc : f32_pair_asc);
    sublimation_pack_sort_f32(keys, indices, n, desc);

    int ok = 1;
    for (size_t i = 0; i < n; i++) {
        if (indices[i] != ref[i].index) {
            fprintf(stderr, "  [FAIL] %s: position %zu: got idx %u key %f; expected idx %u key %f\n",
                    name, i, indices[i], (double)keys[indices[i]], ref[i].index, (double)ref[i].key);
            ok = 0;
            break;
        }
    }
    if (ok) { printf("  %-50s PASS\n", name); _pass++; } else { _fail++; }
    free(keys); free(indices); free(ref);
}

// Full 64-bit keys -- values well above 2^32 to prove the radix path keeps
// the high bits the old (key<<32)|index pack could not hold.
static void test_u64(size_t n, bool desc, const char *name) {
    uint64_t *keys = (uint64_t *)malloc(n * sizeof(uint64_t));
    uint32_t *indices = (uint32_t *)malloc(n * sizeof(uint32_t));
    u64_pair_t *ref = (u64_pair_t *)malloc(n * sizeof(u64_pair_t));
    for (size_t i = 0; i < n; i++) {
        keys[i] = lcg_next();  // full 64-bit spread
        indices[i] = (uint32_t)i;
        ref[i].key = keys[i];
        ref[i].index = (uint32_t)i;
    }
    qsort(ref, n, sizeof(u64_pair_t), desc ? u64_pair_desc : u64_pair_asc);
    sublimation_pack_sort_u64(keys, indices, n, desc);
    int ok = 1;
    for (size_t i = 0; i < n; i++) {
        if (indices[i] != ref[i].index) {
            fprintf(stderr, "  [FAIL] %s: position %zu: got idx %u key %llu; expected idx %u key %llu\n",
                    name, i, indices[i], (unsigned long long)keys[indices[i]],
                    ref[i].index, (unsigned long long)ref[i].key);
            ok = 0; break;
        }
    }
    if (ok) { printf("  %-50s PASS\n", name); _pass++; } else { _fail++; }
    free(keys); free(indices); free(ref);
}

static void test_i64(size_t n, bool desc, const char *name) {
    int64_t *keys = (int64_t *)malloc(n * sizeof(int64_t));
    uint32_t *indices = (uint32_t *)malloc(n * sizeof(uint32_t));
    i64_pair_t *ref = (i64_pair_t *)malloc(n * sizeof(i64_pair_t));
    for (size_t i = 0; i < n; i++) {
        keys[i] = (int64_t)lcg_next();  // spans negative and positive
        indices[i] = (uint32_t)i;
        ref[i].key = keys[i];
        ref[i].index = (uint32_t)i;
    }
    qsort(ref, n, sizeof(i64_pair_t), desc ? i64_pair_desc : i64_pair_asc);
    sublimation_pack_sort_i64(keys, indices, n, desc);
    int ok = 1;
    for (size_t i = 0; i < n; i++) {
        if (indices[i] != ref[i].index) {
            fprintf(stderr, "  [FAIL] %s: position %zu: got idx %u; expected idx %u\n",
                    name, i, indices[i], ref[i].index);
            ok = 0; break;
        }
    }
    if (ok) { printf("  %-50s PASS\n", name); _pass++; } else { _fail++; }
    free(keys); free(indices); free(ref);
}

static void test_f64(size_t n, bool desc, const char *name) {
    double *keys = (double *)malloc(n * sizeof(double));
    uint32_t *indices = (uint32_t *)malloc(n * sizeof(uint32_t));
    f64_pair_t *ref = (f64_pair_t *)malloc(n * sizeof(f64_pair_t));
    for (size_t i = 0; i < n; i++) {
        int64_t r = (int64_t)lcg_next();
        keys[i] = (double)r / 1000000.0;  // mixed sign, avoid NaN
        indices[i] = (uint32_t)i;
        ref[i].key = keys[i];
        ref[i].index = (uint32_t)i;
    }
    qsort(ref, n, sizeof(f64_pair_t), desc ? f64_pair_desc : f64_pair_asc);
    sublimation_pack_sort_f64(keys, indices, n, desc);
    int ok = 1;
    for (size_t i = 0; i < n; i++) {
        if (indices[i] != ref[i].index) {
            fprintf(stderr, "  [FAIL] %s: position %zu: got idx %u key %f; expected idx %u key %f\n",
                    name, i, indices[i], keys[indices[i]], ref[i].index, ref[i].key);
            ok = 0; break;
        }
    }
    if (ok) { printf("  %-50s PASS\n", name); _pass++; } else { _fail++; }
    free(keys); free(indices); free(ref);
}

int main(void) {
    lcg_seed(0xC0DEFEEDull);
    test_u32(100, false, "u32_asc_100");
    test_u32(100, true,  "u32_desc_100");
    test_u32(10000, false, "u32_asc_10k");
    test_u32(10000, true,  "u32_desc_10k");

    lcg_seed(0xC0DEFEEDull);
    test_i32(100, false, "i32_asc_100");
    test_i32(100, true,  "i32_desc_100");
    test_i32(10000, false, "i32_asc_10k");
    test_i32(10000, true,  "i32_desc_10k");

    lcg_seed(0xC0DEFEEDull);
    test_f32(100, false, "f32_asc_100");
    test_f32(100, true,  "f32_desc_100");
    test_f32(10000, false, "f32_asc_10k");
    test_f32(10000, true,  "f32_desc_10k");

    lcg_seed(0xC0DEFEEDull);
    test_u64(100, false, "u64_asc_100");
    test_u64(100, true,  "u64_desc_100");
    test_u64(10000, false, "u64_asc_10k");
    test_u64(10000, true,  "u64_desc_10k");

    lcg_seed(0xC0DEFEEDull);
    test_i64(100, false, "i64_asc_100");
    test_i64(100, true,  "i64_desc_100");
    test_i64(10000, false, "i64_asc_10k");
    test_i64(10000, true,  "i64_desc_10k");

    lcg_seed(0xC0DEFEEDull);
    test_f64(100, false, "f64_asc_100");
    test_f64(100, true,  "f64_desc_100");
    test_f64(10000, false, "f64_asc_10k");
    test_f64(10000, true,  "f64_desc_10k");

    // 64-bit keys that differ only ABOVE bit 32: the old (key<<32)|index pack
    // would collapse these to equal; the radix path must keep them distinct.
    {
        uint64_t k[] = {3ull << 40, 1ull << 40, 2ull << 40, 1ull << 40};
        uint32_t idx[4];
        for (int i = 0; i < 4; i++) idx[i] = (uint32_t)i;
        sublimation_pack_sort_u64(k, idx, 4, false);
        uint32_t expected[] = {1, 3, 2, 0};  // two 1<<40 keys stable (1 before 3)
        int ok = 1;
        for (int i = 0; i < 4; i++) if (idx[i] != expected[i]) { ok = 0; break; }
        if (ok) { printf("  %-50s PASS\n", "u64_highbits_stable"); _pass++; }
        else    { printf("  [FAIL] u64_highbits_stable\n"); _fail++; }
    }

    // Edge cases
    {
        uint32_t k[] = {5, 3, 8, 1, 5, 2, 8, 5};
        uint32_t idx[8];
        for (int i = 0; i < 8; i++) idx[i] = (uint32_t)i;
        sublimation_pack_sort_u32(k, idx, 8, false);
        uint32_t expected[] = {3, 5, 1, 0, 4, 7, 2, 6};  // stable on equal keys
        int ok = 1;
        for (int i = 0; i < 8; i++) {
            if (idx[i] != expected[i]) { ok = 0; break; }
        }
        if (ok) { printf("  %-50s PASS\n", "u32_stable_equal_keys"); _pass++; }
        else    { printf("  [FAIL] u32_stable_equal_keys\n"); _fail++; }
    }
    {
        uint32_t k[1] = {42};
        uint32_t idx[1] = {0};
        sublimation_pack_sort_u32(k, idx, 1, false);
        if (idx[0] == 0) { printf("  %-50s PASS\n", "u32_n1"); _pass++; }
        else             { printf("  [FAIL] u32_n1\n"); _fail++; }
    }
    {
        sublimation_pack_sort_u32(NULL, NULL, 0, false);
        printf("  %-50s PASS\n", "u32_n0_noop"); _pass++;
    }

    printf("\n  %d passed, %d failed\n", _pass, _fail);
    return _fail > 0 ? 1 : 0;
}
