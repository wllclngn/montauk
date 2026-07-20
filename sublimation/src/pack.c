// pack.c -- index sort by companion numeric key. Backs sublimation_pack.h.
//
// Pipeline:
//   1. For each (key, index) pair, map key -> monotonic uint32 via
//      sub_key_from_<T>, optionally bit-invert for descending, and pack
//      as (mono_key << 32) | indices[i] into a uint64.
//   2. Sort the packed array with sublimation_u64.
//   3. Unpack: indices[i] = packed[i].low.
//
// The high 32 bits dominate u64 ordering, so the result is sorted by key
// (ascending or descending); the low 32 bits being the original index
// keep the sort stable for equal keys.
#include "sublimation_pack.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern void sublimation_u64(uint64_t *arr, size_t n);

static inline uint64_t sub_pack_key_u32(uint32_t k, uint32_t idx, bool desc) {
    uint32_t mono = desc ? ~k : k;
    return ((uint64_t)mono << 32) | (uint64_t)idx;
}

void sublimation_pack_sort_u32_with_scratch(
    const uint32_t *keys, uint32_t *indices, size_t n, bool desc,
    uint64_t *scratch) {
    for (size_t i = 0; i < n; i++) {
        scratch[i] = sub_pack_key_u32(sub_key_from_u32(keys[i]), indices[i], desc);
    }
    sublimation_u64(scratch, n);
    for (size_t i = 0; i < n; i++) {
        indices[i] = (uint32_t)(scratch[i] & 0xFFFFFFFFu);
    }
}

void sublimation_pack_sort_i32_with_scratch(
    const int32_t *keys, uint32_t *indices, size_t n, bool desc,
    uint64_t *scratch) {
    for (size_t i = 0; i < n; i++) {
        scratch[i] = sub_pack_key_u32(sub_key_from_i32(keys[i]), indices[i], desc);
    }
    sublimation_u64(scratch, n);
    for (size_t i = 0; i < n; i++) {
        indices[i] = (uint32_t)(scratch[i] & 0xFFFFFFFFu);
    }
}

void sublimation_pack_sort_f32_with_scratch(
    const float *keys, uint32_t *indices, size_t n, bool desc,
    uint64_t *scratch) {
    for (size_t i = 0; i < n; i++) {
        scratch[i] = sub_pack_key_u32(sub_key_from_f32(keys[i]), indices[i], desc);
    }
    sublimation_u64(scratch, n);
    for (size_t i = 0; i < n; i++) {
        indices[i] = (uint32_t)(scratch[i] & 0xFFFFFFFFu);
    }
}

void sublimation_pack_sort_u32(
    const uint32_t *keys, uint32_t *indices, size_t n, bool desc) {
    if (n < 2) return;
    uint64_t *scratch = (uint64_t *)malloc(n * sizeof(uint64_t));
    if (!scratch) return;
    sublimation_pack_sort_u32_with_scratch(keys, indices, n, desc, scratch);
    free(scratch);
}

void sublimation_pack_sort_i32(
    const int32_t *keys, uint32_t *indices, size_t n, bool desc) {
    if (n < 2) return;
    uint64_t *scratch = (uint64_t *)malloc(n * sizeof(uint64_t));
    if (!scratch) return;
    sublimation_pack_sort_i32_with_scratch(keys, indices, n, desc, scratch);
    free(scratch);
}

void sublimation_pack_sort_f32(
    const float *keys, uint32_t *indices, size_t n, bool desc) {
    if (n < 2) return;
    uint64_t *scratch = (uint64_t *)malloc(n * sizeof(uint64_t));
    if (!scratch) return;
    sublimation_pack_sort_f32_with_scratch(keys, indices, n, desc, scratch);
    free(scratch);
}

// 64-bit key index sort. A 64-bit key + 32-bit index does not co-pack into one
// uint64, so the pack trick used above does not apply. Instead we carry the
// index as a satellite through a stable LSD radix over the 8 key bytes:
// 8 passes of 1 byte, least-significant first. LSD radix is stable, so equal
// keys keep their input (ascending index) order -- matching the 32-bit entries.
// 8 passes is even, so the sorted result lands back in the first scratch half.
static void sub_radix_pairs64(sublimation_pack64_slot *a,
                              sublimation_pack64_slot *b, size_t n) {
    if (n == 0) return;
    sublimation_pack64_slot *dest = a;
    for (int pass = 0; pass < 8; pass++) {
        size_t count[256] = {0};
        const int shift = pass * 8;
        for (size_t i = 0; i < n; i++)
            count[(a[i].key >> shift) & 0xFFu]++;
        // Constant byte: every key shares this byte (the histogram puts all n
        // in one bucket), so the stable distribution is the identity. Skip
        // the pass; the final-copy check below restores buffer parity.
        if (count[(a[0].key >> shift) & 0xFFu] == n) continue;
        size_t sum = 0;
        for (int d = 0; d < 256; d++) { size_t c = count[d]; count[d] = sum; sum += c; }
        for (size_t i = 0; i < n; i++) {
            uint8_t d = (uint8_t)((a[i].key >> shift) & 0xFFu);
            b[count[d]++] = a[i];
        }
        sublimation_pack64_slot *t = a; a = b; b = t;
    }
    // An odd number of executed passes leaves the sorted data in the other
    // half; the caller reads the half it passed as `a`.
    if (a != dest)
        memcpy(dest, a, n * sizeof(sublimation_pack64_slot));
}

void sublimation_pack_sort_u64_with_scratch(
    const uint64_t *keys, uint32_t *indices, size_t n, bool desc,
    sublimation_pack64_slot *scratch) {
    sublimation_pack64_slot *a = scratch, *b = scratch + n;
    for (size_t i = 0; i < n; i++) {
        uint64_t mono = sub_key_from_u64(keys[i]);
        a[i].key = desc ? ~mono : mono;
        a[i].idx = indices[i];
    }
    sub_radix_pairs64(a, b, n);
    for (size_t i = 0; i < n; i++) indices[i] = a[i].idx;
}

void sublimation_pack_sort_i64_with_scratch(
    const int64_t *keys, uint32_t *indices, size_t n, bool desc,
    sublimation_pack64_slot *scratch) {
    sublimation_pack64_slot *a = scratch, *b = scratch + n;
    for (size_t i = 0; i < n; i++) {
        uint64_t mono = sub_key_from_i64(keys[i]);
        a[i].key = desc ? ~mono : mono;
        a[i].idx = indices[i];
    }
    sub_radix_pairs64(a, b, n);
    for (size_t i = 0; i < n; i++) indices[i] = a[i].idx;
}

void sublimation_pack_sort_f64_with_scratch(
    const double *keys, uint32_t *indices, size_t n, bool desc,
    sublimation_pack64_slot *scratch) {
    sublimation_pack64_slot *a = scratch, *b = scratch + n;
    for (size_t i = 0; i < n; i++) {
        uint64_t mono = sub_key_from_f64(keys[i]);
        a[i].key = desc ? ~mono : mono;
        a[i].idx = indices[i];
    }
    sub_radix_pairs64(a, b, n);
    for (size_t i = 0; i < n; i++) indices[i] = a[i].idx;
}

void sublimation_pack_sort_u64(
    const uint64_t *keys, uint32_t *indices, size_t n, bool desc) {
    if (n < 2) return;
    sublimation_pack64_slot *scratch =
        (sublimation_pack64_slot *)malloc(2 * n * sizeof(sublimation_pack64_slot));
    if (!scratch) return;
    sublimation_pack_sort_u64_with_scratch(keys, indices, n, desc, scratch);
    free(scratch);
}

void sublimation_pack_sort_i64(
    const int64_t *keys, uint32_t *indices, size_t n, bool desc) {
    if (n < 2) return;
    sublimation_pack64_slot *scratch =
        (sublimation_pack64_slot *)malloc(2 * n * sizeof(sublimation_pack64_slot));
    if (!scratch) return;
    sublimation_pack_sort_i64_with_scratch(keys, indices, n, desc, scratch);
    free(scratch);
}

void sublimation_pack_sort_f64(
    const double *keys, uint32_t *indices, size_t n, bool desc) {
    if (n < 2) return;
    sublimation_pack64_slot *scratch =
        (sublimation_pack64_slot *)malloc(2 * n * sizeof(sublimation_pack64_slot));
    if (!scratch) return;
    sublimation_pack_sort_f64_with_scratch(keys, indices, n, desc, scratch);
    free(scratch);
}
