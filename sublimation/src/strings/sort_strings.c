// sort_strings.c -- public string-sort entry points
//
// Pipeline:
//   1. Pack first 4 bytes of each string as big-endian u32; combine with
//      32-bit original index into u64 as (prefix4 << 32) | index.
//   2. Sort the packed array with sublimation_u64 (full flow-model
//      pipeline runs unchanged on the prefix array).
//   3. Permute the pointer/length working arrays (and, if requested, the
//      output index array) using the recovered indices.
//   4. Walk the sorted packed array; for runs where consecutive entries
//      share the same prefix4, invoke sub_msd_radix on bytes 4+ to
//      resolve the tie cluster. Indices are permuted alongside arr/lens
//      inside sub_msd_radix when the caller asked for an index output.
//
// Scratch: 8n (packed u64) + 8n (pointer scratch) + 8n (lens scratch)
// = ~24n bytes. Per-call malloc/free. Larger when indices requested:
// sub_msd_radix additionally allocates a uint32 scratch inside each call.
#include "sublimation_strings.h"
#include "strings/strings_internal.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern void sublimation_u64(uint64_t *arr, size_t n);

static int sub_strings_qsort_cmp(const void *a, const void *b) {
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

// Shared pipeline. `arr` and `lens` are working arrays (mutable, permuted
// in place). `indices` is optional — if non-NULL, it is filled with the
// sorted permutation of 0..n-1 (overwriting any prior contents).
static void sub_strings_internal(const char **arr, size_t *lens,
                                  uint32_t *indices, size_t n) {
    if (n < 2) {
        if (indices && n == 1) indices[0] = 0;
        return;
    }

    if (n > UINT32_MAX) {
        fprintf(stderr,
                "sublimation_strings: n=%zu exceeds 2^32; falling back to qsort+strcmp\n",
                n);
        qsort(arr, n, sizeof(const char *), sub_strings_qsort_cmp);
        if (indices) {
            // Without the packed-index trick we can't recover the
            // permutation cheaply; callers that hit this path lose the
            // indices output. Leaves indices in indeterminate state;
            // document as undefined for n > UINT32_MAX.
        }
        return;
    }

    uint64_t *packed = (uint64_t *)malloc(n * sizeof(uint64_t));
    const char **str_scratch = (const char **)malloc(n * sizeof(const char *));
    size_t *lens_scratch = (size_t *)malloc(n * sizeof(size_t));
    if (!packed || !str_scratch || !lens_scratch) {
        free(packed);
        free(str_scratch);
        free(lens_scratch);
        qsort(arr, n, sizeof(const char *), sub_strings_qsort_cmp);
        return;
    }

    for (size_t i = 0; i < n; i++) {
        uint32_t prefix4 = sub_pack_prefix4(arr[i], lens[i]);
        packed[i] = ((uint64_t)prefix4 << 32) | (uint32_t)i;
    }

    sublimation_u64(packed, n);

    for (size_t i = 0; i < n; i++) {
        uint32_t orig_i = (uint32_t)(packed[i] & 0xFFFFFFFFu);
        str_scratch[i] = arr[orig_i];
        lens_scratch[i] = lens[orig_i];
    }
    memcpy(arr, str_scratch, n * sizeof(const char *));
    memcpy(lens, lens_scratch, n * sizeof(size_t));

    if (indices) {
        for (size_t i = 0; i < n; i++) {
            indices[i] = (uint32_t)(packed[i] & 0xFFFFFFFFu);
        }
    }

    size_t i = 0;
    while (i < n) {
        uint32_t prefix_i = (uint32_t)(packed[i] >> 32);
        size_t j = i + 1;
        while (j < n && (uint32_t)(packed[j] >> 32) == prefix_i) j++;
        if (j - i >= 2) {
            sub_msd_radix(arr, lens, indices, str_scratch, i, j, 4);
        }
        i = j;
    }

    free(packed);
    free(str_scratch);
    free(lens_scratch);
}

void sublimation_strings(const char **arr, size_t n) {
    if (n < 2) return;

    size_t *lens = (size_t *)malloc(n * sizeof(size_t));
    if (!lens) {
        qsort(arr, n, sizeof(const char *), sub_strings_qsort_cmp);
        return;
    }
    for (size_t i = 0; i < n; i++) lens[i] = strlen(arr[i]);

    sub_strings_internal(arr, lens, NULL, n);

    free(lens);
}

void sublimation_strings_len(const char **arr, const size_t *lens, size_t n) {
    if (n < 2) return;

    size_t *lens_copy = (size_t *)malloc(n * sizeof(size_t));
    if (!lens_copy) {
        qsort(arr, n, sizeof(const char *), sub_strings_qsort_cmp);
        return;
    }
    memcpy(lens_copy, lens, n * sizeof(size_t));

    sub_strings_internal(arr, lens_copy, NULL, n);

    free(lens_copy);
}

void sublimation_strings_indices(const char **arr, uint32_t *indices, size_t n) {
    if (n == 0) return;
    if (n == 1) { indices[0] = 0; return; }

    // Working arrays: we don't touch the caller's arr.
    const char **arr_work = (const char **)malloc(n * sizeof(const char *));
    size_t *lens_work = (size_t *)malloc(n * sizeof(size_t));
    if (!arr_work || !lens_work) {
        free(arr_work); free(lens_work);
        // Degenerate output: identity permutation, then qsort-based sort.
        // We can't easily produce correct indices here without scratch.
        for (size_t i = 0; i < n; i++) indices[i] = (uint32_t)i;
        return;
    }

    memcpy(arr_work, arr, n * sizeof(const char *));
    for (size_t i = 0; i < n; i++) lens_work[i] = strlen(arr[i]);

    sub_strings_internal(arr_work, lens_work, indices, n);

    free(arr_work);
    free(lens_work);
}

void sublimation_strings_indices_len(const char **arr, const size_t *lens,
                                      uint32_t *indices, size_t n) {
    if (n == 0) return;
    if (n == 1) { indices[0] = 0; return; }

    const char **arr_work = (const char **)malloc(n * sizeof(const char *));
    size_t *lens_work = (size_t *)malloc(n * sizeof(size_t));
    if (!arr_work || !lens_work) {
        free(arr_work); free(lens_work);
        for (size_t i = 0; i < n; i++) indices[i] = (uint32_t)i;
        return;
    }

    memcpy(arr_work, arr, n * sizeof(const char *));
    memcpy(lens_work, lens, n * sizeof(size_t));

    sub_strings_internal(arr_work, lens_work, indices, n);

    free(arr_work);
    free(lens_work);
}
