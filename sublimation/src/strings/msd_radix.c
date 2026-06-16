// msd_radix.c -- iterative MSD radix tiebreak for string-sort tail
//
// Algorithm (per-frame):
//   1. Counting pass: count[c+2]++ for byte c at depth d (c = -1 means
//      string exhausted at this depth; treated as a sentinel that sorts
//      before all real bytes).
//   2. Prefix-sum to convert counts to cumulative bucket-end positions.
//   3. Stable distribution into a parallel scratch array using count[c+1]
//      as the next-slot position (post-incremented). After this pass,
//      count[r] holds the start of bucket r relative to lo, and
//      count[r+1] - count[r] is bucket r's size.
//   4. Copy scratch back to arr[lo..hi).
//   5. For each non-empty bucket of byte value r in {0..255}, push a new
//      frame (lo + count[r], lo + count[r+1], depth + 1) onto the work
//      stack. Bucket -1 (sentinel) is skipped: exhausted strings have no
//      more bytes to compare.
//
// Cutoff: when frame range size < SUB_STRINGS_MSD_CUTOVER, fall back to
// insertion sort using byte comparison from the current depth.
//
// Stack: heap-allocated, geometric growth. Cannot blow the C stack on
// adversarial inputs (e.g. 1024 strings sharing a 4 KB prefix).
#include "strings/strings_internal.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    size_t lo;
    size_t hi;
    size_t depth;
} sub_msd_frame_t;

static int sub_less_byte(const char *s, size_t s_len,
                          const char *t, size_t t_len, size_t d) {
    size_t common = s_len < t_len ? s_len : t_len;
    for (size_t i = d; i < common; i++) {
        unsigned char a = (unsigned char)s[i];
        unsigned char b = (unsigned char)t[i];
        if (a != b) return a < b;
    }
    return s_len < t_len;
}

static void sub_insertion_sort(const char **arr, size_t *lens,
                                uint32_t *indices,
                                size_t lo, size_t hi, size_t depth) {
    for (size_t i = lo + 1; i < hi; i++) {
        for (size_t j = i; j > lo &&
             sub_less_byte(arr[j], lens[j], arr[j - 1], lens[j - 1], depth); j--) {
            const char *tmp_p = arr[j];     arr[j]   = arr[j - 1]; arr[j - 1]   = tmp_p;
            size_t      tmp_l = lens[j];    lens[j]  = lens[j - 1]; lens[j - 1] = tmp_l;
            if (indices) {
                uint32_t tmp_i = indices[j]; indices[j] = indices[j - 1]; indices[j - 1] = tmp_i;
            }
        }
    }
}

void sub_msd_radix(
    const char **arr,
    size_t *lens,
    uint32_t *indices,
    const char **scratch,
    size_t lo,
    size_t hi,
    size_t depth)
{
    if (hi - lo < 2) return;

    size_t *lens_scratch = (size_t *)malloc((hi - lo) * sizeof(size_t));
    if (!lens_scratch) {
        sub_insertion_sort(arr, lens, indices, lo, hi, depth);
        return;
    }

    uint32_t *idx_scratch = NULL;
    if (indices) {
        idx_scratch = (uint32_t *)malloc((hi - lo) * sizeof(uint32_t));
        if (!idx_scratch) {
            free(lens_scratch);
            sub_insertion_sort(arr, lens, indices, lo, hi, depth);
            return;
        }
    }

    size_t stack_cap = 64;
    sub_msd_frame_t *stack = (sub_msd_frame_t *)malloc(stack_cap * sizeof(sub_msd_frame_t));
    if (!stack) {
        free(lens_scratch);
        free(idx_scratch);
        sub_insertion_sort(arr, lens, indices, lo, hi, depth);
        return;
    }
    size_t sp = 0;
    stack[sp++] = (sub_msd_frame_t){lo, hi, depth};

    while (sp > 0) {
        sub_msd_frame_t f = stack[--sp];

        if (f.hi - f.lo < SUB_STRINGS_MSD_CUTOVER) {
            sub_insertion_sort(arr, lens, indices, f.lo, f.hi, f.depth);
            continue;
        }

        size_t count[258];
        memset(count, 0, sizeof(count));

        for (size_t i = f.lo; i < f.hi; i++) {
            int c = (f.depth < lens[i]) ? (int)(unsigned char)arr[i][f.depth] : -1;
            count[(size_t)(c + 2)]++;
        }
        for (size_t r = 0; r < 257; r++) {
            count[r + 1] += count[r];
        }

        // Distribute into scratch (slots 0..hi-lo)
        for (size_t i = f.lo; i < f.hi; i++) {
            int c = (f.depth < lens[i]) ? (int)(unsigned char)arr[i][f.depth] : -1;
            size_t idx = count[(size_t)(c + 1)]++;
            scratch[idx] = arr[i];
            lens_scratch[idx] = lens[i];
            if (indices) idx_scratch[idx] = indices[i];
        }

        // Copy back into arr/lens/indices
        for (size_t i = f.lo; i < f.hi; i++) {
            arr[i] = scratch[i - f.lo];
            lens[i] = lens_scratch[i - f.lo];
            if (indices) indices[i] = idx_scratch[i - f.lo];
        }

        // Push frames for each non-empty byte-value bucket r in 0..255.
        // Bucket r occupies arr[f.lo + count[r], f.lo + count[r+1]).
        // Bucket -1 (sentinel) is at arr[f.lo, f.lo + count[0]) and skipped.
        for (int r = 0; r < 256; r++) {
            size_t bs = f.lo + count[(size_t)r];
            size_t be = f.lo + count[(size_t)(r + 1)];
            if (be - bs >= 2) {
                if (sp >= stack_cap) {
                    stack_cap *= 2;
                    sub_msd_frame_t *new_stack = (sub_msd_frame_t *)realloc(
                        stack, stack_cap * sizeof(sub_msd_frame_t));
                    if (!new_stack) {
                        free(stack);
                        free(lens_scratch);
                        free(idx_scratch);
                        sub_insertion_sort(arr, lens, indices, bs, be, f.depth + 1);
                        return;
                    }
                    stack = new_stack;
                }
                stack[sp++] = (sub_msd_frame_t){bs, be, f.depth + 1};
            }
        }
    }

    free(stack);
    free(lens_scratch);
    free(idx_scratch);
}
