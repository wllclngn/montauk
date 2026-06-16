#define _POSIX_C_SOURCE 199309L
// sort.c -- Flow-model sort entry point
//
// Type-generic via macro template instantiation.
// Each inclusion of sort_impl.h generates a full set of typed functions.
#include "internal/sort_internal.h"
#include "internal/pool.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef __AVX2__
#include <immintrin.h>
#endif

// Wall-clock nanoseconds (POSIX) -- used by sublimation_i64_stats.
static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

// AVX2 SIMD PARTITION (int64_t only, vpcompressq emulation)
//
// Vectorized partition for SUB_RANDOM data. Uses _mm256_cmpgt_epi64 + a
// 16-entry shuffle table to compress < pivot elements to the front lanes
// of a YMM register. Each iteration processes 4 int64 elements with no
// serial dependency on the write pointer.
//
// Used by sub_avx2_random_quicksort_i64. Out-of-place via scratch buffer.

#ifdef __AVX2__

// Shuffle table: for each 4-bit mask, gives an int32 permutation that
// moves the "selected" int64 lanes to the front. Each int64 = 2 int32s,
// so the indices are interleaved: lane k = int32 indices [2k, 2k+1].
static const int32_t avx2_compress_shuffle[16][8] = {
    /* 0000 */ {0,1, 2,3, 4,5, 6,7},
    /* 0001 */ {0,1, 2,3, 4,5, 6,7},
    /* 0010 */ {2,3, 0,1, 4,5, 6,7},
    /* 0011 */ {0,1, 2,3, 4,5, 6,7},
    /* 0100 */ {4,5, 0,1, 2,3, 6,7},
    /* 0101 */ {0,1, 4,5, 2,3, 6,7},
    /* 0110 */ {2,3, 4,5, 0,1, 6,7},
    /* 0111 */ {0,1, 2,3, 4,5, 6,7},
    /* 1000 */ {6,7, 0,1, 2,3, 4,5},
    /* 1001 */ {0,1, 6,7, 2,3, 4,5},
    /* 1010 */ {2,3, 6,7, 0,1, 4,5},
    /* 1011 */ {0,1, 2,3, 6,7, 4,5},
    /* 1100 */ {4,5, 6,7, 0,1, 2,3},
    /* 1101 */ {0,1, 4,5, 6,7, 2,3},
    /* 1110 */ {2,3, 4,5, 6,7, 0,1},
    /* 1111 */ {0,1, 2,3, 4,5, 6,7},
};

// SIMD partition: arr[lo..hi-1] in-place around pivot via scratch buffer.
// < pivot grows from scratch[0]; >= pivot grows from scratch[n-1] backwards.
// SIMD loop runs while free space >= 8. Scalar tail handles the rest.
static size_t avx2_partition_i64(int64_t *arr, size_t lo, size_t hi, int64_t pivot,
                                   int64_t *scratch) {
    size_t n = hi - lo;
    if (n < 16) {
        size_t write = lo;
        for (size_t i = lo; i < hi; i++) {
            int64_t val = arr[i];
            if (val < pivot) {
                arr[i] = arr[write];
                arr[write] = val;
                write++;
            }
        }
        return write;
    }

    __m256i pivot_v = _mm256_set1_epi64x(pivot);
    size_t scratch_lo = 0;
    size_t scratch_hi = n;

    size_t i = 0;
    while (i + 4 <= n && (scratch_hi - scratch_lo) >= 8) {
        __m256i v = _mm256_loadu_si256((const __m256i *)(arr + lo + i));
        __m256i lt = _mm256_cmpgt_epi64(pivot_v, v);
        unsigned mask = (unsigned)_mm256_movemask_pd(_mm256_castsi256_pd(lt));
        int popcnt = __builtin_popcount(mask);

        __m256i perm = _mm256_loadu_si256((const __m256i *)avx2_compress_shuffle[mask]);
        __m256i compressed = _mm256_permutevar8x32_epi32(v, perm);

        _mm256_storeu_si256((__m256i *)(scratch + scratch_lo), compressed);
        _mm256_storeu_si256((__m256i *)(scratch + scratch_hi - 4), compressed);

        scratch_lo += (size_t)popcnt;
        scratch_hi -= (size_t)(4 - popcnt);
        i += 4;
    }

    for (; i < n; i++) {
        int64_t val = arr[lo + i];
        if (val < pivot) {
            scratch[scratch_lo++] = val;
        } else {
            scratch[--scratch_hi] = val;
        }
    }

    memcpy(arr + lo, scratch, n * sizeof(int64_t));
    return lo + scratch_lo;
}

// BMI2 PEXT-based in-place partition (Edelkamp-Weiss BlockQuicksort,
// arXiv:1604.06697, with the AVX2+PEXT inner loop ipnsort-style).
//
// The vpcompressq emulation above is fast per-element but writes to a
// scratch buffer (4n bytes of memory traffic per partition level).
// This in-place version uses 4x vpcmpgtq per 16-element block to compute
// a 16-bit "wrong side" mask, then BMI2 PEXT to compress the indices of
// wrong-side elements into a packed 64-bit nibble list. Walks left+right
// blocks, swapping pairs in place. Memory traffic: 2n bytes per level.
//
// PEXT is 1 uop / 3 cycle latency on Intel Skylake (and Zen 3+); microcoded
// on Zen 1/2 only. Our host is Skylake -- check.
//
// Used at the top of avx2_quicksort_with_scratch_i64 for partitions large
// enough that memory traffic dominates the SIMD parallelism of the shuffle
// table. Threshold = SUB_PEXT_THRESHOLD.

// Helper: per 16-element block, compute the packed nibble-indices of
// "wrong side" elements. `looking_for_ge` selects which side is wrong:
//   true  -> we expect < pivot in this block, return indices of >= pivot
//   false -> we expect >= pivot in this block, return indices of <  pivot
// `*count` receives the popcount.
static inline uint64_t pext_wrong_indices_16(const int64_t *block, int64_t pivot,
                                                bool looking_for_ge, int *count) {
    __m256i pv = _mm256_set1_epi64x(pivot);
    __m256i v0 = _mm256_loadu_si256((const __m256i *)(block + 0));
    __m256i v1 = _mm256_loadu_si256((const __m256i *)(block + 4));
    __m256i v2 = _mm256_loadu_si256((const __m256i *)(block + 8));
    __m256i v3 = _mm256_loadu_si256((const __m256i *)(block + 12));

    // cmpgt(pv, v) sets the lane mask where v < pivot.
    __m256i lt0 = _mm256_cmpgt_epi64(pv, v0);
    __m256i lt1 = _mm256_cmpgt_epi64(pv, v1);
    __m256i lt2 = _mm256_cmpgt_epi64(pv, v2);
    __m256i lt3 = _mm256_cmpgt_epi64(pv, v3);

    int m0 = _mm256_movemask_pd(_mm256_castsi256_pd(lt0));
    int m1 = _mm256_movemask_pd(_mm256_castsi256_pd(lt1));
    int m2 = _mm256_movemask_pd(_mm256_castsi256_pd(lt2));
    int m3 = _mm256_movemask_pd(_mm256_castsi256_pd(lt3));

    // 16-bit "v < pivot" mask
    uint32_t lt_mask = (uint32_t)(m0 | (m1 << 4) | (m2 << 8) | (m3 << 12));
    uint32_t wrong   = looking_for_ge ? (lt_mask ^ 0xFFFFu) : lt_mask;

    *count = __builtin_popcount(wrong);

    // Expand each set bit at position i to a full nibble of 0xF at nibble i.
    // pdep places one bit per nibble; the two ORs fill out the rest of each
    // nibble.
    uint64_t nibble = _pdep_u64(wrong, 0x1111111111111111ULL);
    nibble |= nibble << 1;
    nibble |= nibble << 2;

    // PEXT extracts the nibbles of set bit-indices, packing them low-to-high.
    return _pext_u64(0xFEDCBA9876543210ULL, nibble);
}

// In-place block partition. arr[lo..hi) is permuted around `pivot`; returns
// p such that arr[lo..p) < pivot and arr[p..hi) >= pivot.
// Default visibility so the standalone unit test can link against it.
__attribute__((visibility("default")))
size_t block_partition_pext_i64(int64_t *arr, size_t lo, size_t hi, int64_t pivot) {
    const size_t BLOCK = 16;

    // Tiny ranges: scalar Lomuto.
    if (hi - lo < 2 * BLOCK) {
        size_t w = lo;
        for (size_t i = lo; i < hi; i++) {
            if (arr[i] < pivot) {
                int64_t t = arr[w]; arr[w] = arr[i]; arr[i] = t;
                w++;
            }
        }
        return w;
    }

    size_t l = lo;
    size_t r = hi;
    uint64_t l_idx = 0; int l_cnt = 0;
    uint64_t r_idx = 0; int r_cnt = 0;

    while (r - l >= 2 * BLOCK) {
        if (l_cnt == 0) {
            l_idx = pext_wrong_indices_16(arr + l, pivot,
                                           /*looking_for_ge=*/true, &l_cnt);
        }
        if (r_cnt == 0) {
            r_idx = pext_wrong_indices_16(arr + r - BLOCK, pivot,
                                           /*looking_for_ge=*/false, &r_cnt);
        }
        int n_swap = (l_cnt < r_cnt) ? l_cnt : r_cnt;
        for (int k = 0; k < n_swap; k++) {
            size_t li = l + (size_t)(l_idx & 0xF);
            size_t ri = (r - BLOCK) + (size_t)(r_idx & 0xF);
            int64_t t = arr[li]; arr[li] = arr[ri]; arr[ri] = t;
            l_idx >>= 4;
            r_idx >>= 4;
        }
        l_cnt -= n_swap;
        r_cnt -= n_swap;
        if (l_cnt == 0) l += BLOCK;
        if (r_cnt == 0) r -= BLOCK;
    }

    // Cleanup: scalar Lomuto over the residual middle [l, r). The partial
    // blocks (if any uncommitted indices remain in l_idx/r_idx) just contain
    // their unswapped wrong-side elements, which Lomuto correctly skips.
    // Already-swapped elements are now at correct sides and Lomuto handles
    // them too. The multiset is preserved at every step.
    size_t w = l;
    for (size_t i = l; i < r; i++) {
        if (arr[i] < pivot) {
            int64_t t = arr[w]; arr[w] = arr[i]; arr[i] = t;
            w++;
        }
    }
    return w;
}

// AVX2 quicksort with caller-provided scratch buffer (must be >= n elements).
// Used by sub_avx2_random_quicksort_i64 and by sub_random_sort_i64 which
// re-uses its scratch across many small bucket sorts to amortize malloc.
//
// Partition primitive: threshold-switched. Above SUB_PEXT_THRESHOLD elements
// the in-place BMI2 PEXT block partition wins (memory traffic dominates at
// scale). Below it, the AVX2 vpcompressq emulation wins (its 4-element-per-op
// SIMD parallelism dominates inside L1). Threshold set at L1-fit
// (4096 i64 = 32 KB, the i5-7300HQ L1 size).
//
// Base case (len < 32): defers to sub_small_sort_i64 which dispatches to AVX2
// sort networks (sort4_avx2 / sort8_avx2 / sort16_avx2 / sort32_avx2) and
// branchless cswap chains.
#define SUB_PEXT_THRESHOLD 4096

static void avx2_quicksort_with_scratch_i64(int64_t *arr, size_t n,
                                              int64_t *scratch) {
    if (n <= 1) return;

    typedef struct { size_t lo, hi; } range_t;
    range_t stack[64];
    size_t sp = 0;
    size_t lo = 0, hi = n;

    while (1) {
        size_t len = hi - lo;
        if (len < 32) {
            if (len >= 2) {
                uint64_t cmp_dummy = 0, swp_dummy = 0;
                sub_small_sort_i64(arr + lo, len, &cmp_dummy, &swp_dummy);
            }
            if (sp == 0) break;
            range_t r = stack[--sp];
            lo = r.lo; hi = r.hi;
            continue;
        }

        // Median-of-three pivot
        size_t mid = lo + len / 2;
        if (arr[mid] < arr[lo]) { int64_t t = arr[mid]; arr[mid] = arr[lo]; arr[lo] = t; }
        if (arr[hi - 1] < arr[lo]) { int64_t t = arr[hi - 1]; arr[hi - 1] = arr[lo]; arr[lo] = t; }
        if (arr[hi - 1] < arr[mid]) { int64_t t = arr[hi - 1]; arr[hi - 1] = arr[mid]; arr[mid] = t; }
        int64_t pivot = arr[mid];

        { int64_t tmp = arr[mid]; arr[mid] = arr[hi - 1]; arr[hi - 1] = tmp; }

        // Threshold-switch the partition primitive: PEXT in-place above L1
        // fit, vpcompressq emulation below it.
        size_t pivot_pos;
        if ((hi - 1 - lo) > SUB_PEXT_THRESHOLD) {
            pivot_pos = block_partition_pext_i64(arr, lo, hi - 1, pivot);
        } else {
            pivot_pos = avx2_partition_i64(arr, lo, hi - 1, pivot, scratch);
        }
        {
            int64_t pp_tmp = arr[pivot_pos];
            arr[pivot_pos] = arr[hi - 1];
            arr[hi - 1] = pp_tmp;
        }

        // Pdqsort-style fat-pivot duplicate handling.
        //
        // After Lomuto partition: arr[lo..pivot_pos) < pivot,
        //                         arr[pivot_pos] = pivot,
        //                         arr[pivot_pos+1..hi) >= pivot.
        //
        // Quicksort with a 2-way partition degrades on duplicate-heavy data
        // (Zipfian, hash-clustered, etc.) because all duplicates of the pivot
        // pile onto the same side, producing chronically unbalanced
        // recursion. Fix: detect duplicates cheaply, then sweep equals
        // adjacent to the pivot and exclude the entire equivalence class
        // from the right recursion. Same shape as pdqsort's fat-pivot path.
        //
        // Detection: probe the first 4 right-side elements for pivot
        // equality. On unique-value data the probe almost never matches and
        // exits in 1-4 compares. On duplicate-heavy data it fires often.
        size_t right_lo = pivot_pos + 1;
        size_t right_hi = hi;
        if (right_lo < right_hi) {
            size_t check_n = right_hi - right_lo;
            if (check_n > 4) check_n = 4;
            bool may_have_dups = false;
            for (size_t k = 0; k < check_n; k++) {
                if (arr[right_lo + k] == pivot) { may_have_dups = true; break; }
            }
            if (may_have_dups) {
                // Sweep: gather all equal-to-pivot elements adjacent to
                // the pivot. Lomuto-style compaction.
                size_t equal_end = right_lo;
                for (size_t scan = right_lo; scan < right_hi; scan++) {
                    if (arr[scan] == pivot) {
                        int64_t tmp = arr[scan];
                        arr[scan] = arr[equal_end];
                        arr[equal_end] = tmp;
                        equal_end++;
                    }
                }
                right_lo = equal_end;
            }
        }

        // Smaller-half-first: process small side immediately, push large side.
        size_t left_lo = lo, left_hi = pivot_pos;
        size_t left_len = left_hi - left_lo;
        size_t right_len = right_hi - right_lo;

        if (left_len < right_len) {
            if (right_len > 1) {
                if (sp >= 64) return;
                stack[sp++] = (range_t){right_lo, right_hi};
            }
            if (left_len > 1) {
                lo = left_lo; hi = left_hi;
            } else {
                if (sp == 0) break;
                range_t r = stack[--sp];
                lo = r.lo; hi = r.hi;
            }
        } else {
            if (left_len > 1) {
                if (sp >= 64) return;
                stack[sp++] = (range_t){left_lo, left_hi};
            }
            if (right_len > 1) {
                lo = right_lo; hi = right_hi;
            } else {
                if (sp == 0) break;
                range_t r = stack[--sp];
                lo = r.lo; hi = r.hi;
            }
        }
    }
}

// Public wrapper: malloc scratch then call the helper.
void sub_avx2_random_quicksort_i64(int64_t *arr, size_t n) {
    if (n <= 1) return;
    int64_t *scratch = (int64_t *)malloc(n * sizeof(int64_t));
    if (!scratch) return;
    avx2_quicksort_with_scratch_i64(arr, n, scratch);
    free(scratch);
}

// RANDOM-DATA SORT: linear-PCF bucketing + sort-network leaves
//
// Two ideas composed:
//
//   1. Top-level bucketing via a learned linear CDF (Sato-Matsui PCF Learned
//      Sort, TMLR 2024). Sample a few hundred elements, derive min/max from
//      the trimmed sample, map every element to one of B=256 buckets via a
//      single fmul + cvtsd2si. Scatter via 256 software write-combine buffers
//      to minimize TLB pressure during the scatter phase.
//
//   2. Bucket sorts use avx2_quicksort_with_scratch_i64 (sharing one scratch
//      allocation across all buckets). Its base case (len < 32) dispatches
//      to AVX2 sort networks via sub_small_sort_i64 -- the AlphaDev-shaped
//      branchless leaves.
//
// Together this beats a pure AVX2 quicksort by ~24% on uniform random i64
// data and is the production random-sort path. B=256 is the empirically
// confirmed local optimum across n in [100K, 10M] on this CPU; dynamic B
// at n >= 6.1M tracks L2 fit via a static formula (no learning).
//
// References:
//   - Sato, Matsui. "PCF Learned Sort" arXiv:2405.07122 (TMLR May 2024)
//   - Mankowitz et al. "Faster sorting algorithms discovered using deep
//     reinforcement learning." Nature 618, 257-263 (2023).

#define SUB_RANDOM_BUCKETS_MIN  256
#define SUB_RANDOM_BUCKETS_MAX  4096
#define SUB_RANDOM_TARGET_ELEMS 24000  // ~192 KB per bucket: fits 256 KB L2 with margin
#define SUB_RANDOM_WC_BUFSIZE   8      // 8 i64 = one cache line per buffer

// Linear-PCF bucket lookup. Same expression used in both the histogram pass
// and the scatter pass -- if these two ever diverge, buckets will be wrong.
static inline size_t sub_pcf_bucket(int64_t v, int64_t lo_v, double slope, size_t B) {
    double f = (double)(v - lo_v) * slope;
    long b = (long)f;
    if (b < 0) b = 0;
    else if (b >= (long)B) b = (long)B - 1;
    return (size_t)b;
}

void sub_random_sort_i64(int64_t *arr, size_t n) {
    // Below ~4K, sampling overhead dominates -- fall back to baseline.
    if (n < 4096) {
        sub_avx2_random_quicksort_i64(arr, n);
        return;
    }

    // Dynamic B: pick bucket count so each bucket fits L2 with headroom.
    // At n <= ~6.1M the formula clamps to MIN=256 (the empirical local
    // optimum at typical sizes); at n=10M it expands to ~417, eliminating
    // the L2 cliff diagnosed in research/STATE_OF_THE_SORT.md. Static math,
    // no learning -- the moratorium forbids grader-driven knobs.
    size_t B = (n + SUB_RANDOM_TARGET_ELEMS - 1) / SUB_RANDOM_TARGET_ELEMS;
    if (B < SUB_RANDOM_BUCKETS_MIN) B = SUB_RANDOM_BUCKETS_MIN;
    if (B > SUB_RANDOM_BUCKETS_MAX) B = SUB_RANDOM_BUCKETS_MAX;

    // Phase 1: sample S elements at equally-spaced positions
    size_t S = n / 16;
    if (S > 1024) S = 1024;
    if (S < 256) S = 256;

    int64_t *sample = (int64_t *)malloc(S * sizeof(int64_t));
    if (!sample) {
        sub_avx2_random_quicksort_i64(arr, n);
        return;
    }
    size_t sample_step = n / S;
    for (size_t i = 0; i < S; i++) {
        sample[i] = arr[i * sample_step];
    }

    // Phase 2: sort the sample to learn the [min, max] envelope
    sub_avx2_random_quicksort_i64(sample, S);

    // Phase 3: compute the linear PCF parameters from the sample CDF.
    int64_t lo_q = sample[S / 20];          // 5th percentile
    int64_t hi_q = sample[S - S / 20 - 1];  // 95th percentile
    int64_t span = hi_q - lo_q;
    int64_t margin = span / 10;
    if (margin < 1) margin = 1;
    int64_t lo_v = lo_q - margin;
    int64_t hi_v = hi_q + margin;
    if (lo_v > sample[0])      lo_v = sample[0];
    if (hi_v < sample[S - 1])  hi_v = sample[S - 1];

    free(sample);

    if (hi_v <= lo_v) {
        sub_avx2_random_quicksort_i64(arr, n);
        return;
    }
    double slope = (double)B / (double)(hi_v - lo_v + 1);

    // Phase 4: allocate scratch. The bucket index is recomputed inline in
    // the scatter pass (no per-element side array) -- saves n*2 bytes of
    // memory traffic and an n-byte heap allocation.
    int64_t *scratch = (int64_t *)malloc(n * sizeof(int64_t));
    if (!scratch) {
        sub_avx2_random_quicksort_i64(arr, n);
        return;
    }

    // Stack-allocated bucket workspace at MAX size; only first B entries are
    // touched. At B=4096 the wc[][] array is 256 KB on stack -- within Linux's
    // 8 MB default stack budget. Function is non-recursive (top-level only).
    size_t hist[SUB_RANDOM_BUCKETS_MAX];
    size_t offsets[SUB_RANDOM_BUCKETS_MAX];
    size_t wc_pos[SUB_RANDOM_BUCKETS_MAX];
    size_t wc_head[SUB_RANDOM_BUCKETS_MAX];
    _Alignas(64) int64_t wc[SUB_RANDOM_BUCKETS_MAX][SUB_RANDOM_WC_BUFSIZE];

    // Phase 5: histogram pass. Compute bucket index per element, increment
    // hist[b]. The index is NOT stored -- it's recomputed in the scatter pass
    // via sub_pcf_bucket() which is the single source of truth for the math.
    memset(hist, 0, B * sizeof(size_t));
    for (size_t i = 0; i < n; i++) {
        size_t b = sub_pcf_bucket(arr[i], lo_v, slope, B);
        hist[b]++;
    }

    // Phase 6: exclusive prefix sum
    {
        size_t acc = 0;
        for (size_t b = 0; b < B; b++) {
            offsets[b] = acc;
            acc += hist[b];
        }
    }

    // Phase 7: scatter via software write-combine buffers (one cache line
    // per bucket). Bucket index is recomputed inline -- same expression as
    // the histogram pass above.
    memcpy(wc_head, offsets, B * sizeof(size_t));
    memset(wc_pos,  0,       B * sizeof(size_t));

    for (size_t i = 0; i < n; i++) {
        int64_t v = arr[i];
        size_t b = sub_pcf_bucket(v, lo_v, slope, B);
        size_t p = wc_pos[b];
        wc[b][p] = v;
        p++;
        if (p == SUB_RANDOM_WC_BUFSIZE) {
            memcpy(scratch + wc_head[b], wc[b],
                   SUB_RANDOM_WC_BUFSIZE * sizeof(int64_t));
            wc_head[b] += SUB_RANDOM_WC_BUFSIZE;
            wc_pos[b] = 0;
        } else {
            wc_pos[b] = p;
        }
    }

    // Drain any partial buffers.
    for (size_t b = 0; b < B; b++) {
        size_t p = wc_pos[b];
        if (p > 0) {
            memcpy(scratch + wc_head[b], wc[b], p * sizeof(int64_t));
            wc_head[b] += p;
        }
    }

    // Phase 8: copy bucketed scratch back to arr.
    memcpy(arr, scratch, n * sizeof(int64_t));

    // Phase 9: sort each bucket with the AVX2 quicksort, sharing scratch.
    // The sort-network leaves handle the n<32 base case.
    for (size_t b = 0; b < B; b++) {
        size_t bn = hist[b];
        if (bn <= 1) continue;
        avx2_quicksort_with_scratch_i64(arr + offsets[b], bn, scratch);
    }

    free(scratch);
}

#endif // __AVX2__

// TYPE-GENERIC SORT (all types via template)

// int32_t
#define SUB_TYPE int32_t
#define SUB_SUFFIX _i32
#include "sort_impl.h"
#undef SUB_TYPE
#undef SUB_SUFFIX

// int64_t (with parallel + spectral fallback)
#define SUB_TYPE int64_t
#define SUB_SUFFIX _i64
#define SUB_TYPE_IS_I64
#include "sort_impl.h"
#undef SUB_TYPE_IS_I64
#undef SUB_TYPE
#undef SUB_SUFFIX

// uint32_t
#define SUB_TYPE uint32_t
#define SUB_SUFFIX _u32
#include "sort_impl.h"
#undef SUB_TYPE
#undef SUB_SUFFIX

// uint64_t
#define SUB_TYPE uint64_t
#define SUB_SUFFIX _u64
#include "sort_impl.h"
#undef SUB_TYPE
#undef SUB_SUFFIX

// float
#define SUB_TYPE float
#define SUB_SUFFIX _f32
#include "sort_impl.h"
#undef SUB_TYPE
#undef SUB_SUFFIX

// double
#define SUB_TYPE double
#define SUB_SUFFIX _f64
#include "sort_impl.h"
#undef SUB_TYPE
#undef SUB_SUFFIX

// PUBLIC API: parallel sort (i64 only)

void sublimation_i64_parallel(int64_t *restrict arr, size_t n, size_t num_threads) {
    if (n <= 1) return;

    // Multi-threaded entry point. When num_threads >= 2 and n is large enough
    // to amortize thread spin-up, dispatch DIRECTLY to the IPS4o-style parallel
    // pool. Skip the classifier entirely -- the pool handles random data well,
    // and the classifier's 3-4 O(n) passes (count_runs, sample_inversion_ratio,
    // estimate_distinct) cost ~10 ns/elem at large n, which dominates the
    // parallel speedup. Users calling sublimation_i64_parallel on already-
    // sorted data are doing something unusual; they should call sublimation_i64
    // (the serial entry) which has the structured-data fast paths.
    if (num_threads >= 2 && n >= SUB_PARALLEL_THRESHOLD) {
        sub_parallel_sort_i64(arr, n, num_threads, (int)SUB_RANDOM);
        return;
    }

    // num_threads < 2 OR n too small for parallel: serial path with full
    // structured-data fast paths.
    sub_profile_t profile;
    if (fast_path_dispatch_i64(arr, n, &profile)) return;

    sub_adaptive_t state;
    sub_adaptive_init(&state, n);
    sub_sort_internal_i64(arr, n, &state);
}

// PUBLIC API: per-type sort with stats.
// Runs classification, then the full adaptive sort, then populates the
// user-supplied sub_stats_t with comparison counts, the hook-length info-
// theoretic bound, and the resulting comparison_efficiency ratio.
#define DEFINE_PUBLIC_STATS(T, SUFFIX)                                       \
    void sublimation_##SUFFIX##_stats(T *restrict arr, size_t n,            \
                                       sub_stats_t *stats) {                \
        uint64_t t0 = now_ns();                                             \
                                                                             \
        sub_adaptive_t state;                                               \
        sub_adaptive_init(&state, n);                                       \
                                                                             \
        sub_profile_t profile = sub_classify_internal_##SUFFIX(arr, n);     \
        sub_sort_internal_##SUFFIX(arr, n, &state);                         \
                                                                             \
        uint64_t t1 = now_ns();                                             \
                                                                             \
        if (stats) {                                                        \
            stats->comparisons = state.comparisons;                         \
            stats->swaps = state.swaps;                                     \
            stats->levels_built = state.levels_built;                       \
            stats->gap_prunes = state.gap_prunes;                           \
            stats->rescans = state.rescans;                                 \
            stats->spectral_decompositions = state.spectral_attempted ? 1 : 0; \
            stats->spectral_gap = (double)state.last_spectral_gap;          \
            stats->info_theoretic_bound = (double)profile.info_theoretic_bound; \
            stats->comparison_efficiency = 0.0;                             \
            if (stats->comparisons > 0 && stats->info_theoretic_bound > 0.0) { \
                stats->comparison_efficiency =                              \
                    stats->info_theoretic_bound / (double)stats->comparisons; \
            }                                                                \
            stats->disorder = profile.disorder;                             \
            stats->wall_ns = (double)(t1 - t0);                             \
        }                                                                    \
    }

DEFINE_PUBLIC_STATS(int32_t,  i32)
DEFINE_PUBLIC_STATS(int64_t,  i64)
DEFINE_PUBLIC_STATS(uint32_t, u32)
DEFINE_PUBLIC_STATS(uint64_t, u64)
DEFINE_PUBLIC_STATS(float,    f32)
DEFINE_PUBLIC_STATS(double,   f64)

#undef DEFINE_PUBLIC_STATS

// PUBLIC API: generic qsort-compatible

void sublimation(void *base, size_t nmemb, size_t size,
               int (*compar)(const void *, const void *)) {
    qsort(base, nmemb, size, compar);
}

// PUBLIC API: version

int sublimation_api_version(void) {
    return SUBLIMATION_API_VERSION;
}

const char *sublimation_version(void) {
    return SUBLIMATION_VERSION_STRING;
}
