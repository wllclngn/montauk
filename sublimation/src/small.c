// small.c -- Base case sort for small arrays (n <= SUB_SMALL_THRESHOLD)
//
// Type-generic via macro template instantiation.
// AVX2 vectorized paths are i64-only.
#include "internal/sort_internal.h"

#ifdef __AVX2__
#include <immintrin.h>
#endif

// ============================================================================
// AVX2 VECTORIZED SORTING NETWORKS (int64_t only)
// ============================================================================

#ifdef __AVX2__

#define AVX2_CMP_GT(a, b) _mm256_cmpgt_epi64((a), (b))
#define AVX2_MIN(a, b, cmp) _mm256_blendv_epi8((a), (b), (cmp))
#define AVX2_MAX(a, b, cmp) _mm256_blendv_epi8((b), (a), (cmp))

SUB_INLINE void avx2_minmax(__m256i *lo, __m256i *hi) {
    __m256i cmp = AVX2_CMP_GT(*lo, *hi);
    __m256i mn = AVX2_MIN(*lo, *hi, cmp);
    __m256i mx = AVX2_MAX(*lo, *hi, cmp);
    *lo = mn;
    *hi = mx;
}

SUB_INLINE __m256i avx2_reverse(__m256i v) {
    return _mm256_permute4x64_epi64(v, _MM_SHUFFLE(0, 1, 2, 3));
}

SUB_INLINE __m256i avx2_swap_pairs(__m256i v) {
    return _mm256_permute4x64_epi64(v, _MM_SHUFFLE(2, 3, 0, 1));
}

SUB_INLINE __m256i avx2_swap_inner(__m256i v) {
    return _mm256_permute4x64_epi64(v, _MM_SHUFFLE(3, 1, 2, 0));
}

SUB_INLINE void sort4_avx2(int64_t *arr) {
    __m256i v = _mm256_loadu_si256((__m256i *)arr);

    __m256i s1 = avx2_swap_pairs(v);
    __m256i cmp1 = AVX2_CMP_GT(v, s1);
    __m256i mn1 = AVX2_MIN(v, s1, cmp1);
    __m256i mx1 = AVX2_MAX(v, s1, cmp1);
    v = _mm256_blend_epi32(mn1, mx1, 0xCC);

    __m256i s2 = _mm256_permute4x64_epi64(v, _MM_SHUFFLE(1, 0, 3, 2));
    __m256i cmp2 = AVX2_CMP_GT(v, s2);
    __m256i mn2 = AVX2_MIN(v, s2, cmp2);
    __m256i mx2 = AVX2_MAX(v, s2, cmp2);
    v = _mm256_blend_epi32(mn2, mx2, 0xF0);

    __m256i s3 = avx2_swap_inner(v);
    __m256i cmp3 = AVX2_CMP_GT(v, s3);
    __m256i mn3 = AVX2_MIN(v, s3, cmp3);
    __m256i mx3 = AVX2_MAX(v, s3, cmp3);
    v = _mm256_blend_epi32(mn3, mx3, 0xF0);

    _mm256_storeu_si256((__m256i *)arr, v);
}

SUB_INLINE void sort8_avx2(int64_t *arr) {
    __m256i a = _mm256_loadu_si256((__m256i *)(arr));
    __m256i b = _mm256_loadu_si256((__m256i *)(arr + 4));

    // Sort each register of 4
    {
        __m256i s = avx2_swap_pairs(a);
        __m256i c = AVX2_CMP_GT(a, s);
        __m256i mn = AVX2_MIN(a, s, c);
        __m256i mx = AVX2_MAX(a, s, c);
        a = _mm256_blend_epi32(mn, mx, 0xCC);

        s = _mm256_permute4x64_epi64(a, _MM_SHUFFLE(1, 0, 3, 2));
        c = AVX2_CMP_GT(a, s);
        mn = AVX2_MIN(a, s, c);
        mx = AVX2_MAX(a, s, c);
        a = _mm256_blend_epi32(mn, mx, 0xF0);

        s = avx2_swap_inner(a);
        c = AVX2_CMP_GT(a, s);
        mn = AVX2_MIN(a, s, c);
        mx = AVX2_MAX(a, s, c);
        a = _mm256_blend_epi32(mn, mx, 0xF0);
    }

    {
        __m256i s = avx2_swap_pairs(b);
        __m256i c = AVX2_CMP_GT(b, s);
        __m256i mn = AVX2_MIN(b, s, c);
        __m256i mx = AVX2_MAX(b, s, c);
        b = _mm256_blend_epi32(mn, mx, 0xCC);

        s = _mm256_permute4x64_epi64(b, _MM_SHUFFLE(1, 0, 3, 2));
        c = AVX2_CMP_GT(b, s);
        mn = AVX2_MIN(b, s, c);
        mx = AVX2_MAX(b, s, c);
        b = _mm256_blend_epi32(mn, mx, 0xF0);

        s = avx2_swap_inner(b);
        c = AVX2_CMP_GT(b, s);
        mn = AVX2_MIN(b, s, c);
        mx = AVX2_MAX(b, s, c);
        b = _mm256_blend_epi32(mn, mx, 0xF0);
    }

    // Bitonic merge
    b = avx2_reverse(b);
    avx2_minmax(&a, &b);

    {
        __m256i sa = _mm256_permute4x64_epi64(a, _MM_SHUFFLE(1, 0, 3, 2));
        __m256i ca = AVX2_CMP_GT(a, sa);
        __m256i mna = AVX2_MIN(a, sa, ca);
        __m256i mxa = AVX2_MAX(a, sa, ca);
        a = _mm256_blend_epi32(mna, mxa, 0xF0);

        __m256i sb = _mm256_permute4x64_epi64(b, _MM_SHUFFLE(1, 0, 3, 2));
        __m256i cb = AVX2_CMP_GT(b, sb);
        __m256i mnb = AVX2_MIN(b, sb, cb);
        __m256i mxb = AVX2_MAX(b, sb, cb);
        b = _mm256_blend_epi32(mnb, mxb, 0xF0);
    }

    {
        __m256i sa = avx2_swap_pairs(a);
        __m256i ca = AVX2_CMP_GT(a, sa);
        __m256i mna = AVX2_MIN(a, sa, ca);
        __m256i mxa = AVX2_MAX(a, sa, ca);
        a = _mm256_blend_epi32(mna, mxa, 0xCC);

        __m256i sb = avx2_swap_pairs(b);
        __m256i cb = AVX2_CMP_GT(b, sb);
        __m256i mnb = AVX2_MIN(b, sb, cb);
        __m256i mxb = AVX2_MAX(b, sb, cb);
        b = _mm256_blend_epi32(mnb, mxb, 0xCC);
    }

    _mm256_storeu_si256((__m256i *)(arr), a);
    _mm256_storeu_si256((__m256i *)(arr + 4), b);
}

static void sort16_avx2(int64_t *arr) {
    sort8_avx2(arr);
    sort8_avx2(arr + 8);

    __m256i a = _mm256_loadu_si256((__m256i *)(arr));
    __m256i b = _mm256_loadu_si256((__m256i *)(arr + 4));
    __m256i c = _mm256_loadu_si256((__m256i *)(arr + 8));
    __m256i d = _mm256_loadu_si256((__m256i *)(arr + 12));

    __m256i tmp = avx2_reverse(d);
    d = avx2_reverse(c);
    c = tmp;

    avx2_minmax(&a, &c);
    avx2_minmax(&b, &d);
    avx2_minmax(&a, &b);
    avx2_minmax(&c, &d);

    {
        __m256i sa, ca, mn, mx;
        #define BITONIC_STAGE3(r) do { \
            sa = _mm256_permute4x64_epi64(r, _MM_SHUFFLE(1, 0, 3, 2)); \
            ca = AVX2_CMP_GT(r, sa); \
            mn = AVX2_MIN(r, sa, ca); \
            mx = AVX2_MAX(r, sa, ca); \
            r = _mm256_blend_epi32(mn, mx, 0xF0); \
        } while (0)
        BITONIC_STAGE3(a);
        BITONIC_STAGE3(b);
        BITONIC_STAGE3(c);
        BITONIC_STAGE3(d);
        #undef BITONIC_STAGE3
    }

    {
        __m256i sa, ca, mn, mx;
        #define BITONIC_STAGE4(r) do { \
            sa = avx2_swap_pairs(r); \
            ca = AVX2_CMP_GT(r, sa); \
            mn = AVX2_MIN(r, sa, ca); \
            mx = AVX2_MAX(r, sa, ca); \
            r = _mm256_blend_epi32(mn, mx, 0xCC); \
        } while (0)
        BITONIC_STAGE4(a);
        BITONIC_STAGE4(b);
        BITONIC_STAGE4(c);
        BITONIC_STAGE4(d);
        #undef BITONIC_STAGE4
    }

    _mm256_storeu_si256((__m256i *)(arr), a);
    _mm256_storeu_si256((__m256i *)(arr + 4), b);
    _mm256_storeu_si256((__m256i *)(arr + 8), c);
    _mm256_storeu_si256((__m256i *)(arr + 12), d);
}

// AVX2 sort32: sort two halves of 16, then bitonic merge via 8 YMM registers.
// All 8 registers fit in the 16 YMM the architecture provides.
static void sort32_avx2(int64_t *arr) {
    sort16_avx2(arr);
    sort16_avx2(arr + 16);

    __m256i a = _mm256_loadu_si256((__m256i *)(arr));
    __m256i b = _mm256_loadu_si256((__m256i *)(arr + 4));
    __m256i c = _mm256_loadu_si256((__m256i *)(arr + 8));
    __m256i d = _mm256_loadu_si256((__m256i *)(arr + 12));
    __m256i e = _mm256_loadu_si256((__m256i *)(arr + 16));
    __m256i f = _mm256_loadu_si256((__m256i *)(arr + 20));
    __m256i g = _mm256_loadu_si256((__m256i *)(arr + 24));
    __m256i h = _mm256_loadu_si256((__m256i *)(arr + 28));

    // Reverse second half (e..h) to form bitonic sequence
    __m256i tmp;
    tmp = avx2_reverse(h); h = avx2_reverse(e); e = tmp;
    tmp = avx2_reverse(g); g = avx2_reverse(f); f = tmp;

    // Bitonic merge 32: 5 stages of compare-swap pairs
    // Stage 1: distance 16 (a↔e, b↔f, c↔g, d↔h)
    avx2_minmax(&a, &e);
    avx2_minmax(&b, &f);
    avx2_minmax(&c, &g);
    avx2_minmax(&d, &h);

    // Stage 2: distance 8 (a↔c, b↔d, e↔g, f↔h)
    avx2_minmax(&a, &c);
    avx2_minmax(&b, &d);
    avx2_minmax(&e, &g);
    avx2_minmax(&f, &h);

    // Stage 3: distance 4 (a↔b, c↔d, e↔f, g↔h)
    avx2_minmax(&a, &b);
    avx2_minmax(&c, &d);
    avx2_minmax(&e, &f);
    avx2_minmax(&g, &h);

    // Stage 4: distance 2 within each register (lanes 0,1 vs 2,3)
    {
        __m256i sa, ca, mn, mx;
        #define BITONIC_LANE2(r) do { \
            sa = _mm256_permute4x64_epi64(r, _MM_SHUFFLE(1, 0, 3, 2)); \
            ca = AVX2_CMP_GT(r, sa); \
            mn = AVX2_MIN(r, sa, ca); \
            mx = AVX2_MAX(r, sa, ca); \
            r = _mm256_blend_epi32(mn, mx, 0xF0); \
        } while (0)
        BITONIC_LANE2(a); BITONIC_LANE2(b); BITONIC_LANE2(c); BITONIC_LANE2(d);
        BITONIC_LANE2(e); BITONIC_LANE2(f); BITONIC_LANE2(g); BITONIC_LANE2(h);
        #undef BITONIC_LANE2
    }

    // Stage 5: distance 1 within each register (adjacent pairs)
    {
        __m256i sa, ca, mn, mx;
        #define BITONIC_LANE1(r) do { \
            sa = avx2_swap_pairs(r); \
            ca = AVX2_CMP_GT(r, sa); \
            mn = AVX2_MIN(r, sa, ca); \
            mx = AVX2_MAX(r, sa, ca); \
            r = _mm256_blend_epi32(mn, mx, 0xCC); \
        } while (0)
        BITONIC_LANE1(a); BITONIC_LANE1(b); BITONIC_LANE1(c); BITONIC_LANE1(d);
        BITONIC_LANE1(e); BITONIC_LANE1(f); BITONIC_LANE1(g); BITONIC_LANE1(h);
        #undef BITONIC_LANE1
    }

    _mm256_storeu_si256((__m256i *)(arr),      a);
    _mm256_storeu_si256((__m256i *)(arr + 4),  b);
    _mm256_storeu_si256((__m256i *)(arr + 8),  c);
    _mm256_storeu_si256((__m256i *)(arr + 12), d);
    _mm256_storeu_si256((__m256i *)(arr + 16), e);
    _mm256_storeu_si256((__m256i *)(arr + 20), f);
    _mm256_storeu_si256((__m256i *)(arr + 24), g);
    _mm256_storeu_si256((__m256i *)(arr + 28), h);
}

#endif // __AVX2__

// ============================================================================
// TYPE-GENERIC SORTING NETWORKS (all types via template)
// ============================================================================

// int32_t
#define SUB_TYPE int32_t
#define SUB_SUFFIX _i32
#include "small_impl.h"
#undef SUB_TYPE
#undef SUB_SUFFIX

// int64_t (with AVX2 support)
#define SUB_TYPE int64_t
#define SUB_SUFFIX _i64
#define SUB_TYPE_IS_I64
#include "small_impl.h"
#undef SUB_TYPE_IS_I64
#undef SUB_TYPE
#undef SUB_SUFFIX

// uint32_t
#define SUB_TYPE uint32_t
#define SUB_SUFFIX _u32
#include "small_impl.h"
#undef SUB_TYPE
#undef SUB_SUFFIX

// uint64_t
#define SUB_TYPE uint64_t
#define SUB_SUFFIX _u64
#include "small_impl.h"
#undef SUB_TYPE
#undef SUB_SUFFIX

// float
#define SUB_TYPE float
#define SUB_SUFFIX _f32
#include "small_impl.h"
#undef SUB_TYPE
#undef SUB_SUFFIX

// double
#define SUB_TYPE double
#define SUB_SUFFIX _f64
#include "small_impl.h"
#undef SUB_TYPE
#undef SUB_SUFFIX
