// radix.c -- the pure-random arm (see radix.h)
#define _POSIX_C_SOURCE 200809L
#include "internal/radix.h"
#include <stdlib.h>
#include <string.h>

#define SIGN32 0x80000000u
#define SIGN64 0x8000000000000000ull
#define RADIX_INSERTION 32   // below this, radix's fixed pass overhead loses

static inline uint64_t f64_bits(double d) { uint64_t u; memcpy(&u, &d, 8); return u; }
static inline double  bits_f64(uint64_t u) { double d; memcpy(&d, &u, 8); return d; }
static inline uint32_t f32_bits(float f)   { uint32_t u; memcpy(&u, &f, 4); return u; }
static inline float   bits_f32(uint32_t u) { float f; memcpy(&f, &u, 4); return f; }

// IEEE total-order flips (Herf): map float bits to a monotonic unsigned key.
static inline uint64_t flt_fwd64(uint64_t b) { return b ^ ((-(int64_t)(b >> 63)) | SIGN64); }
static inline uint64_t flt_inv64(uint64_t b) { return b ^ (((b >> 63) - 1) | SIGN64); }
static inline uint32_t flt_fwd32(uint32_t b) { return b ^ ((uint32_t)(-(int32_t)(b >> 31)) | SIGN32); }
static inline uint32_t flt_inv32(uint32_t b) { return b ^ (((b >> 31) - 1) | SIGN32); }

#define GEN_INSERTION(T, NAME) \
    static void NAME(T *a, size_t n) { \
        for (size_t i = 1; i < n; i++) { T k = a[i]; size_t j = i; \
            while (j > 0 && a[j-1] > k) { a[j] = a[j-1]; j--; } a[j] = k; } }
GEN_INSERTION(uint32_t, ins_u32)
GEN_INSERTION(uint64_t, ins_u64)

// Tuned LSD radix over u64: one combined histogram scan across all 8 byte
// columns, then write-combining scatter passes (one cache line per bucket) with
// constant-byte skipping and ping-pong buffers. `buf` is caller scratch, n u64.
static void radix_u64_core(uint64_t *arr, size_t n, uint64_t *buf) {
    if (n < RADIX_INSERTION) { ins_u64(arr, n); return; }
    enum { WC = 8 };                       // 8 u64 = one 64-byte cache line
    size_t hist[8][256];
    memset(hist, 0, sizeof hist);
    for (size_t i = 0; i < n; i++) {
        uint64_t v = arr[i];
        hist[0][ v        & 0xff]++; hist[1][(v >>  8) & 0xff]++;
        hist[2][(v >> 16) & 0xff]++; hist[3][(v >> 24) & 0xff]++;
        hist[4][(v >> 32) & 0xff]++; hist[5][(v >> 40) & 0xff]++;
        hist[6][(v >> 48) & 0xff]++; hist[7][(v >> 56) & 0xff]++;
    }
    uint64_t *src = arr, *dst = buf;
    for (int p = 0; p < 8; p++) {
        int sh = p * 8;
        size_t *h = hist[p];
        if (h[(src[0] >> sh) & 0xff] == n) continue;   // constant byte: skip pass
        size_t head[256], pos[256];
        _Alignas(64) uint64_t wc[256][WC];
        size_t acc = 0;
        for (int d = 0; d < 256; d++) { head[d] = acc; acc += h[d]; pos[d] = 0; }
        for (size_t i = 0; i < n; i++) {
            uint64_t v = src[i];
            uint8_t d = (uint8_t)((v >> sh) & 0xff);
            size_t pp = pos[d];
            wc[d][pp] = v;
            if (++pp == WC) { memcpy(dst + head[d], wc[d], WC * sizeof(uint64_t)); head[d] += WC; pos[d] = 0; }
            else pos[d] = pp;
        }
        for (int d = 0; d < 256; d++) {
            size_t pp = pos[d];
            if (pp) { memcpy(dst + head[d], wc[d], pp * sizeof(uint64_t)); head[d] += pp; }
        }
        uint64_t *t = src; src = dst; dst = t;
    }
    if (src != arr) memcpy(arr, src, n * sizeof(uint64_t));
}

// Tuned LSD radix over u32: 4 byte columns, otherwise identical.
static void radix_u32_core(uint32_t *arr, size_t n, uint32_t *buf) {
    if (n < RADIX_INSERTION) { ins_u32(arr, n); return; }
    enum { WC = 16 };                      // 16 u32 = one 64-byte cache line
    size_t hist[4][256];
    memset(hist, 0, sizeof hist);
    for (size_t i = 0; i < n; i++) {
        uint32_t v = arr[i];
        hist[0][ v        & 0xff]++; hist[1][(v >>  8) & 0xff]++;
        hist[2][(v >> 16) & 0xff]++; hist[3][(v >> 24) & 0xff]++;
    }
    uint32_t *src = arr, *dst = buf;
    for (int p = 0; p < 4; p++) {
        int sh = p * 8;
        size_t *h = hist[p];
        if (h[(src[0] >> sh) & 0xff] == n) continue;
        size_t head[256], pos[256];
        _Alignas(64) uint32_t wc[256][WC];
        size_t acc = 0;
        for (int d = 0; d < 256; d++) { head[d] = acc; acc += h[d]; pos[d] = 0; }
        for (size_t i = 0; i < n; i++) {
            uint32_t v = src[i];
            uint8_t d = (uint8_t)((v >> sh) & 0xff);
            size_t pp = pos[d];
            wc[d][pp] = v;
            if (++pp == WC) { memcpy(dst + head[d], wc[d], WC * sizeof(uint32_t)); head[d] += WC; pos[d] = 0; }
            else pos[d] = pp;
        }
        for (int d = 0; d < 256; d++) {
            size_t pp = pos[d];
            if (pp) { memcpy(dst + head[d], wc[d], pp * sizeof(uint32_t)); head[d] += pp; }
        }
        uint32_t *t = src; src = dst; dst = t;
    }
    if (src != arr) memcpy(arr, src, n * sizeof(uint32_t));
}

// Serial fallback when scratch cannot be allocated: an in-place insertion sort
// keeps correctness (slow, only on OOM at large n, which is already dire).
#define OOM_FALLBACK(T, NAME) \
    static void NAME(T *a, size_t n) { \
        for (size_t i = 1; i < n; i++) { T k = a[i]; size_t j = i; \
            while (j > 0 && a[j-1] > k) { a[j] = a[j-1]; j--; } a[j] = k; } }
OOM_FALLBACK(int32_t,  oom_i32)
OOM_FALLBACK(int64_t,  oom_i64)
OOM_FALLBACK(uint32_t, oom_u32)
OOM_FALLBACK(uint64_t, oom_u64)
OOM_FALLBACK(float,    oom_f32)
OOM_FALLBACK(double,   oom_f64)

void sub_radix_sort_u64(uint64_t *arr, size_t n) {
    if (n < 2) return;
    uint64_t *buf = malloc(n * sizeof(uint64_t));
    if (!buf) { oom_u64(arr, n); return; }
    radix_u64_core(arr, n, buf);
    free(buf);
}

void sub_radix_sort_i64(int64_t *arr, size_t n) {
    if (n < 2) return;
    uint64_t *keys = malloc(n * sizeof(uint64_t)), *buf = malloc(n * sizeof(uint64_t));
    if (!keys || !buf) { free(keys); free(buf); oom_i64(arr, n); return; }
    for (size_t i = 0; i < n; i++) keys[i] = (uint64_t)arr[i] ^ SIGN64;
    radix_u64_core(keys, n, buf);
    for (size_t i = 0; i < n; i++) arr[i] = (int64_t)(keys[i] ^ SIGN64);
    free(keys); free(buf);
}

void sub_radix_sort_f64(double *arr, size_t n) {
    if (n < 2) return;
    uint64_t *keys = malloc(n * sizeof(uint64_t)), *buf = malloc(n * sizeof(uint64_t));
    if (!keys || !buf) { free(keys); free(buf); oom_f64(arr, n); return; }
    for (size_t i = 0; i < n; i++) keys[i] = flt_fwd64(f64_bits(arr[i]));
    radix_u64_core(keys, n, buf);
    for (size_t i = 0; i < n; i++) arr[i] = bits_f64(flt_inv64(keys[i]));
    free(keys); free(buf);
}

void sub_radix_sort_u32(uint32_t *arr, size_t n) {
    if (n < 2) return;
    uint32_t *buf = malloc(n * sizeof(uint32_t));
    if (!buf) { oom_u32(arr, n); return; }
    radix_u32_core(arr, n, buf);
    free(buf);
}

void sub_radix_sort_i32(int32_t *arr, size_t n) {
    if (n < 2) return;
    uint32_t *keys = malloc(n * sizeof(uint32_t)), *buf = malloc(n * sizeof(uint32_t));
    if (!keys || !buf) { free(keys); free(buf); oom_i32(arr, n); return; }
    for (size_t i = 0; i < n; i++) keys[i] = (uint32_t)arr[i] ^ SIGN32;
    radix_u32_core(keys, n, buf);
    for (size_t i = 0; i < n; i++) arr[i] = (int32_t)(keys[i] ^ SIGN32);
    free(keys); free(buf);
}

void sub_radix_sort_f32(float *arr, size_t n) {
    if (n < 2) return;
    uint32_t *keys = malloc(n * sizeof(uint32_t)), *buf = malloc(n * sizeof(uint32_t));
    if (!keys || !buf) { free(keys); free(buf); oom_f32(arr, n); return; }
    for (size_t i = 0; i < n; i++) keys[i] = flt_fwd32(f32_bits(arr[i]));
    radix_u32_core(keys, n, buf);
    for (size_t i = 0; i < n; i++) arr[i] = bits_f32(flt_inv32(keys[i]));
    free(keys); free(buf);
}
