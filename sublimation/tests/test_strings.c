// test_strings.c -- correctness fixtures for sublimation_strings
//
// Verifier: sort a copy of the input via qsort+strcmp, compare against
// sublimation_strings output element-by-element (pointer equality is fine
// since we permute pointers). Any mismatch is a fail.
#include "../src/include/sublimation_strings.h"

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

static int qsort_cmp(const void *a, const void *b) {
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

// Verifier: sort a duplicate via qsort, then compare contents.
static void check(const char *name, const char **arr, size_t n) {
    const char **ref = NULL;
    if (n > 0) {
        ref = (const char **)malloc(n * sizeof(const char *));
        memcpy(ref, arr, n * sizeof(const char *));
        qsort(ref, n, sizeof(const char *), qsort_cmp);
    }

    sublimation_strings(arr, n);

    int ok = 1;
    for (size_t i = 0; i < n; i++) {
        if (strcmp(arr[i], ref[i]) != 0) {
            fprintf(stderr, "  [FAIL] %s: position %zu: got '%.32s', expected '%.32s'\n",
                    name, i, arr[i], ref[i]);
            ok = 0;
            break;
        }
    }

    if (ok) {
        printf("  %-50s PASS\n", name);
        _pass++;
    } else {
        _fail++;
    }
    free(ref);
}

// Random ASCII string of length L into buf (buf must hold L+1 bytes).
static void random_string(char *buf, size_t L) {
    static const char alphabet[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for (size_t i = 0; i < L; i++) {
        buf[i] = alphabet[lcg_next() % 62];
    }
    buf[L] = '\0';
}

// Build n strings of given length. Caller receives both the pointer
// array and the backing buffer; both must be freed independently because
// sort permutes the pointer array.
static const char **build_random_strings(size_t n, size_t L, uint64_t seed,
                                          char **out_buf) {
    lcg_seed(seed);
    char *buf = (char *)malloc(n * (L + 1));
    const char **arr = (const char **)malloc(n * sizeof(const char *));
    for (size_t i = 0; i < n; i++) {
        random_string(buf + i * (L + 1), L);
        arr[i] = buf + i * (L + 1);
    }
    *out_buf = buf;
    return arr;
}

// Test 1: trivial sizes -- early-return guards
static void test_trivial(void) {
    check("trivial_empty", NULL, 0);
    const char *single[] = {"alone"};
    check("trivial_single", single, 1);
}

// Test 2: all identical strings
static void test_all_identical(void) {
    const size_t N = 1000;
    const char **arr = (const char **)malloc(N * sizeof(const char *));
    static const char *S = "duplicate_string";
    for (size_t i = 0; i < N; i++) arr[i] = S;
    check("all_identical_1000", arr, N);
    free(arr);
}

// Test 3: all empty
static void test_all_empty(void) {
    const size_t N = 1000;
    const char **arr = (const char **)malloc(N * sizeof(const char *));
    static const char *S = "";
    for (size_t i = 0; i < N; i++) arr[i] = S;
    check("all_empty_1000", arr, N);
    free(arr);
}

// Test 4: mixed empty + non-empty
static void test_mixed_empty(void) {
    const size_t N = 1000;
    const char **arr = (const char **)malloc(N * sizeof(const char *));
    static const char *S = "";
    char *buf = (char *)malloc(N * 8);
    lcg_seed(0xE57E817Aull);
    for (size_t i = 0; i < N; i++) {
        if (lcg_next() & 1) {
            arr[i] = S;
        } else {
            random_string(buf + i * 8, 7);
            arr[i] = buf + i * 8;
        }
    }
    check("mixed_empty_1000", arr, N);
    free(arr);
    free(buf);
}

// Test 5: common prefix < 4 bytes (resolved by prefix4 alone)
static void test_short_common_prefix(void) {
    const size_t N = 1000;
    const char **arr = (const char **)malloc(N * sizeof(const char *));
    char *buf = (char *)malloc(N * 16);
    for (size_t i = 0; i < N; i++) {
        snprintf(buf + i * 16, 16, "ab%05u", (unsigned)(N - i));
        arr[i] = buf + i * 16;
    }
    check("short_common_prefix_1000", arr, N);
    free(arr);
    free(buf);
}

// Test 6: common prefix >= 4 bytes (exercises MSD path)
static void test_long_common_prefix(void) {
    const size_t N = 1000;
    const char **arr = (const char **)malloc(N * sizeof(const char *));
    char *buf = (char *)malloc(N * 24);
    for (size_t i = 0; i < N; i++) {
        snprintf(buf + i * 24, 24, "hello_world_%05u", (unsigned)(N - i));
        arr[i] = buf + i * 24;
    }
    check("long_common_prefix_1000", arr, N);
    free(arr);
    free(buf);
}

// Test 7: common prefix > 256 bytes (MSD work-stack growth)
static void test_deep_common_prefix(void) {
    const size_t N = 200;
    const size_t PREFIX = 300;
    const size_t L = PREFIX + 8;
    const char **arr = (const char **)malloc(N * sizeof(const char *));
    char *buf = (char *)malloc(N * (L + 1));
    for (size_t i = 0; i < N; i++) {
        char *p = buf + i * (L + 1);
        memset(p, 'X', PREFIX);
        snprintf(p + PREFIX, 9, "%07u", (unsigned)(N - i));
        p[L] = '\0';
        arr[i] = p;
    }
    check("deep_common_prefix_200", arr, N);
    free(arr);
    free(buf);
}

// Test 8: adversarial 4 KB shared prefix
static void test_adversarial_4kb(void) {
    const size_t N = 1024;
    const size_t PREFIX = 4096;
    const size_t L = PREFIX + 4;
    const char **arr = (const char **)malloc(N * sizeof(const char *));
    char *buf = (char *)malloc(N * (L + 1));
    for (size_t i = 0; i < N; i++) {
        char *p = buf + i * (L + 1);
        memset(p, 'A', PREFIX);
        snprintf(p + PREFIX, 5, "%04u", (unsigned)(N - i));
        p[L] = '\0';
        arr[i] = p;
    }
    check("adversarial_4kb_1024", arr, N);
    free(arr);
    free(buf);
}

// Test 9: UTF-8 multibyte sequences (byte order = code point order)
static void test_utf8(void) {
    const char *base[] = {
        "café", "naïve", "résumé", "über",
        "日本語", "中文", "한국어", "العربية",
        "ḡϱøsş", "Ĉĥö", "🎉", "👋",
        "abc", "xyz", "alpha", "beta",
    };
    const size_t N = sizeof(base) / sizeof(base[0]);
    const char **arr = (const char **)malloc(N * sizeof(const char *));
    memcpy(arr, base, sizeof(base));
    check("utf8_16", arr, N);
    free(arr);
}

// Test 11: pre-sorted input
static void test_pre_sorted(void) {
    const size_t N = 100000;
    char *buf;
    const char **arr = build_random_strings(N, 12, 0xC0DEFEEDull, &buf);
    qsort(arr, N, sizeof(const char *), qsort_cmp);
    check("pre_sorted_100k", arr, N);
    free(arr); free(buf);
}

// Test 12: reverse-sorted input
static void test_reverse_sorted(void) {
    const size_t N = 100000;
    char *buf;
    const char **arr = build_random_strings(N, 12, 0xDEADBEEFull, &buf);
    qsort(arr, N, sizeof(const char *), qsort_cmp);
    for (size_t i = 0, j = N - 1; i < j; i++, j--) {
        const char *tmp = arr[i]; arr[i] = arr[j]; arr[j] = tmp;
    }
    check("reverse_sorted_100k", arr, N);
    free(arr); free(buf);
}

// Test 13: random uniform 100k
static void test_random_100k(void) {
    const size_t N = 100000;
    char *buf;
    const char **arr = build_random_strings(N, 12, 0xCAFEBABEull, &buf);
    check("random_100k", arr, N);
    free(arr); free(buf);
}

// Test 14: random uniform 1M
static void test_random_1m(void) {
    const size_t N = 1000000;
    char *buf;
    const char **arr = build_random_strings(N, 12, 0x1234567890ABCDEFull, &buf);
    check("random_1m", arr, N);
    free(arr); free(buf);
}

// Test 10: embedded NUL via sublimation_strings_len
//
// Each "string" is 8 bytes with a NUL in the middle. The length-explicit
// API treats the NUL as data, not a terminator. NUL (0x00) is the
// lex-smallest byte, so a NUL at position k makes the string sort before
// any string with a non-NUL byte at position k (if bytes 0..k-1 match).
static int strings_len_sorted(const char **arr, const size_t *lens, size_t n) {
    for (size_t i = 1; i < n; i++) {
        size_t common = lens[i - 1] < lens[i] ? lens[i - 1] : lens[i];
        int cmp = memcmp(arr[i - 1], arr[i], common);
        if (cmp > 0) return 0;
        if (cmp == 0 && lens[i - 1] > lens[i]) return 0;
    }
    return 1;
}

static void test_embedded_nul(void) {
    const size_t N = 100;
    const size_t L = 8;
    char *buf = (char *)malloc(N * L);
    const char **arr = (const char **)malloc(N * sizeof(const char *));
    size_t *lens = (size_t *)malloc(N * sizeof(size_t));

    lcg_seed(0xE17BED1Eull);
    for (size_t i = 0; i < N; i++) {
        char *p = buf + i * L;
        for (size_t j = 0; j < L; j++) {
            p[j] = (char)(0x21 + (char)(lcg_next() % 0x5E)); // printable ASCII
        }
        p[L / 2] = '\0';  // embedded NUL
        arr[i] = p;
        lens[i] = L;
    }

    sublimation_strings_len(arr, lens, N);
    int ok = strings_len_sorted(arr, lens, N);
    if (ok) {
        printf("  %-50s PASS\n", "embedded_nul_100");
        _pass++;
    } else {
        fprintf(stderr, "  [FAIL] embedded_nul_100: not sorted\n");
        _fail++;
    }
    free(arr); free(lens); free(buf);
}

int main(void) {
    test_trivial();
    test_all_identical();
    test_all_empty();
    test_mixed_empty();
    test_short_common_prefix();
    test_long_common_prefix();
    test_deep_common_prefix();
    test_adversarial_4kb();
    test_utf8();
    test_pre_sorted();
    test_reverse_sorted();
    test_random_100k();
    test_random_1m();
    test_embedded_nul();

    // Index-output variant: sort via sublimation_strings AND
    // sublimation_strings_indices on the same input; verify they produce
    // the same order.
    {
        const size_t N = 10000;
        char *buf_a, *buf_b;
        const char **arr_a = build_random_strings(N, 12, 0x10DEC5E5ull, &buf_a);
        const char **arr_b = (const char **)malloc(N * sizeof(const char *));
        char *buf_b_alloc = (char *)malloc(N * 13);
        memcpy(buf_b_alloc, buf_a, N * 13);
        (void)buf_b;
        buf_b = buf_b_alloc;
        for (size_t i = 0; i < N; i++) arr_b[i] = buf_b + i * 13;

        sublimation_strings(arr_a, N);

        uint32_t *indices = (uint32_t *)malloc(N * sizeof(uint32_t));
        sublimation_strings_indices(arr_b, indices, N);

        int ok = 1;
        for (size_t i = 0; i < N; i++) {
            const char *via_indices = arr_b[indices[i]];
            if (strcmp(arr_a[i], via_indices) != 0) {
                fprintf(stderr,
                        "  [FAIL] indices_parity_10k: position %zu: arr_a='%s' via_indices='%s'\n",
                        i, arr_a[i], via_indices);
                ok = 0; break;
            }
        }
        if (ok) { printf("  %-50s PASS\n", "indices_parity_10k"); _pass++; }
        else    { _fail++; }

        free(arr_a); free(buf_a); free(arr_b); free(buf_b); free(indices);
    }

    // indices_len variant: embedded-NUL input
    {
        const size_t N = 50;
        const size_t L = 6;
        char *buf = (char *)malloc(N * L);
        const char **arr = (const char **)malloc(N * sizeof(const char *));
        size_t *lens = (size_t *)malloc(N * sizeof(size_t));
        lcg_seed(0x1DE4BEDCull);
        for (size_t i = 0; i < N; i++) {
            char *p = buf + i * L;
            for (size_t j = 0; j < L; j++) p[j] = (char)(0x21 + (char)(lcg_next() % 0x5E));
            p[L / 2] = '\0';
            arr[i] = p;
            lens[i] = L;
        }
        uint32_t *indices = (uint32_t *)malloc(N * sizeof(uint32_t));
        sublimation_strings_indices_len(arr, lens, indices, N);

        int ok = 1;
        for (size_t i = 1; i < N; i++) {
            size_t a = indices[i - 1], b = indices[i];
            size_t common = lens[a] < lens[b] ? lens[a] : lens[b];
            int cmp = memcmp(arr[a], arr[b], common);
            if (cmp > 0 || (cmp == 0 && lens[a] > lens[b])) {
                fprintf(stderr, "  [FAIL] indices_len_50: not sorted at %zu\n", i);
                ok = 0; break;
            }
        }
        if (ok) { printf("  %-50s PASS\n", "indices_len_50"); _pass++; }
        else    { _fail++; }

        free(arr); free(lens); free(indices); free(buf);
    }

    // Degenerate indices cases
    {
        uint32_t out[1] = {99};
        const char *single[] = {"alone"};
        sublimation_strings_indices(single, out, 1);
        if (out[0] == 0) { printf("  %-50s PASS\n", "indices_n1"); _pass++; }
        else             { printf("  [FAIL] indices_n1\n"); _fail++; }
    }
    {
        sublimation_strings_indices(NULL, NULL, 0);
        printf("  %-50s PASS\n", "indices_n0_noop"); _pass++;
    }

    printf("\n  %d passed, %d failed\n", _pass, _fail);
    return _fail > 0 ? 1 : 0;
}
