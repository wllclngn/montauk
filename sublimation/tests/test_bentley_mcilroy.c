// test_bentley_mcilroy.c -- Canonical Bentley-McIlroy 1993 sort test matrix
//
// 5 distributions x 6 modes x multiple sizes x multiple moduli.
// Every combination: fill, apply mode, sort, verify sorted + permutation.
#include "../src/include/sublimation.h"
#include "verify.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// ── Deterministic RNG (LCG) ────────────────────────────────────────
static uint64_t bm_rng_state = 0xDEADBEEF42ULL;

static uint64_t bm_rand(void) {
    bm_rng_state = bm_rng_state * 6364136223846793005ULL + 1442695040888963407ULL;
    return bm_rng_state >> 16;
}

static void bm_seed(uint64_t s) {
    bm_rng_state = s;
}

// ── Distributions ──────────────────────────────────────────────────
// Each generates values in [0, n-1] with structural bias controlled by m.

static int64_t dist_sawtooth(size_t i, size_t m) {
    return (int64_t)(i % m);
}

static int64_t dist_rand(size_t i, size_t m) {
    (void)i;
    return (int64_t)(bm_rand() % m);
}

static int64_t dist_stagger(size_t i, size_t m, size_t n) {
    return (int64_t)((i * m + i) % n);
}

static int64_t dist_plateau(size_t i, size_t m) {
    return (int64_t)(i < m ? i : m);
}

static int64_t dist_shuffle(size_t i, size_t m) {
    (void)i;
    return (bm_rand() % m) ? (int64_t)(bm_rand() % m) : 0;
}

// ── Modes (applied to generated array) ─────────────────────────────

static void mode_copy(int64_t *arr, size_t n) {
    // identity -- do nothing
    (void)arr; (void)n;
}

static void mode_reverse(int64_t *arr, size_t n) {
    for (size_t i = 0; i < n / 2; i++) {
        int64_t tmp = arr[i];
        arr[i] = arr[n - 1 - i];
        arr[n - 1 - i] = tmp;
    }
}

static void mode_reverse_front(int64_t *arr, size_t n) {
    size_t half = n / 2;
    for (size_t i = 0; i < half / 2; i++) {
        int64_t tmp = arr[i];
        arr[i] = arr[half - 1 - i];
        arr[half - 1 - i] = tmp;
    }
}

static void mode_reverse_back(int64_t *arr, size_t n) {
    size_t half = n / 2;
    for (size_t i = half; i < half + (n - half) / 2; i++) {
        size_t j = n - 1 - (i - half);
        int64_t tmp = arr[i];
        arr[i] = arr[j];
        arr[j] = tmp;
    }
}

static int bm_cmp_i64(const void *a, const void *b) {
    int64_t va = *(const int64_t *)a, vb = *(const int64_t *)b;
    return (va > vb) - (va < vb);
}

static void mode_sorted(int64_t *arr, size_t n) {
    qsort(arr, n, sizeof(int64_t), bm_cmp_i64);
}

static void mode_dither(int64_t *arr, size_t n) {
    for (size_t i = 0; i < n; i++) {
        int64_t d = (int64_t)(bm_rand() % 3) - 1;  // -1, 0, or +1
        arr[i] += d;
    }
}

// ── Driver ─────────────────────────────────────────────────────────

static const char *dist_names[] = {
    "sawtooth", "rand", "stagger", "plateau", "shuffle"
};

static const char *mode_names[] = {
    "copy", "reverse", "rev_front", "rev_back", "sorted", "dither"
};

typedef void (*mode_fn)(int64_t *, size_t);
static mode_fn modes[] = {
    mode_copy, mode_reverse, mode_reverse_front,
    mode_reverse_back, mode_sorted, mode_dither
};

static void fill_distribution(int64_t *arr, size_t n, int dist, size_t m) {
    for (size_t i = 0; i < n; i++) {
        switch (dist) {
            case 0: arr[i] = dist_sawtooth(i, m); break;
            case 1: arr[i] = dist_rand(i, m);     break;
            case 2: arr[i] = dist_stagger(i, m, n); break;
            case 3: arr[i] = dist_plateau(i, m);  break;
            case 4: arr[i] = dist_shuffle(i, m);  break;
        }
    }
}

int main(void) {
    printf("[sublimation] Bentley-McIlroy test matrix\n\n");

    static const size_t sizes[] = {100, 1023, 1024, 1025, 10000};
    int num_sizes = (int)(sizeof(sizes) / sizeof(sizes[0]));
    int num_dists = 5;
    int num_modes = 6;

    int total = 0;

    for (int si = 0; si < num_sizes; si++) {
        size_t n = sizes[si];
        int64_t *arr = (int64_t *)malloc(n * sizeof(int64_t));
        if (!arr) {
            fprintf(stderr, "  [FAIL] malloc failed for n=%zu\n", n);
            _verify_fail++;
            continue;
        }

        // generate moduli: 1, 2, 4, 8, ..., up to 2*n (powers of 2)
        size_t moduli[20];
        int num_moduli = 0;
        for (size_t m = 1; m <= 2 * n && num_moduli < 20; m *= 2) {
            moduli[num_moduli++] = m;
        }

        for (int di = 0; di < num_dists; di++) {
            for (int mi = 0; mi < num_modes; mi++) {
                for (int mdi = 0; mdi < num_moduli; mdi++) {
                    size_t m = moduli[mdi];

                    // deterministic seed per combo
                    bm_seed((uint64_t)n * 1000000 + (uint64_t)di * 10000 +
                            (uint64_t)mi * 100 + (uint64_t)mdi);

                    fill_distribution(arr, n, di, m);
                    modes[mi](arr, n);

                    // save, sort, verify
                    char label[128];
                    snprintf(label, sizeof(label), "n=%zu %s/%s m=%zu",
                             n, dist_names[di], mode_names[mi], m);

                    int64_t *saved = verify_save(arr, n);
                    sublimation_i64(arr, n);
                    verify_sort(arr, saved, n, label);
                    free(saved);
                    total++;
                }
            }
        }

        free(arr);
    }

    printf("\n  Bentley-McIlroy matrix: %d combinations tested\n", total);
    return verify_summary();
}
