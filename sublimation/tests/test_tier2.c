// test_tier2.c -- Tier 2: Adversarial input patterns
//
// Patterns specifically designed to break sorting algorithms.
// Every result property-verified: sorted + permutation.
#include "../src/include/sublimation.h"
#include "verify.h"
#include <assert.h>
#include <math.h>

static void test_pattern(const char *name, int64_t *arr, size_t n) {
    VERIFY_SORT(arr, n, sublimation_i64, name);
}

// PIPE ORGAN: ascending then descending
static void fill_pipe_organ(int64_t *arr, size_t n) {
    size_t half = n / 2;
    for (size_t i = 0; i < half; i++) arr[i] = (int64_t)i;
    for (size_t i = half; i < n; i++) arr[i] = (int64_t)(n - 1 - i);
}

// PUSH FRONT: sorted except first element is max
static void fill_push_front(int64_t *arr, size_t n) {
    for (size_t i = 0; i < n; i++) arr[i] = (int64_t)(i + 1);
    arr[0] = (int64_t)n;
}

// PUSH MIDDLE: sorted except middle element is min
static void fill_push_middle(int64_t *arr, size_t n) {
    for (size_t i = 0; i < n; i++) arr[i] = (int64_t)(i + 1);
    arr[n / 2] = 0;
}

// ASCENDING SAWTOOTH: repeated ascending runs
static void fill_asc_sawtooth(int64_t *arr, size_t n) {
    size_t run_len = n / 8;
    if (run_len < 2) run_len = 2;
    for (size_t i = 0; i < n; i++) {
        arr[i] = (int64_t)(i % run_len);
    }
}

// DESCENDING SAWTOOTH: repeated descending runs
static void fill_desc_sawtooth(int64_t *arr, size_t n) {
    size_t run_len = n / 8;
    if (run_len < 2) run_len = 2;
    for (size_t i = 0; i < n; i++) {
        arr[i] = (int64_t)(run_len - 1 - (i % run_len));
    }
}

// ORGAN PIPES: multiple pipe organs concatenated
static void fill_organ_pipes(int64_t *arr, size_t n) {
    size_t segment = n / 4;
    if (segment < 4) segment = 4;
    for (size_t i = 0; i < n; i++) {
        size_t pos = i % segment;
        size_t half = segment / 2;
        if (pos < half) arr[i] = (int64_t)pos;
        else arr[i] = (int64_t)(segment - 1 - pos);
    }
}

// SORTED + RANDOM MIDDLE: sorted prefix, random block, sorted suffix
static void fill_sorted_random_middle(int64_t *arr, size_t n) {
    for (size_t i = 0; i < n; i++) arr[i] = (int64_t)i;
    size_t start = n / 4;
    size_t end = n * 3 / 4;
    uint64_t seed = 0xCAFEBABE;
    for (size_t i = start; i < end; i++) {
        seed = seed * 6364136223846793005ull + 1442695040888963407ull;
        arr[i] = (int64_t)(seed >> 16);
    }
}

// PLATEAU: sorted with flat region of equal values in the middle
static void fill_plateau(int64_t *arr, size_t n) {
    for (size_t i = 0; i < n; i++) arr[i] = (int64_t)i;
    int64_t mid_val = (int64_t)(n / 2);
    size_t start = n / 3;
    size_t end = n * 2 / 3;
    for (size_t i = start; i < end; i++) arr[i] = mid_val;
}

// SORTED + RANDOM TAIL (phased)
static void fill_sorted_random_tail(int64_t *arr, size_t n) {
    size_t boundary = n * 3 / 4;
    for (size_t i = 0; i < boundary; i++) arr[i] = (int64_t)i;
    uint64_t seed = 0xDEADC0DE;
    for (size_t i = boundary; i < n; i++) {
        seed = seed * 6364136223846793005ull + 1442695040888963407ull;
        arr[i] = (int64_t)(seed >> 16);
    }
}

// REVERSE SORTED + RANDOM TAIL
static void fill_reverse_random_tail(int64_t *arr, size_t n) {
    size_t boundary = n * 3 / 4;
    for (size_t i = 0; i < boundary; i++) arr[i] = (int64_t)(boundary - i);
    uint64_t seed = 0xBAADF00D;
    for (size_t i = boundary; i < n; i++) {
        seed = seed * 6364136223846793005ull + 1442695040888963407ull;
        arr[i] = (int64_t)(seed >> 16);
    }
}

// MANY DUPLICATES: sqrt(n) distinct values
static void fill_many_dupes(int64_t *arr, size_t n) {
    size_t k = 1;
    while (k * k < n) k++;
    uint64_t seed = 0x1234ABCD;
    for (size_t i = 0; i < n; i++) {
        seed = seed * 6364136223846793005ull + 1442695040888963407ull;
        arr[i] = (int64_t)((seed >> 33) % k);
    }
}

// SHUFFLE WITH DISPLACEMENT LIMIT: each element at most d positions from sorted
static void fill_limited_displacement(int64_t *arr, size_t n, size_t d) {
    for (size_t i = 0; i < n; i++) arr[i] = (int64_t)i;
    uint64_t seed = 0xABCDEF01;
    for (size_t i = 0; i < n; i++) {
        seed = seed * 6364136223846793005ull + 1442695040888963407ull;
        size_t j = i + (size_t)(seed >> 33) % (d + 1);
        if (j >= n) j = n - 1;
        int64_t tmp = arr[i]; arr[i] = arr[j]; arr[j] = tmp;
    }
}

// MCILROY ADVERSARY SKELETON
// Simplified: sorted except every k-th element is random (breaks bad pivots)
static void fill_mcilroy_lite(int64_t *arr, size_t n) {
    for (size_t i = 0; i < n; i++) arr[i] = (int64_t)i;
    uint64_t seed = 0xFEEDFACE;
    size_t k = 8;
    for (size_t i = 0; i < n; i += k) {
        seed = seed * 6364136223846793005ull + 1442695040888963407ull;
        arr[i] = (int64_t)(seed >> 16);
    }
}

// RUN ALL PATTERNS AT GIVEN SIZE

static void run_all_patterns(size_t n) {
    char name[80];
    int64_t *arr = (int64_t *)malloc(n * sizeof(int64_t));
    assert(arr);

    #define P(fn, label) do { \
        fn(arr, n); \
        snprintf(name, sizeof(name), "%s_%zu", label, n); \
        test_pattern(name, arr, n); \
    } while(0)

    P(fill_pipe_organ, "pipe_organ");
    P(fill_push_front, "push_front");
    P(fill_push_middle, "push_middle");
    P(fill_asc_sawtooth, "asc_sawtooth");
    P(fill_desc_sawtooth, "desc_sawtooth");
    P(fill_organ_pipes, "organ_pipes");
    P(fill_sorted_random_middle, "sorted_random_middle");
    P(fill_plateau, "plateau");
    P(fill_sorted_random_tail, "sorted_random_tail");
    P(fill_reverse_random_tail, "reverse_random_tail");
    P(fill_many_dupes, "many_dupes");
    P(fill_mcilroy_lite, "mcilroy_lite");

    // limited displacement: d=1, d=5, d=sqrt(n)
    fill_limited_displacement(arr, n, 1);
    snprintf(name, sizeof(name), "disp_1_%zu", n);
    test_pattern(name, arr, n);

    fill_limited_displacement(arr, n, 5);
    snprintf(name, sizeof(name), "disp_5_%zu", n);
    test_pattern(name, arr, n);

    size_t sqrtn = 1;
    while (sqrtn * sqrtn < n) sqrtn++;
    fill_limited_displacement(arr, n, sqrtn);
    snprintf(name, sizeof(name), "disp_sqrt_%zu", n);
    test_pattern(name, arr, n);

    #undef P
    free(arr);
}

int main(void) {
    printf("[sublimation] Tier 2: adversarial input patterns\n\n");

    size_t sizes[] = {100, 1000, 10000, 100000};
    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        printf("  --- n = %zu ---\n", sizes[i]);
        run_all_patterns(sizes[i]);
        printf("\n");
    }

    return verify_summary();
}
