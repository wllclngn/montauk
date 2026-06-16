// test_adversarial.c -- Adversarial patterns designed to break adaptive sorters
//
// Every pattern is run at sizes 100, 1000, 10000, 100000.
// Each result is property-verified: sorted + permutation.
#include "../src/include/sublimation.h"
#include "verify.h"
#include <assert.h>
#include <limits.h>
#include <math.h>

static const size_t SIZES[] = {100, 1000, 10000, 100000};
#define NUM_SIZES 4

// Deterministic LCG for reproducible patterns
static uint64_t lcg_state;

static void lcg_seed(uint64_t s) { lcg_state = s; }

static uint64_t lcg_next(void) {
    lcg_state = lcg_state * 6364136223846793005ull + 1442695040888963407ull;
    return lcg_state;
}

static int64_t lcg_range(int64_t lo, int64_t hi) {
    uint64_t range = (uint64_t)(hi - lo + 1);
    return lo + (int64_t)((lcg_next() >> 16) % range);
}

// Run a single test: allocate, fill, sort, verify, free
typedef void (*fill_fn)(int64_t *arr, size_t n);

static void run_pattern(const char *pattern_name, fill_fn filler) {
    for (int si = 0; si < NUM_SIZES; si++) {
        size_t n = SIZES[si];
        char name[128];
        snprintf(name, sizeof(name), "%s (n=%zu)", pattern_name, n);

        int64_t *arr = (int64_t *)malloc(n * sizeof(int64_t));
        assert(arr && "malloc failed");

        lcg_seed(0xAD0E5A41A1ull ^ (uint64_t)n);
        filler(arr, n);

        int64_t *saved = verify_save(arr, n);
        sublimation_i64(arr, n);
        verify_sort(arr, saved, n, name);
        free(saved);
        free(arr);
    }
}

// ============================================================
// CLASSIFIER CONFUSION (attacks the RSK presort gate)
// ============================================================

// 1. sorted_random_splice: first 90% sorted, last 10% random.
//    Fools run-count into "nearly sorted" when the tail needs partition.
static void fill_sorted_random_splice(int64_t *arr, size_t n) {
    size_t boundary = n * 9 / 10;
    for (size_t i = 0; i < boundary; i++)
        arr[i] = (int64_t)i;
    for (size_t i = boundary; i < n; i++)
        arr[i] = (int64_t)(lcg_next() >> 16);
}

// 2. ascending_sawtooth: k ascending runs each starting from 0.
//    High run count but structured.
static void fill_ascending_sawtooth(int64_t *arr, size_t n) {
    size_t k = (size_t)sqrt((double)n);
    if (k < 2) k = 2;
    size_t run_len = n / k;
    for (size_t i = 0; i < n; i++)
        arr[i] = (int64_t)(i % run_len);
}

// 3. descending_sawtooth: k descending runs.
//    Forces run reversal overhead.
static void fill_descending_sawtooth(int64_t *arr, size_t n) {
    size_t k = (size_t)sqrt((double)n);
    if (k < 2) k = 2;
    size_t run_len = n / k;
    for (size_t i = 0; i < n; i++)
        arr[i] = (int64_t)(run_len - 1 - (i % run_len));
}

// 4. plateau_cliff: 99% elements are 42, last 1% random.
//    Is it few-unique or nearly-sorted?
static void fill_plateau_cliff(int64_t *arr, size_t n) {
    size_t boundary = n * 99 / 100;
    if (boundary >= n) boundary = n - 1;
    for (size_t i = 0; i < boundary; i++)
        arr[i] = 42;
    for (size_t i = boundary; i < n; i++)
        arr[i] = (int64_t)(lcg_next() >> 16);
}

// 5. sorted_with_periodic_spikes: sorted array with random spikes
//    every sqrt(n) positions.
static void fill_sorted_with_periodic_spikes(int64_t *arr, size_t n) {
    for (size_t i = 0; i < n; i++)
        arr[i] = (int64_t)i;
    size_t stride = (size_t)sqrt((double)n);
    if (stride < 1) stride = 1;
    for (size_t i = 0; i < n; i += stride)
        arr[i] = (int64_t)(lcg_next() >> 16);
}

// ============================================================
// PIVOT KILLERS (attacks partition)
// ============================================================

// 6. pipe_organ_nested: 4 segments, each is a pipe organ [0..n/4..0].
static void fill_pipe_organ_nested(int64_t *arr, size_t n) {
    size_t seg = n / 4;
    for (size_t s = 0; s < 4; s++) {
        size_t base = s * seg;
        size_t len = (s == 3) ? (n - base) : seg;
        size_t half = len / 2;
        for (size_t i = 0; i < half; i++)
            arr[base + i] = (int64_t)i;
        for (size_t i = half; i < len; i++)
            arr[base + i] = (int64_t)(len - 1 - i);
    }
}

// 7. median_of_three_killer: the Musser anti-quicksort sequence.
//    Start with sorted [0..n), then for i from n-1 down to 2,
//    swap arr[i] with arr[i/2].
static void fill_median_of_three_killer(int64_t *arr, size_t n) {
    for (size_t i = 0; i < n; i++)
        arr[i] = (int64_t)i;
    for (size_t i = n; i >= 3; i--) {
        int64_t tmp = arr[i - 1];
        arr[i - 1] = arr[(i - 1) / 2];
        arr[(i - 1) / 2] = tmp;
    }
}

// 8. repeated_element_noise: 80% same value, 20% random.
//    Tests three-way partition detection.
static void fill_repeated_element_noise(int64_t *arr, size_t n) {
    int64_t dominant = 1000000;
    for (size_t i = 0; i < n; i++) {
        if ((lcg_next() >> 16) % 5 == 0)
            arr[i] = (int64_t)(lcg_next() >> 16);
        else
            arr[i] = dominant;
    }
}

// ============================================================
// MERGE PATHOLOGY (attacks R_eff merge)
// ============================================================

// 9. interleaved_sorted: two sorted sequences woven together.
//    [0, n/2, 1, n/2+1, 2, n/2+2, ...]. Maximum merge cost.
static void fill_interleaved_sorted(int64_t *arr, size_t n) {
    size_t half = n / 2;
    for (size_t i = 0; i < n; i++) {
        if (i % 2 == 0)
            arr[i] = (int64_t)(i / 2);
        else
            arr[i] = (int64_t)(half + i / 2);
    }
}

// 10. anti_merge_runs: k runs with maximally overlapping value ranges.
//     Run i contains values [i*stride, i*stride + range) where range > stride.
static void fill_anti_merge_runs(int64_t *arr, size_t n) {
    size_t k = (size_t)sqrt((double)n);
    if (k < 2) k = 2;
    size_t run_len = n / k;
    int64_t stride = (int64_t)(run_len / 2);
    if (stride < 1) stride = 1;
    int64_t range = stride * 3;

    size_t idx = 0;
    for (size_t r = 0; r < k && idx < n; r++) {
        int64_t base_val = (int64_t)r * stride;
        size_t this_len = (r == k - 1) ? (n - idx) : run_len;
        // fill this run as ascending within [base_val, base_val + range)
        for (size_t j = 0; j < this_len && idx < n; j++, idx++) {
            arr[idx] = base_val + (int64_t)((int64_t)j * range / (int64_t)this_len);
        }
    }
}

// ============================================================
// DISTRIBUTION EDGE CASES
// ============================================================

// 11. zipfian: power-law distributed values.
//     Element i gets value floor(n / (rank+1)) where rank is random.
static void fill_zipfian(int64_t *arr, size_t n) {
    for (size_t i = 0; i < n; i++) {
        uint64_t rank = (lcg_next() >> 16) % n;
        arr[i] = (int64_t)(n / (rank + 1));
    }
}

// 12. sqrt_unique: exactly sqrt(n) distinct values, uniformly distributed.
//     Right at the boundary of few-unique detection.
static void fill_sqrt_unique(int64_t *arr, size_t n) {
    size_t num_unique = (size_t)sqrt((double)n);
    if (num_unique < 2) num_unique = 2;
    for (size_t i = 0; i < n; i++)
        arr[i] = (int64_t)((lcg_next() >> 16) % num_unique);
}

// 13. displacement_k: sorted array where every element at position i
//     is swapped with position i + d for d = sqrt(n).
static void fill_displacement_k(int64_t *arr, size_t n) {
    for (size_t i = 0; i < n; i++)
        arr[i] = (int64_t)i;
    size_t d = (size_t)sqrt((double)n);
    if (d < 1) d = 1;
    for (size_t i = 0; i + d < n; i += d) {
        int64_t tmp = arr[i];
        arr[i] = arr[i + d];
        arr[i + d] = tmp;
    }
}

// ============================================================
// ADVERSARIAL STABILITY
// ============================================================

// 14. all_equal_except_endpoints: [INT64_MAX, 0, 0, ..., 0, INT64_MIN].
//     Two elements maximally displaced.
static void fill_all_equal_except_endpoints(int64_t *arr, size_t n) {
    for (size_t i = 0; i < n; i++)
        arr[i] = 0;
    if (n >= 1) arr[0] = INT64_MAX;
    if (n >= 2) arr[n - 1] = INT64_MIN;
}

// 15. organ_of_organs: 8 pipe organ segments concatenated,
//     each segment is a pipe organ of n/8 elements with non-overlapping ranges.
static void fill_organ_of_organs(int64_t *arr, size_t n) {
    size_t num_segments = 8;
    size_t seg_len = n / num_segments;
    if (seg_len < 2) seg_len = 2;

    for (size_t s = 0; s < num_segments && s * seg_len < n; s++) {
        size_t base_idx = s * seg_len;
        size_t len = (s == num_segments - 1) ? (n - base_idx) : seg_len;
        int64_t range_base = (int64_t)s * (int64_t)(seg_len * 2);
        size_t half = len / 2;

        // ascending half
        for (size_t i = 0; i < half; i++)
            arr[base_idx + i] = range_base + (int64_t)i;
        // descending half
        for (size_t i = half; i < len; i++)
            arr[base_idx + i] = range_base + (int64_t)(len - 1 - i);
    }
}

// ============================================================
// McILROY DYNAMIC ADVERSARY (1999)
// ============================================================
//
// Constructs worst-case input DURING sorting by observing which
// comparisons the sort makes. When two "gas" (undecided) elements
// are compared, the one that looks like a pivot candidate gets
// frozen to a low value, maximizing partition imbalance.

static int mcilroy_n;
static int *mcilroy_gas;       // 1 = undecided, 0 = frozen
static int64_t *mcilroy_val;   // assigned values
static int mcilroy_nsolid;     // number of frozen elements
static int mcilroy_candidate;  // current pivot candidate
static size_t mcilroy_ncmp;    // comparison counter

static int mcilroy_cmp(const void *ap, const void *bp) {
    size_t a = ((const int64_t *)ap - mcilroy_val);
    size_t b = ((const int64_t *)bp - mcilroy_val);
    mcilroy_ncmp++;

    if (mcilroy_gas[a] && mcilroy_gas[b]) {
        // Both gas: freeze the candidate (last gas seen)
        if (mcilroy_candidate >= 0 && mcilroy_gas[mcilroy_candidate]) {
            mcilroy_gas[mcilroy_candidate] = 0;
            mcilroy_val[mcilroy_candidate] = mcilroy_nsolid++;
        }
        mcilroy_candidate = (int)a;
    }
    if (mcilroy_gas[a] && !mcilroy_gas[b]) mcilroy_candidate = (int)a;
    if (!mcilroy_gas[a] && mcilroy_gas[b]) mcilroy_candidate = (int)b;

    // Compare: frozen elements by assigned value, gas elements are "equal"
    int64_t va = mcilroy_gas[a] ? mcilroy_n : mcilroy_val[a];
    int64_t vb = mcilroy_gas[b] ? mcilroy_n : mcilroy_val[b];
    return (va > vb) - (va < vb);
}

static void test_mcilroy_adversary(void) {
    static const size_t mcilroy_sizes[] = {1000, 10000, 100000};
    int num_sizes = 3;

    printf("\n  --- McIlroy dynamic adversary ---\n");

    for (int si = 0; si < num_sizes; si++) {
        size_t n = mcilroy_sizes[si];
        char name[128];
        snprintf(name, sizeof(name), "mcilroy_adversary (n=%zu)", n);

        // Allocate state
        mcilroy_n = (int)n;
        mcilroy_gas = (int *)malloc(n * sizeof(int));
        mcilroy_val = (int64_t *)malloc(n * sizeof(int64_t));
        assert(mcilroy_gas && mcilroy_val);

        // Initialize: all elements are gas, values are placeholders
        for (size_t i = 0; i < n; i++) {
            mcilroy_gas[i] = 1;
            mcilroy_val[i] = 0;
        }
        mcilroy_nsolid = 0;
        mcilroy_candidate = -1;
        mcilroy_ncmp = 0;

        // Sort using the generic comparator interface -- the adversary
        // observes comparisons and freezes pivot candidates to low values
        sublimation(mcilroy_val, n, sizeof(int64_t), mcilroy_cmp);

        // Freeze any remaining gas elements
        for (size_t i = 0; i < n; i++) {
            if (mcilroy_gas[i]) {
                mcilroy_gas[i] = 0;
                mcilroy_val[i] = mcilroy_nsolid++;
            }
        }

        // Verify output is sorted
        int sorted_ok = 1;
        for (size_t i = 1; i < n; i++) {
            if (mcilroy_val[i] < mcilroy_val[i - 1]) {
                sorted_ok = 0;
                break;
            }
        }

        // O(n^2) detector: comparisons must be < n * log2(n) * 4
        double log2n = log2((double)n);
        size_t bound = (size_t)((double)n * log2n * 4.0);
        int cmp_ok = mcilroy_ncmp <= bound;

        if (sorted_ok && cmp_ok) {
            printf("  %-50s PASS  (cmps=%zu, bound=%zu)\n", name, mcilroy_ncmp, bound);
            _verify_pass++;
        } else {
            if (!sorted_ok) {
                fprintf(stderr, "  [FAIL] %s: output not sorted\n", name);
            }
            if (!cmp_ok) {
                fprintf(stderr, "  [FAIL] %s: too many comparisons: %zu > %zu (possible O(n^2))\n",
                        name, mcilroy_ncmp, bound);
            }
            _verify_fail++;
        }

        free(mcilroy_gas);
        free(mcilroy_val);
    }
}

// ============================================================
// COMPARISON BOUND ENFORCEMENT
// ============================================================
//
// Uses sublimation_i64_stats() to get exact comparison counts.
// Enforces comparisons <= n * ceil(log2(n)) * 3 on adversarial
// patterns. This is a noise-free O(n^2) regression detector.

typedef struct {
    const char *name;
    fill_fn filler;
} bound_pattern_t;

static void test_comparison_bounds(void) {
    static const size_t bound_sizes[] = {10000, 100000};
    int num_sizes = 2;

    bound_pattern_t patterns[] = {
        {"random",                NULL},
        {"sorted_random_splice",  fill_sorted_random_splice},
        {"ascending_sawtooth",    fill_ascending_sawtooth},
        {"pipe_organ_nested",     fill_pipe_organ_nested},
        {"median_of_three_killer", fill_median_of_three_killer},
        {"interleaved_sorted",    fill_interleaved_sorted},
    };
    int num_patterns = (int)(sizeof(patterns) / sizeof(patterns[0]));

    printf("\n  --- Comparison bound enforcement ---\n");

    for (int pi = 0; pi < num_patterns; pi++) {
        for (int si = 0; si < num_sizes; si++) {
            size_t n = bound_sizes[si];
            char name[128];
            snprintf(name, sizeof(name), "cmp_bound/%s (n=%zu)", patterns[pi].name, n);

            int64_t *arr = (int64_t *)malloc(n * sizeof(int64_t));
            assert(arr && "malloc failed");

            lcg_seed(0xB0D4D000ull ^ (uint64_t)n ^ (uint64_t)pi);

            if (patterns[pi].filler) {
                patterns[pi].filler(arr, n);
            } else {
                // "random" pattern
                for (size_t i = 0; i < n; i++)
                    arr[i] = (int64_t)(lcg_next() >> 16);
            }

            int64_t *saved = verify_save(arr, n);

            sub_stats_t stats = {0};
            sublimation_i64_stats(arr, n, &stats);

            // Verify correctness first
            int sorted_ok = verify_sorted(arr, n, name);
            int perm_ok = saved ? verify_permutation(arr, saved, n, name) : 1;

            // Enforce comparison bound: n * ceil(log2(n)) * 3
            double log2n = ceil(log2((double)n));
            uint64_t bound = (uint64_t)((double)n * log2n * 3.0);

            if (sorted_ok && perm_ok) {
                if (stats.comparisons <= bound) {
                    printf("  %-50s PASS  (cmps=%lu, bound=%lu)\n",
                           name, (unsigned long)stats.comparisons, (unsigned long)bound);
                    _verify_pass++;
                } else {
                    fprintf(stderr, "  [FAIL] %s: comparisons %lu > bound %lu (possible O(n^2))\n",
                            name, (unsigned long)stats.comparisons, (unsigned long)bound);
                    _verify_fail++;
                }
            }
            // If sort correctness failed, verify_sorted/verify_permutation already
            // incremented _verify_fail, so we don't double-count.

            free(saved);
            free(arr);
        }
    }
}

// ============================================================
// MAIN
// ============================================================

int main(void) {
    printf("[sublimation] adversarial correctness tests\n\n");

    // Classifier confusion
    run_pattern("sorted_random_splice", fill_sorted_random_splice);
    run_pattern("ascending_sawtooth", fill_ascending_sawtooth);
    run_pattern("descending_sawtooth", fill_descending_sawtooth);
    run_pattern("plateau_cliff", fill_plateau_cliff);
    run_pattern("sorted_with_periodic_spikes", fill_sorted_with_periodic_spikes);

    // Pivot killers
    run_pattern("pipe_organ_nested", fill_pipe_organ_nested);
    run_pattern("median_of_three_killer", fill_median_of_three_killer);
    run_pattern("repeated_element_noise", fill_repeated_element_noise);

    // Merge pathology
    run_pattern("interleaved_sorted", fill_interleaved_sorted);
    run_pattern("anti_merge_runs", fill_anti_merge_runs);

    // Distribution edge cases
    run_pattern("zipfian", fill_zipfian);
    run_pattern("sqrt_unique", fill_sqrt_unique);
    run_pattern("displacement_k", fill_displacement_k);

    // Adversarial stability
    run_pattern("all_equal_except_endpoints", fill_all_equal_except_endpoints);
    run_pattern("organ_of_organs", fill_organ_of_organs);

    // McIlroy dynamic adversary
    test_mcilroy_adversary();

    // Comparison bound enforcement
    test_comparison_bounds();

    printf("\n  adversarial: %d passed, %d failed\n", _verify_pass, _verify_fail);
    return _verify_fail > 0 ? 1 : 0;
}
