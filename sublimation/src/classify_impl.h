// classify_impl.h -- Template body for classification (included once per type)
//
// Requires SUB_TYPE and SUB_SUFFIX to be defined before inclusion.
// E.g. #define SUB_TYPE int64_t / #define SUB_SUFFIX _i64

// ---------- AVX2 VECTORIZED SORTED/REVERSED DETECTION (int64_t only) ----------
// Defined once (guarded) as concrete int64_t functions.  Called from the
// templated sub_classify_internal via a compile-time sizeof+signedness gate
// that the compiler constant-folds away for non-i64 instantiations.
#if defined(__AVX2__) && !defined(SUB_CLASSIFY_AVX2_DEFINED)
#define SUB_CLASSIFY_AVX2_DEFINED
#include <immintrin.h>

// Returns true if arr[0..n) is non-decreasing.
// Processes 4 int64s per iteration using _mm256_cmpgt_epi64.
static inline bool sub_avx2_is_sorted_i64(const int64_t *arr, size_t n) {
    if (n <= 1) return true;
    size_t i = 0;
    // SIMD: compare arr[i..i+3] > arr[i+1..i+4]  (detect any descent)
    for (; i + 4 < n; i += 4) {
        __m256i prev = _mm256_loadu_si256((const __m256i *)(arr + i));
        __m256i cur  = _mm256_loadu_si256((const __m256i *)(arr + i + 1));
        __m256i gt   = _mm256_cmpgt_epi64(prev, cur);  // prev[j] > cur[j]
        if (_mm256_movemask_epi8(gt) != 0) return false;
    }
    // Scalar remainder
    for (size_t j = (i > 0 ? i : 1); j < n; j++) {
        if (arr[j] < arr[j - 1]) return false;
    }
    return true;
}

// Returns true if arr[0..n) is non-increasing (fully reversed / descending).
static inline bool sub_avx2_is_reversed_i64(const int64_t *arr, size_t n) {
    if (n <= 1) return true;
    size_t i = 0;
    // Descent = cur > prev  (ascending step violates reversed order)
    for (; i + 4 < n; i += 4) {
        __m256i prev = _mm256_loadu_si256((const __m256i *)(arr + i));
        __m256i cur  = _mm256_loadu_si256((const __m256i *)(arr + i + 1));
        __m256i gt   = _mm256_cmpgt_epi64(cur, prev);  // cur[j] > prev[j]
        if (_mm256_movemask_epi8(gt) != 0) return false;
    }
    for (size_t j = (i > 0 ? i : 1); j < n; j++) {
        if (arr[j] > arr[j - 1]) return false;
    }
    return true;
}

// Returns true if every element equals arr[0].
static inline bool sub_avx2_is_equal_i64(const int64_t *arr, size_t n) {
    if (n <= 1) return true;
    __m256i ref = _mm256_set1_epi64x(arr[0]);
    size_t i = 0;
    for (; i + 4 <= n; i += 4) {
        __m256i v  = _mm256_loadu_si256((const __m256i *)(arr + i));
        // XOR with ref: any non-zero lane means mismatch
        __m256i diff = _mm256_xor_si256(v, ref);
        if (!_mm256_testz_si256(diff, diff)) return false;
    }
    for (; i < n; i++) {
        if (arr[i] != arr[0]) return false;
    }
    return true;
}
#endif // __AVX2__ && !SUB_CLASSIFY_AVX2_DEFINED

// PATIENCE SORTING (Robinson-Schensted first row)
// Returns LIS length. If pile_sizes_out is non-NULL, fills it with pile sizes
// (conjugate partition lambda'). max_pile_size_out receives the LDS length.
static size_t SUB_TYPED(patience_sort_lis_full)(const SUB_TYPE *arr, size_t n,
                                                 size_t *pile_sizes_out,
                                                 size_t *max_pile_size_out) {
    if (n <= 1) {
        if (pile_sizes_out && n == 1) pile_sizes_out[0] = 1;
        if (max_pile_size_out) *max_pile_size_out = n;
        return n;
    }

    SUB_TYPE *pile_tops = malloc(n * sizeof(SUB_TYPE));
    if (sub_unlikely(!pile_tops)) return 1;

    // Allocate pile_sizes alongside pile_tops (always, it's cheap)
    size_t *pile_sizes = calloc(n, sizeof(size_t));
    if (sub_unlikely(!pile_sizes)) {
        free(pile_tops);
        return 1;
    }

    size_t num_piles = 0;
    size_t max_pile = 0;

    for (size_t i = 0; i < n; i++) {
        SUB_TYPE val = arr[i];

        size_t lo = 0, hi = num_piles;
        while (lo < hi) {
            size_t mid = lo + (hi - lo) / 2;
            if (pile_tops[mid] < val) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }

        pile_tops[lo] = val;
        pile_sizes[lo]++;
        if (pile_sizes[lo] > max_pile) {
            max_pile = pile_sizes[lo];
        }
        if (lo == num_piles) {
            num_piles++;
        }
    }

    // Copy pile sizes out if requested
    if (pile_sizes_out) {
        for (size_t j = 0; j < num_piles; j++) {
            pile_sizes_out[j] = pile_sizes[j];
        }
    }
    if (max_pile_size_out) {
        *max_pile_size_out = max_pile;
    }

    free(pile_tops);
    free(pile_sizes);
    return num_piles;
}

// Backward-compatible wrapper: just returns LIS length
static size_t SUB_TYPED(patience_sort_lis)(const SUB_TYPE *arr, size_t n) {
    return SUB_TYPED(patience_sort_lis_full)(arr, n, NULL, NULL);
}

// HOOK LENGTH FORMULA (information-theoretic bound)
// Computes log2(f^lambda) where f^lambda = n! / prod h(i,j)
// pile_sizes = column lengths from patience sort (NOT necessarily sorted)
// num_piles = lambda_1 (number of columns = LIS length)
// max_pile = max column length (LDS length = number of rows)
// n = total number of elements
static float SUB_TYPED(hook_length_bound)(const size_t *pile_sizes, size_t num_piles,
                                           size_t max_pile, size_t n) {
    if (n <= 1 || num_piles == 0 || max_pile == 0) return 0.0f;
    if (max_pile > 256 || num_piles > SUB_TABLEAU_MAX_LIS) return 0.0f;

    // Sort pile_sizes into descending order to form a proper partition lambda'
    // (pile sizes from patience sort may not be monotonically decreasing)
    size_t col_lengths[256];
    for (size_t j = 0; j < num_piles; j++) {
        col_lengths[j] = pile_sizes[j];
    }
    // Simple insertion sort -- num_piles <= 256
    for (size_t i = 1; i < num_piles; i++) {
        size_t key = col_lengths[i];
        size_t j = i;
        while (j > 0 && col_lengths[j - 1] < key) {
            col_lengths[j] = col_lengths[j - 1];
            j--;
        }
        col_lengths[j] = key;
    }

    // Now col_lengths is lambda' in descending order.
    // Compute row lengths lambda from the conjugate:
    // lambda_i = |{j : col_lengths[j] >= i+1}|
    // Since col_lengths is sorted descending, this is a simple scan.
    size_t row_lengths[256];
    for (size_t i = 0; i < max_pile; i++) {
        size_t count = 0;
        for (size_t j = 0; j < num_piles; j++) {
            if (col_lengths[j] >= i + 1) count++;
            else break;  // sorted descending, so no more will qualify
        }
        row_lengths[i] = count;
    }

    // log2(n!) using Stirling's approximation
    // log2(n!) = n*log2(n) - n*log2(e) + 0.5*log2(2*pi*n)
    double log2_n_fact;
    if (n <= 1) {
        log2_n_fact = 0.0;
    } else {
        double dn = (double)n;
        log2_n_fact = dn * log2(dn) - dn * 1.4426950408889634 + 0.5 * log2(6.283185307179586 * dn);
    }

    // Sum log2(h(i,j)) over all cells (i,j) in the Young diagram
    // Iterate row i, column j within that row
    // h(i,j) = arm(i,j) + leg(i,j) + 1
    // arm(i,j) = row_lengths[i] - j - 1 (cells to the right in row i)
    // leg(i,j) = col_lengths[j] - i - 1 (cells below in column j)
    // Since col_lengths is sorted descending and we iterate j < row_lengths[i],
    // col_lengths[j] >= i+1 is guaranteed, so leg >= 0.
    double sum_log2_hooks = 0.0;
    for (size_t i = 0; i < max_pile; i++) {
        for (size_t j = 0; j < row_lengths[i]; j++) {
            size_t arm = row_lengths[i] - j - 1;
            size_t leg = col_lengths[j] - i - 1;
            size_t hook = arm + leg + 1;
            sum_log2_hooks += log2((double)hook);
        }
    }

    double info_bound = log2_n_fact - sum_log2_hooks;
    if (info_bound < 0.0) info_bound = 0.0;

    return (float)info_bound;
}

// DETECT K-INTERLEAVED SORTED SEQUENCES from tableau shape
// Returns k if the data consists of k interleaved sorted sequences (k <= 8),
// 0 otherwise.
static size_t SUB_TYPED(detect_interleaved)(const size_t *pile_sizes, size_t num_piles,
                                             size_t max_pile, size_t n) {
    // k = number of rows = max_pile (LDS length)
    // For k-interleaved detection: k must be small
    if (max_pile < 2 || max_pile > 8) return 0;
    if (num_piles == 0 || n < max_pile * 2) return 0;

    // Sort pile sizes descending for proper partition computation
    size_t col_lengths[256];
    size_t np = num_piles < 256 ? num_piles : 256;
    for (size_t j = 0; j < np; j++) col_lengths[j] = pile_sizes[j];
    for (size_t i = 1; i < np; i++) {
        size_t key = col_lengths[i];
        size_t j = i;
        while (j > 0 && col_lengths[j - 1] < key) {
            col_lengths[j] = col_lengths[j - 1];
            j--;
        }
        col_lengths[j] = key;
    }

    // Compute row lengths from sorted column lengths
    size_t row_lengths[8];
    for (size_t i = 0; i < max_pile; i++) {
        size_t count = 0;
        for (size_t j = 0; j < np; j++) {
            if (col_lengths[j] >= i + 1) count++;
            else break;
        }
        row_lengths[i] = count;
    }

    // Check if row lengths are balanced (within 2x of each other)
    size_t min_row = row_lengths[0], max_row = row_lengths[0];
    for (size_t i = 1; i < max_pile; i++) {
        if (row_lengths[i] < min_row) min_row = row_lengths[i];
        if (row_lengths[i] > max_row) max_row = row_lengths[i];
    }

    // Balanced: max_row <= 2 * min_row
    if (min_row == 0 || max_row > 2 * min_row) return 0;

    return max_pile;
}

// RUN COUNTING
typedef struct {
    size_t run_count;
    size_t mono_count;
    size_t max_run_len;
    int64_t max_descent_gap;
    bool   is_sorted;
    bool   is_reversed;
} SUB_TYPED(sub_run_info_t);

static SUB_TYPED(sub_run_info_t) SUB_TYPED(count_runs)(const SUB_TYPE *arr, size_t n) {
    SUB_TYPED(sub_run_info_t) info = {
        .run_count = 1,
        .mono_count = 1,
        .max_run_len = 1,
        .max_descent_gap = 0,
        .is_sorted = true,
        .is_reversed = (n >= 2),
    };

    if (n < 2) return info;

    size_t current_run = 1;
    bool current_ascending = (arr[1] >= arr[0]);

    for (size_t i = 1; i < n; i++) {
        bool ascending = (arr[i] >= arr[i - 1]);
        bool descending = (arr[i] < arr[i - 1]);

        if (descending) {
            info.is_sorted = false;
            int64_t gap;
            if (sizeof(SUB_TYPE) <= 4) {
                gap = (int64_t)(arr[i - 1] - arr[i]);
            } else {
                double d = (double)arr[i - 1] - (double)arr[i];
                gap = (d >= 0.0 && d <= (double)INT64_MAX) ? (int64_t)d : INT64_MAX;
            }
            if (gap > info.max_descent_gap) info.max_descent_gap = gap;
        }
        if (ascending)  info.is_reversed = false;

        if (ascending == current_ascending) {
            current_run++;
        } else {
            if (current_run > info.max_run_len) {
                info.max_run_len = current_run;
            }
            info.mono_count++;
            if (ascending) {
                info.run_count++;
            }
            current_ascending = ascending;
            current_run = 1;
        }

        if (descending && i > 1 && arr[i - 1] >= arr[i - 2]) {
            // transitioning from ascending to descending
        }
    }

    if (current_run > info.max_run_len) {
        info.max_run_len = current_run;
    }

    info.run_count = 1;
    for (size_t i = 1; i < n; i++) {
        if (arr[i] < arr[i - 1]) {
            while (i < n && arr[i] < arr[i - 1]) i++;
            if (i < n) info.run_count++;
        }
    }

    return info;
}

// SAMPLED INVERSION RATIO
static float SUB_TYPED(sample_inversion_ratio)(const SUB_TYPE *arr, size_t n) {
    if (n < 2) return 0.0f;

    size_t sample_count = SUB_CLASSIFY_SAMPLE;
    if (sample_count > n * (n - 1) / 2) {
        sample_count = n * (n - 1) / 2;
    }

    size_t inversions = 0;
    uint64_t rng = 0x5DEECE66Dull ^ (uint64_t)n;

    for (size_t k = 0; k < sample_count; k++) {
        rng = rng * 6364136223846793005ull + 1442695040888963407ull;
        size_t i = (size_t)(rng >> 33) % n;
        rng = rng * 6364136223846793005ull + 1442695040888963407ull;
        size_t j = (size_t)(rng >> 33) % n;

        if (i == j) continue;
        if (i > j) { size_t tmp = i; i = j; j = tmp; }
        if (arr[i] > arr[j]) inversions++;
    }

    return (float)inversions / (float)sample_count;
}

// DISTINCT VALUE ESTIMATE
static size_t SUB_TYPED(estimate_distinct)(const SUB_TYPE *arr, size_t n) {
    SUB_CONSTEXPR size_t MAX_SAMPLE = 64;
    size_t sample_n = n < MAX_SAMPLE ? n : MAX_SAMPLE;

    SUB_TYPE sample[64];
    size_t stride = n / sample_n;
    if (stride < 1) stride = 1;

    for (size_t i = 0; i < sample_n; i++) {
        sample[i] = arr[i * stride];
    }

    for (size_t i = 1; i < sample_n; i++) {
        SUB_TYPE key = sample[i];
        size_t j = i;
        while (j > 0 && sample[j - 1] > key) {
            sample[j] = sample[j - 1];
            j--;
        }
        sample[j] = key;
    }

    size_t distinct = 1;
    for (size_t i = 1; i < sample_n; i++) {
        if (sample[i] != sample[i - 1]) distinct++;
    }

    size_t estimate = (distinct * n) / sample_n;
    if (estimate > n) estimate = n;
    return estimate;
}

// CUSUM PHASE BOUNDARY DETECTION
static size_t SUB_TYPED(detect_phase_boundary)(const SUB_TYPE *arr, size_t n) {
    if (n < 64) return 0;

    SUB_CONSTEXPR size_t WINDOW = 32;
    float cusum = 0.0f;
    float baseline = 0.0f;
    bool have_baseline = false;

    for (size_t i = WINDOW; i < n; i += WINDOW / 2) {
        size_t inv = 0;
        size_t end = i + WINDOW < n ? i + WINDOW : n;
        for (size_t j = i; j + 1 < end; j++) {
            if (arr[j] > arr[j + 1]) inv++;
        }
        float rate = (float)inv / (float)(end - i);

        if (!have_baseline) {
            baseline = rate;
            have_baseline = true;
            continue;
        }

        float deviation = rate - baseline - SUB_CUSUM_K;
        if (deviation > 0.0f) {
            cusum += deviation;
        } else {
            cusum *= 0.5f;
        }

        if (cusum > SUB_CUSUM_H) {
            return i;
        }

        baseline = 0.9f * baseline + 0.1f * rate;
    }

    return 0;
}

// COMPUTE TABLEAU FIELDS from pile sizes (helper)
// Fills profile's lds_length, info_theoretic_bound, interleave_k
static void SUB_TYPED(compute_tableau_fields)(sub_profile_t *p,
                                               const size_t *pile_sizes, size_t num_piles,
                                               size_t max_pile, size_t n) {
    p->lds_length = max_pile;

    // Hook length bound: only for bounded inputs
    if (n <= SUB_TABLEAU_MAX_N && num_piles <= SUB_TABLEAU_MAX_LIS && max_pile <= 256) {
        p->info_theoretic_bound = SUB_TYPED(hook_length_bound)(pile_sizes, num_piles, max_pile, n);
    }

    // K-interleaved detection
    p->interleave_k = SUB_TYPED(detect_interleaved)(pile_sizes, num_piles, max_pile, n);
}

// FULL PATIENCE SORT WITH TABLEAU (wrapper that manages pile_sizes buffer)
// Calls patience_sort_lis_full, then computes tableau fields on the profile.
static void SUB_TYPED(patience_sort_with_tableau)(const SUB_TYPE *arr, size_t n, sub_profile_t *p) {
    // Allocate pile_sizes on stack if small, heap otherwise
    size_t pile_buf_stack[256];
    size_t *pile_sizes = pile_buf_stack;
    bool heap_alloc = false;

    if (n > 256) {
        pile_sizes = calloc(n, sizeof(size_t));
        if (!pile_sizes) {
            // Fallback: just get LIS length, no tableau
            p->lis_length = SUB_TYPED(patience_sort_lis)(arr, n);
            return;
        }
        heap_alloc = true;
    } else {
        for (size_t i = 0; i < 256; i++) pile_buf_stack[i] = 0;
    }

    size_t max_pile = 0;
    p->lis_length = SUB_TYPED(patience_sort_lis_full)(arr, n, pile_sizes, &max_pile);

    SUB_TYPED(compute_tableau_fields)(p, pile_sizes, p->lis_length, max_pile, n);

    if (heap_alloc) free(pile_sizes);
}

// ROTATED SORTED ARRAY DETECTION
// Returns the rotation point (single descent index) if array is a rotation
// of a sorted array, or 0 if not.
static size_t SUB_TYPED(detect_rotation)(const SUB_TYPE *arr, size_t n) {
    if (n < 3) return 0;

    // Find descents -- a rotated sorted array has exactly 1 descent
    size_t descent_count = 0;
    size_t descent_pos = 0;
    for (size_t i = 1; i < n; i++) {
        if (arr[i] < arr[i - 1]) {
            descent_count++;
            descent_pos = i;
            if (descent_count > 1) return 0;
        }
    }

    // Exactly 1 descent and the wraparound is valid (arr[n-1] <= arr[0])
    if (descent_count == 1 && arr[n - 1] <= arr[0]) {
        return descent_pos;
    }

    return 0;
}

// FULL CLASSIFICATION
sub_profile_t SUB_TYPED(sub_classify_internal)(const SUB_TYPE *arr, size_t n) {
    sub_profile_t p = {
        .n = n,
        .disorder = SUB_RANDOM,
    };

    if (n <= 1) {
        p.disorder = SUB_SORTED;
        p.lis_length = n;
        p.lds_length = n;
        p.run_count = 1;
        p.mono_count = 1;
        p.max_run_len = n;
        return p;
    }

    // --- AVX2 fast-path: detect sorted/reversed/equal in ~0.25 cycles/element ---
    // Compile-time gate: _Generic resolves to 1 only for int64_t, constant-folded
    // to eliminate dead code for all other type instantiations (including double).
#ifdef __AVX2__
    if (_Generic((SUB_TYPE)0, int64_t: 1, default: 0) && n >= 8) {
        const int64_t *a64 = (const int64_t *)(const void *)arr;
        // All-equal check (cheapest -- single broadcast + XOR)
        if (a64[0] == a64[n - 1] && sub_avx2_is_equal_i64(a64, n)) {
            p.disorder = SUB_SORTED;
            p.lis_length = n;
            p.lds_length = n;
            p.run_count = 1;
            p.mono_count = 1;
            p.max_run_len = n;
            return p;
        }
        // Sorted (non-decreasing)
        if (a64[0] <= a64[n - 1] && sub_avx2_is_sorted_i64(a64, n)) {
            p.disorder = SUB_SORTED;
            p.lis_length = n;
            p.lds_length = 1;
            p.run_count = 1;
            p.mono_count = 1;
            p.max_run_len = n;
            return p;
        }
        // Reversed (non-increasing)
        if (a64[0] >= a64[n - 1] && sub_avx2_is_reversed_i64(a64, n)) {
            p.disorder = SUB_REVERSED;
            p.lis_length = 1;
            p.lds_length = n;
            p.run_count = 1;
            p.mono_count = 1;
            p.max_run_len = n;
            return p;
        }
    }
#endif // __AVX2__

    SUB_TYPED(sub_run_info_t) runs = SUB_TYPED(count_runs)(arr, n);
    p.run_count = runs.run_count;
    p.mono_count = runs.mono_count;
    p.max_run_len = runs.max_run_len;
    p.max_descent_gap = runs.max_descent_gap;

    if (runs.is_sorted) {
        p.disorder = SUB_SORTED;
        p.lis_length = n;
        p.lds_length = 1;
        return p;
    }

    if (runs.is_reversed) {
        p.disorder = SUB_REVERSED;
        p.lis_length = 1;
        p.lds_length = n;
        return p;
    }

    // Rotated sorted array detection (exactly 2 runs)
    if (runs.run_count == 2) {
        size_t rot = SUB_TYPED(detect_rotation)(arr, n);
        if (rot > 0) {
            p.disorder = SUB_NEARLY_SORTED;
            p.lis_length = n - 1;  // all but the rotation break
            p.lds_length = 2;
            p.rotation_point = rot;
            return p;
        }
    }

    if (runs.run_count > n / 4) {
        p.disorder = SUB_RANDOM;
        // Fall through to patience sort below for full tableau
    } else if (runs.run_count < n / 8 && runs.max_run_len > n / 2) {
        p.disorder = SUB_NEARLY_SORTED;
        p.lis_length = runs.max_run_len;
        // Still do patience sort for tableau if within bounds
        if (n >= SUB_PATIENCE_THRESHOLD && n <= SUB_TABLEAU_MAX_N) {
            SUB_TYPED(patience_sort_with_tableau)(arr, n, &p);
        }
        return p;
    }

    p.inversion_ratio = SUB_TYPED(sample_inversion_ratio)(arr, n);
    p.distinct_estimate = SUB_TYPED(estimate_distinct)(arr, n);

    if (p.inversion_ratio < 0.05f && p.run_count <= n / 16) {
        p.disorder = SUB_NEARLY_SORTED;
        if (p.run_count <= 16 && n >= SUB_PATIENCE_THRESHOLD) {
            SUB_TYPED(patience_sort_with_tableau)(arr, n, &p);
        } else {
            p.lis_length = n - (size_t)(p.inversion_ratio * (float)n);
        }
        // If interleaved sequences detected with k <= 4, use k-way merge hint
        if (p.interleave_k >= 2 && p.interleave_k <= 4) {
            p.disorder = SUB_NEARLY_SORTED;
        }
        return p;
    }

    if (p.distinct_estimate <= n / 4) {
        p.disorder = SUB_FEW_UNIQUE;
        if (n >= SUB_PATIENCE_THRESHOLD) {
            SUB_TYPED(patience_sort_with_tableau)(arr, n, &p);
        }
        return p;
    }

    p.phase_boundary = SUB_TYPED(detect_phase_boundary)(arr, n);
    if (p.phase_boundary > 0) {
        bool prefix_sorted = true;
        for (size_t i = 1; i < p.phase_boundary; i++) {
            if (arr[i] < arr[i - 1]) {
                prefix_sorted = false;
                break;
            }
        }
        if (prefix_sorted) {
            p.disorder = SUB_PHASED;
        } else {
            p.phase_boundary = 0;
        }
    }

    // Skip patience sort in sort-path classification — it's O(n log k) with
    // malloc overhead and the tableau doesn't change routing decisions for
    // already-classified data. The public sublimation_classify_*() wrapper
    // computes the tableau on demand for users who want the diagnostic.
    p.lis_length = (size_t)((1.0f - p.inversion_ratio) * (float)n);
    if (p.lis_length < 1) p.lis_length = 1;

    if (p.disorder == SUB_RANDOM && p.lis_length > n * 3 / 4) {
        p.disorder = SUB_NEARLY_SORTED;
    }

    // If k-interleaved detected with k <= 4, override to NEARLY_SORTED for merge routing
    if (p.interleave_k >= 2 && p.interleave_k <= 4 && p.disorder == SUB_RANDOM) {
        p.disorder = SUB_NEARLY_SORTED;
    }

    return p;
}
