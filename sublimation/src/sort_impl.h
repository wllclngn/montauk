// sort_impl.h -- Template body for the main sort (included once per type)
//
// Requires SUB_TYPE and SUB_SUFFIX to be defined before inclusion.

// Reverse an array in-place
static void SUB_TYPED(reverse)(SUB_TYPE *arr, size_t n) {
    size_t lo = 0, hi = n - 1;
    while (lo < hi) {
        SUB_SWAP(SUB_TYPE, arr[lo], arr[hi]);
        lo++;
        hi--;
    }
}

// COUNTING SORT FOR FEW UNIQUE VALUES
#ifndef COUNTING_SORT_MAX_K
#define COUNTING_SORT_MAX_K 64
#endif

// AC-3 constraint propagation: O(1) bucket resolution
//
// For k <= 8: branchless comparison chain.
// Returns the sorted rank of val among the k distinct values.
// Compiles to CMOVcc/ADD — zero branch mispredictions, pipeline never stalls.
static size_t SUB_TYPED(find_bucket_small)(SUB_TYPE val, const SUB_TYPE *uniq, size_t k) {
    size_t idx = 0;
    for (size_t j = 0; j < k; j++) {
        idx += (val > uniq[j]);
    }
    return idx;
}

// For k = 9..64: minimal hash table with linear probing.
// 128-entry table (power of 2, ~2x overprovisioned for k<=64).
// Stack-allocated by caller (~3KB).
#ifndef COUNTING_SORT_HASH_SIZE
#define COUNTING_SORT_HASH_SIZE 128
#define COUNTING_SORT_HASH_MASK (COUNTING_SORT_HASH_SIZE - 1)
#endif

typedef struct {
    SUB_TYPE key;
    size_t   bucket;
    bool     occupied;
} SUB_TYPED(hash_entry_t);

// Type-safe hash: memcpy to uint32/uint64 to avoid UB with float/double.
static inline uint64_t SUB_TYPED(hash_val)(SUB_TYPE val) {
    uint64_t bits;
    if (sizeof(SUB_TYPE) <= 4) {
        uint32_t tmp;
        memcpy(&tmp, &val, sizeof(uint32_t));
        bits = (uint64_t)tmp;
    } else {
        memcpy(&bits, &val, sizeof(uint64_t));
    }
    return (bits * 0x9E3779B97F4A7C15ull) >> 57;
}

// Bit-level equality: handles NaN correctly (NaN != NaN by IEEE 754,
// but memcmp of the bit pattern terminates and matches identical NaNs).
static inline bool SUB_TYPED(key_eq)(SUB_TYPE a, SUB_TYPE b) {
    return memcmp(&a, &b, sizeof(SUB_TYPE)) == 0;
}

static void SUB_TYPED(build_hash)(SUB_TYPED(hash_entry_t) *table,
                                   const SUB_TYPE *uniq, size_t k) {
    memset(table, 0, COUNTING_SORT_HASH_SIZE * sizeof(SUB_TYPED(hash_entry_t)));
    for (size_t i = 0; i < k; i++) {
        uint64_t h = SUB_TYPED(hash_val)(uniq[i]) & COUNTING_SORT_HASH_MASK;
        while (table[h].occupied) h = (h + 1) & COUNTING_SORT_HASH_MASK;
        table[h].key      = uniq[i];
        table[h].bucket   = i;
        table[h].occupied = true;
    }
}

static size_t SUB_TYPED(find_bucket_hash)(const SUB_TYPED(hash_entry_t) *table,
                                           SUB_TYPE val) {
    uint64_t h = SUB_TYPED(hash_val)(val) & COUNTING_SORT_HASH_MASK;
    // Bit equality: terminates for NaN where != would loop forever
    while (!SUB_TYPED(key_eq)(table[h].key, val)) h = (h + 1) & COUNTING_SORT_HASH_MASK;
    return table[h].bucket;
}

static bool SUB_TYPED(counting_sort_few_unique)(SUB_TYPE *arr, size_t n,
                                                 uint64_t *comparisons,
                                                 uint64_t *swaps) {
    SUB_TYPE uniq[COUNTING_SORT_MAX_K];
    size_t  histogram[COUNTING_SORT_MAX_K];
    size_t k = 0;

    // Early-exit probe: after 64 elements, if k==1 (all equal), bail.
    // The classifier's O(n) sorted-detection is faster for equal data.
    #ifndef COUNTING_SORT_PROBE
    #define COUNTING_SORT_PROBE 64
    #endif

    // ── Phase 1: Discovery ──────────────────────────────────────────────
    // Scan all elements to discover distinct values into sorted uniq[].
    // Binary search is fine here: O(n log k) but k <= 64 so log k <= 6,
    // and new insertions are rare (at most 64 across the entire array).
    for (size_t i = 0; i < n; i++) {
        SUB_TYPE val = arr[i];

        if (i == COUNTING_SORT_PROBE && k == 1) {
            return false;
        }

        size_t lo = 0, hi = k;
        while (lo < hi) {
            size_t mid = lo + (hi - lo) / 2;
            if (uniq[mid] < val) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }

        if (lo < k && SUB_TYPED(key_eq)(uniq[lo], val)) {
            continue;  // already known — skip (no counting in this phase)
        }

        if (k >= COUNTING_SORT_MAX_K) {
            return false;
        }

        // Insert new distinct value into sorted position
        for (size_t j = k; j > lo; j--) {
            uniq[j] = uniq[j - 1];
        }
        uniq[lo] = val;
        k++;
    }

    if (k <= 1) return true;

    // ── Phase 2: Histogram (O(1) per element) ──────────────────────────
    memset(histogram, 0, k * sizeof(size_t));

    if (k <= 8) {
        // Branchless comparison chain: zero branch mispredictions.
        // For k=8, that's 8 comparisons per element compiled to ADD —
        // the CPU pipeline never stalls.
        for (size_t i = 0; i < n; i++) {
            size_t bucket = SUB_TYPED(find_bucket_small)(arr[i], uniq, k);
            histogram[bucket]++;
        }
    } else {
        // Hash table: O(1) amortized with fibonacci hashing.
        SUB_TYPED(hash_entry_t) htable[COUNTING_SORT_HASH_SIZE];
        SUB_TYPED(build_hash)(htable, uniq, k);
        for (size_t i = 0; i < n; i++) {
            size_t bucket = SUB_TYPED(find_bucket_hash)(htable, arr[i]);
            histogram[bucket]++;
        }
    }

    // ── Phase 3: Scatter ────────────────────────────────────────────────
    size_t write = 0;
    for (size_t j = 0; j < k; j++) {
        size_t count = histogram[j];
        SUB_TYPE val = uniq[j];
        size_t c = 0;
        for (; c + 4 <= count; c += 4) {
            arr[write]     = val;
            arr[write + 1] = val;
            arr[write + 2] = val;
            arr[write + 3] = val;
            write += 4;
        }
        for (; c < count; c++) {
            arr[write++] = val;
        }
        *swaps += count;
    }

    (void)comparisons;
    return true;
}

// LIGHTWEIGHT QUICKSORT
static void SUB_TYPED(light_insertion_sort)(SUB_TYPE *arr, size_t n) {
    for (size_t i = 1; i < n; i++) {
        SUB_TYPE key = arr[i];
        size_t j = i;
        while (j > 0 && arr[j - 1] > key) {
            arr[j] = arr[j - 1];
            j--;
        }
        arr[j] = key;
    }
}

static void SUB_TYPED(light_siftdown)(SUB_TYPE *arr, size_t root, size_t n) {
    while (2 * root + 1 < n) {
        size_t child = 2 * root + 1;
        if (child + 1 < n && arr[child] < arr[child + 1]) child++;
        if (arr[root] >= arr[child]) break;
        SUB_SWAP(SUB_TYPE, arr[root], arr[child]);
        root = child;
    }
}

static void SUB_TYPED(light_heapsort)(SUB_TYPE *arr, size_t n) {
    if (n < 2) return;
    for (size_t i = n / 2; i > 0; i--) SUB_TYPED(light_siftdown)(arr, i - 1, n);
    for (size_t i = n - 1; i > 0; i--) {
        SUB_SWAP(SUB_TYPE, arr[0], arr[i]);
        SUB_TYPED(light_siftdown)(arr, 0, i);
    }
}

static void SUB_TYPED(light_qsort)(SUB_TYPE *arr, size_t n, int depth) {
    while (n > 24) {
        if (depth == 0) {
            SUB_TYPED(light_heapsort)(arr, n);
            return;
        }
        depth--;

        size_t mid = n / 2;
        if (arr[0] > arr[mid]) SUB_SWAP(SUB_TYPE, arr[0], arr[mid]);
        if (arr[mid] > arr[n - 1]) SUB_SWAP(SUB_TYPE, arr[mid], arr[n - 1]);
        if (arr[0] > arr[mid]) SUB_SWAP(SUB_TYPE, arr[0], arr[mid]);
        SUB_TYPE pivot = arr[mid];

        size_t i = 0, j = n - 1;
        while (i <= j) {
            while (arr[i] < pivot) i++;
            while (arr[j] > pivot) j--;
            if (i <= j) {
                SUB_SWAP(SUB_TYPE, arr[i], arr[j]);
                i++;
                if (j == 0) break;
                j--;
            }
        }

        if (j + 1 < n - i) {
            SUB_TYPED(light_qsort)(arr, j + 1, depth);
            arr += i;
            n -= i;
        } else {
            SUB_TYPED(light_qsort)(arr + i, n - i, depth);
            n = j + 1;
        }
    }
    SUB_TYPED(light_insertion_sort)(arr, n);
}

static void SUB_TYPED(light_sort)(SUB_TYPE *arr, size_t n) {
    int depth = 0;
    size_t t = n;
    while (t > 1) { t >>= 1; depth++; }
    depth *= 2;
    SUB_TYPED(light_qsort)(arr, n, depth);
}

// BINARY INSERTION SORT
static void SUB_TYPED(binary_isort)(SUB_TYPE *arr, size_t n) {
    for (size_t i = 1; i < n; i++) {
        SUB_TYPE key = arr[i];
        if (key >= arr[i - 1]) continue;
        size_t lo = 0, hi = i;
        while (lo < hi) {
            size_t mid = lo + (hi - lo) / 2;
            if (arr[mid] > key) hi = mid;
            else lo = mid + 1;
        }
        memmove(arr + lo + 1, arr + lo, (i - lo) * sizeof(SUB_TYPE));
        arr[lo] = key;
    }
}

// PARTITION PRIMITIVES
static size_t SUB_TYPED(median_of_three)(SUB_TYPE *arr, size_t a, size_t b, size_t c,
                                          uint64_t *comparisons) {
    *comparisons += 3;
    if (arr[a] > arr[b]) SUB_SWAP(SUB_TYPE, arr[a], arr[b]);
    if (arr[b] > arr[c]) SUB_SWAP(SUB_TYPE, arr[b], arr[c]);
    if (arr[a] > arr[b]) SUB_SWAP(SUB_TYPE, arr[a], arr[b]);
    return b;
}

static size_t SUB_TYPED(choose_pivot)(SUB_TYPE *arr, size_t lo, size_t hi,
                                       uint64_t *comparisons) {
    size_t n = hi - lo + 1;
    size_t mid = lo + n / 2;

    if (n <= SUB_MEDIUM_THRESHOLD) {
        return SUB_TYPED(median_of_three)(arr, lo, mid, hi, comparisons);
    }

    size_t step = n / 8;
    SUB_TYPED(median_of_three)(arr, lo, lo + step, lo + 2 * step, comparisons);
    SUB_TYPED(median_of_three)(arr, mid - step, mid, mid + step, comparisons);
    SUB_TYPED(median_of_three)(arr, hi - 2 * step, hi - step, hi, comparisons);
    return SUB_TYPED(median_of_three)(arr, lo + step, mid, hi - step, comparisons);
}

// LOMCYC PARTITION (cyclic permutation Lomuto, Voultapher / Orson Peters)
//
// Maintains a "gap" — one array slot whose contents are logically held in a
// register. Each iteration does 2 stores: one fills the gap (arr[gap_pos] =
// arr[left]), one places the current element (arr[left] = arr[right]). The
// gap then moves to the position we just read.
//
// The key win over standard branchless Lomuto: the second store (gap fill)
// depends on the PREVIOUS iteration's read pointer (sequential), NOT on the
// write pointer. The serial dependency chain on num_lt is broken, allowing
// the CPU to pipeline iterations.
//
// ipnsort uses this. LLVM libc qsort adopted it for ~2.5x speedup.
static size_t SUB_TYPED(partition_block)(SUB_TYPE *arr, size_t lo, size_t hi,
                                          uint64_t *comparisons, uint64_t *swaps) {
    size_t n = hi - lo + 1;
    if (n < 2) return lo;

    size_t pivot_idx = SUB_TYPED(choose_pivot)(arr, lo, hi, comparisons);
    SUB_TYPE pivot = arr[pivot_idx];

    // Move pivot to end
    SUB_SWAP(SUB_TYPE, arr[pivot_idx], arr[hi]);
    (*swaps)++;

    // Lomcyc over arr[lo..hi-1]. Lift arr[lo] as the initial gap value.
    // Comparison counter is batched at the end to avoid memory dep in hot loop.
    SUB_TYPE gap_val = arr[lo];
    size_t gap_pos = lo;
    size_t num_lt = lo;
    size_t loop_count = 0;

    for (size_t right = lo + 1; right < hi; right++) {
        SUB_TYPE val = arr[right];
        size_t left = num_lt;
        size_t is_lt = (size_t)(val < pivot);

        arr[gap_pos] = arr[left];   // fill gap with arr[left] (no dep on num_lt chain)
        arr[left] = val;             // place current element
        gap_pos = right;             // gap follows sequential read pointer
        num_lt += is_lt;             // commit
        loop_count++;
    }
    *comparisons += loop_count + 1;

    // Finalize: place gap_val (the original arr[lo]) based on its pivot comparison.
    if (gap_val < pivot) {
        arr[gap_pos] = arr[num_lt];
        arr[num_lt] = gap_val;
        num_lt++;
    } else {
        arr[gap_pos] = gap_val;
    }

    // Place pivot at its final position
    SUB_SWAP(SUB_TYPE, arr[num_lt], arr[hi]);
    (*swaps)++;

    return num_lt;
}

// THREE-WAY PARTITION
static void SUB_TYPED(partition_three_way)(SUB_TYPE *arr, size_t lo, size_t hi,
                                            size_t *out_lt, size_t *out_gt,
                                            uint64_t *comparisons, uint64_t *swaps) {
    size_t pivot_idx = SUB_TYPED(choose_pivot)(arr, lo, hi, comparisons);
    SUB_TYPE pivot = arr[pivot_idx];

    size_t lt = lo;
    size_t i = lo;
    size_t gt = hi;

    while (i <= gt) {
        (*comparisons)++;
        if (arr[i] < pivot) {
            SUB_SWAP(SUB_TYPE, arr[lt], arr[i]);
            (*swaps)++;
            lt++;
            i++;
        } else if (arr[i] > pivot) {
            SUB_SWAP(SUB_TYPE, arr[i], arr[gt]);
            (*swaps)++;
            if (gt == 0) break;
            gt--;
        } else {
            i++;
        }
    }

    *out_lt = lt;
    *out_gt = gt;
}

// DFS FRAME
typedef struct {
    size_t        lo;
    size_t        hi;
    sub_disorder_t disorder;
} SUB_TYPED(sub_dfs_frame_t);

// PARTITION + ADAPTIVE MONITOR
static size_t SUB_TYPED(partition_one_level)(SUB_TYPE *arr, size_t lo, size_t hi,
                                              sub_adaptive_t *state, sub_disorder_t *disorder,
                                              size_t *out_lt, size_t *out_gt) {
    size_t n = hi - lo + 1;

    // EQUAL ELEMENT DETECTION
#ifdef SUB_TYPE_IS_I64
    if (*disorder != SUB_FEW_UNIQUE && state->has_last_pivot) {
        size_t mid = lo + n / 2;
        if (arr[mid] == state->last_pivot) {
            *disorder = SUB_FEW_UNIQUE;
        }
    }
#endif

    if (*disorder == SUB_FEW_UNIQUE) {
        SUB_TYPED(partition_three_way)(arr, lo, hi, out_lt, out_gt,
                                       &state->comparisons, &state->swaps);
        state->levels_built++;
        if (*out_lt > lo + 1) state->gap_prunes++;
        return SIZE_MAX;
    }

    size_t pivot_pos = SUB_TYPED(partition_block)(arr, lo, hi,
                                                   &state->comparisons, &state->swaps);
    state->levels_built++;

#ifdef SUB_TYPE_IS_I64
    state->last_pivot = arr[pivot_pos];
    state->has_last_pivot = true;
#endif

    float quality = (float)(pivot_pos - lo) / (float)n;
    if (quality > 0.5f) quality = 1.0f - quality;
    quality *= 2.0f;
    sub_ewma_update(&state->partition_quality_ewma, quality);

    bool degraded = sub_cusum_update(&state->cusum_s, quality,
                                     state->partition_quality_ewma,
                                     state->osc_position);

    sub_oscillator_update(&state->osc_position, &state->osc_velocity, degraded);

    if (sub_unlikely(degraded)) {
        state->rescans++;
        state->cusum_s = 0.0f;

        // spectral fallback (only for i64 currently)
#ifdef SUB_TYPE_IS_I64
        if (!state->spectral_attempted
            && n >= SUB_SPECTRAL_MIN_N && n <= SUB_SPECTRAL_MAX_N) {
            sub_spectral_ws_t *ws = sub_spectral_ws_alloc(n);
            if (ws) {
                sub_spectral_result_t sr = sub_spectral_sort_i64(
                    arr + lo, n, ws, state);
                sub_spectral_ws_free(ws);
                state->spectral_attempted = true;
                if (sr.gap_sufficient && sr.converged) {
                    return pivot_pos;
                }
            }
        }
#endif

        state->rescan_trigger = (size_t)((float)state->rescan_trigger * SUB_RESCAN_GROWTH);
    }

    return pivot_pos;
}

// RECURSIVE DFS
static void SUB_TYPED(push_recursive)(SUB_TYPE *arr, size_t lo, size_t hi,
                                       sub_adaptive_t *state, sub_disorder_t disorder,
                                       int depth) {
    size_t n = hi - lo + 1;

    if (n <= SUB_SMALL_THRESHOLD) {
        SUB_TYPED(sub_small_sort)(arr + lo, n, &state->comparisons, &state->swaps);
        return;
    }

    if (sub_unlikely(depth >= SUB_STACK_LIMIT)) {
        goto SUB_TYPED(iterative);
    }

    {
        sub_disorder_t local_disorder = disorder;
        if (depth > 0 && depth % SUB_RECLASSIFY_INTERVAL == 0 && n > SUB_SMALL_THRESHOLD * 4) {
            sub_profile_t sub = SUB_TYPED(sub_classify_internal)(arr + lo, n);
            if (sub.disorder != disorder) {
                local_disorder = sub.disorder;
                state->rescans++;
            }
        }

        size_t lt, gt;
        size_t pivot = SUB_TYPED(partition_one_level)(arr, lo, hi, state, &local_disorder, &lt, &gt);

        if (pivot == SIZE_MAX) {
            if (lt > lo) SUB_TYPED(push_recursive)(arr, lo, lt - 1, state, local_disorder, depth + 1);
            if (gt < hi) SUB_TYPED(push_recursive)(arr, gt + 1, hi, state, local_disorder, depth + 1);
        } else {
            if (pivot > lo + 1) SUB_TYPED(push_recursive)(arr, lo, pivot - 1, state, local_disorder, depth + 1);
            if (pivot + 1 < hi) SUB_TYPED(push_recursive)(arr, pivot + 1, hi, state, local_disorder, depth + 1);
        }
        return;
    }

SUB_TYPED(iterative):
    {
        SUB_CONSTEXPR size_t MAX_FRAMES = 128;
        SUB_TYPED(sub_dfs_frame_t) stack[128];
        size_t sp = 0;

        stack[sp++] = (SUB_TYPED(sub_dfs_frame_t)){lo, hi, disorder};

        while (sp > 0) {
            SUB_TYPED(sub_dfs_frame_t) frame = stack[--sp];
            size_t fn = frame.hi - frame.lo + 1;

            if (fn <= SUB_SMALL_THRESHOLD) {
                SUB_TYPED(sub_small_sort)(arr + frame.lo, fn,
                                          &state->comparisons, &state->swaps);
                continue;
            }

            size_t lt, gt;
            sub_disorder_t fd = frame.disorder;
            size_t pivot = SUB_TYPED(partition_one_level)(arr, frame.lo, frame.hi,
                                                           state, &fd, &lt, &gt);

            if (pivot == SIZE_MAX) {
                if (gt < frame.hi && sp < MAX_FRAMES) {
                    stack[sp++] = (SUB_TYPED(sub_dfs_frame_t)){gt + 1, frame.hi, fd};
                }
                if (lt > frame.lo && sp < MAX_FRAMES) {
                    stack[sp++] = (SUB_TYPED(sub_dfs_frame_t)){frame.lo, lt - 1, fd};
                }
            } else {
                size_t left_n = pivot > frame.lo ? pivot - frame.lo : 0;
                size_t right_n = pivot < frame.hi ? frame.hi - pivot : 0;

                if (left_n > right_n) {
                    if (left_n > 1 && sp < MAX_FRAMES) {
                        stack[sp++] = (SUB_TYPED(sub_dfs_frame_t)){frame.lo, pivot - 1, fd};
                    }
                    if (right_n > 1 && sp < MAX_FRAMES) {
                        stack[sp++] = (SUB_TYPED(sub_dfs_frame_t)){pivot + 1, frame.hi, fd};
                    }
                } else {
                    if (right_n > 1 && sp < MAX_FRAMES) {
                        stack[sp++] = (SUB_TYPED(sub_dfs_frame_t)){pivot + 1, frame.hi, fd};
                    }
                    if (left_n > 1 && sp < MAX_FRAMES) {
                        stack[sp++] = (SUB_TYPED(sub_dfs_frame_t)){frame.lo, pivot - 1, fd};
                    }
                }
            }
        }
    }
}

// HYBRID DFS SORT
static void SUB_TYPED(push)(SUB_TYPE *arr, size_t lo, size_t hi,
                             sub_adaptive_t *state, sub_disorder_t disorder) {
    SUB_TYPED(push_recursive)(arr, lo, hi, state, disorder, 0);
}

// PHASED SORT
static void SUB_TYPED(sort_phased)(SUB_TYPE *arr, size_t n, size_t boundary,
                                    sub_adaptive_t *state) {
    size_t suffix_len = n - boundary;

    if (boundary > 1) {
        bool prefix_sorted = true;
        for (size_t i = 1; i < boundary; i++) {
            if (arr[i] < arr[i - 1]) { prefix_sorted = false; break; }
        }
        if (!prefix_sorted) {
            SUB_TYPED(push)(arr, 0, boundary - 1, state, SUB_RANDOM);
        }
    }

    if (suffix_len > 1) {
        SUB_TYPED(push)(arr, boundary, n - 1, state, SUB_RANDOM);
    }

    if (arr[boundary - 1] <= arr[boundary]) return;

    // Gallop to find where suffix minimum lands in prefix
    SUB_TYPE key = arr[boundary];
    size_t skip = 0, ofs = 1;
    while (ofs < boundary && arr[ofs] < key) { skip = ofs; ofs = (ofs << 1) + 1; }
    if (ofs > boundary) ofs = boundary;
    while (skip < ofs) {
        size_t mid = skip + (ofs - skip) / 2;
        if (arr[mid] < key) skip = mid + 1; else ofs = mid;
    }
    size_t prefix_overlap = boundary - skip;

    if (prefix_overlap <= suffix_len) {
        SUB_TYPE *tmp = malloc(prefix_overlap * sizeof(SUB_TYPE));
        if (!tmp) {
            SUB_TYPED(sub_spectral_merge)(arr, n, &state->comparisons);
            return;
        }
        memcpy(tmp, arr + skip, prefix_overlap * sizeof(SUB_TYPE));

        size_t a = 0, b = boundary, w = skip;
        while (a < prefix_overlap && b < n) {
            state->comparisons++;
            if (tmp[a] <= arr[b]) arr[w++] = tmp[a++];
            else                   arr[w++] = arr[b++];
        }
        while (a < prefix_overlap) arr[w++] = tmp[a++];
        free(tmp);
    } else {
        SUB_TYPE *tmp = malloc(suffix_len * sizeof(SUB_TYPE));
        if (!tmp) {
            SUB_TYPED(sub_spectral_merge)(arr, n, &state->comparisons);
            return;
        }
        memcpy(tmp, arr + boundary, suffix_len * sizeof(SUB_TYPE));

        size_t a = prefix_overlap;
        size_t b = suffix_len;
        size_t w = n;
        while (a > 0 && b > 0) {
            state->comparisons++;
            if (arr[skip + a - 1] > tmp[b - 1]) arr[--w] = arr[skip + --a];
            else                                  arr[--w] = tmp[--b];
        }
        while (b > 0) arr[--w] = tmp[--b];
        free(tmp);
    }
}

// ROTATED SORTED FIX: O(n) via 3 reverses
// arr[0..rot-1] and arr[rot..n-1] are each sorted, arr[n-1] <= arr[0]
// reverse [0..rot-1], reverse [rot..n-1], reverse [0..n-1]
static void SUB_TYPED(fix_rotation)(SUB_TYPE *arr, size_t n, size_t rot, uint64_t *swaps) {
    if (rot == 0 || rot >= n) return;
    // reverse [0..rot-1]
    for (size_t i = 0, j = rot - 1; i < j; i++, j--) {
        SUB_SWAP(SUB_TYPE, arr[i], arr[j]);
        (*swaps)++;
    }
    // reverse [rot..n-1]
    for (size_t i = rot, j = n - 1; i < j; i++, j--) {
        SUB_SWAP(SUB_TYPE, arr[i], arr[j]);
        (*swaps)++;
    }
    // reverse [0..n-1]
    for (size_t i = 0, j = n - 1; i < j; i++, j--) {
        SUB_SWAP(SUB_TYPE, arr[i], arr[j]);
        (*swaps)++;
    }
}

// INTERNAL SORT ENTRY
void SUB_TYPED(sub_sort_internal)(SUB_TYPE *restrict arr, size_t n, sub_adaptive_t *state) {
    if (n <= 1) return;

    sub_profile_t profile = SUB_TYPED(sub_classify_internal)(arr, n);

    switch (profile.disorder) {
    case SUB_SORTED:
        return;

    case SUB_REVERSED:
        SUB_TYPED(reverse)(arr, n);
        state->swaps += n / 2;
        return;

    case SUB_PHASED:
        SUB_TYPED(sort_phased)(arr, n, profile.phase_boundary, state);
        return;

    case SUB_NEARLY_SORTED:
        // Rotated sorted array: O(n) fix
        if (profile.rotation_point > 0) {
            SUB_TYPED(fix_rotation)(arr, n, profile.rotation_point, &state->swaps);
            return;
        }
        if (profile.run_count <= 16) {
            SUB_TYPED(sub_spectral_merge)(arr, n, &state->comparisons);
        } else {
            size_t sqrt_n = 1;
            while (sqrt_n * sqrt_n < n) sqrt_n++;
            if (profile.max_descent_gap <= (int64_t)sqrt_n) {
                SUB_TYPED(binary_isort)(arr, n);
            } else {
                SUB_TYPED(light_sort)(arr, n);
            }
        }
        return;

    case SUB_FEW_UNIQUE:
        if (SUB_TYPED(counting_sort_few_unique)(arr, n, &state->comparisons, &state->swaps)) {
            return;
        }
        SUB_TYPED(push)(arr, 0, n - 1, state, profile.disorder);
        return;

    case SUB_RANDOM:
#if defined(__AVX2__) && defined(SUB_TYPE_IS_I64)
        // PCF Learned Sort + AVX2 sort-network leaves. See sort.c and
        // research/RANDOM_EXPERIMENTS.md for the bench history.
        if (n >= 64) {
            sub_random_sort_i64(arr, n);
            // Bookkeeping: estimate comparison count for stats consumers
            state->comparisons += (uint64_t)n * 4;
            return;
        }
#endif
        SUB_TYPED(push)(arr, 0, n - 1, state, profile.disorder);
        return;

    case SUB_SPECTRAL:
        SUB_TYPED(push)(arr, 0, n - 1, state, SUB_RANDOM);
        return;
    }

    unreachable();
}

// FAST PATH DISPATCH
// Shared logic for public API and parallel entry. Handles counting sort,
// classification, and fast paths (sorted/reversed/nearly/phased/rotated).
// Returns true if handled, false if caller should proceed with full sort.
static bool SUB_TYPED(fast_path_dispatch)(SUB_TYPE *restrict arr, size_t n,
                                           sub_profile_t *out_profile) {
    // Counting sort: O(n) for k <= 64
    {
        uint64_t cmp = 0, swp = 0;
        if (SUB_TYPED(counting_sort_few_unique)(arr, n, &cmp, &swp)) return true;
    }

    *out_profile = SUB_TYPED(sub_classify_internal)(arr, n);

    if (out_profile->disorder == SUB_SORTED) return true;

    if (out_profile->disorder == SUB_REVERSED) {
        SUB_TYPED(reverse)(arr, n);
        return true;
    }

    if (out_profile->disorder == SUB_NEARLY_SORTED) {
        if (out_profile->rotation_point > 0) {
            uint64_t swp = 0;
            SUB_TYPED(fix_rotation)(arr, n, out_profile->rotation_point, &swp);
            return true;
        }
        if (out_profile->run_count <= 16) {
            uint64_t cmp = 0;
            SUB_TYPED(sub_spectral_merge)(arr, n, &cmp);
        } else {
            size_t sqrt_n = 1;
            while (sqrt_n * sqrt_n < n) sqrt_n++;
            if (out_profile->max_descent_gap <= (int64_t)sqrt_n) {
                SUB_TYPED(binary_isort)(arr, n);
            } else {
                SUB_TYPED(light_sort)(arr, n);
            }
        }
        return true;
    }

    if (out_profile->disorder == SUB_PHASED) {
        sub_adaptive_t state;
        sub_adaptive_init(&state, n);
        SUB_TYPED(sort_phased)(arr, n, out_profile->phase_boundary, &state);
        return true;
    }

#if defined(__AVX2__) && defined(SUB_TYPE_IS_I64)
    // SUB_RANDOM SIMD fast path: skips re-classification in sub_sort_internal.
    // Guarded at SUB_PARALLEL_THRESHOLD so large-n random falls through and
    // the serial entry point can auto-dispatch to sublimation_i64_parallel
    // when >=2 workers are available. The serial entry re-checks workers
    // and falls back to sub_random_sort_i64 if only 1 worker is usable.
    if (out_profile->disorder == SUB_RANDOM && n >= 64 && n < SUB_PARALLEL_THRESHOLD) {
        sub_random_sort_i64(arr, n);
        return true;
    }
#endif

    return false; // caller handles FEW_UNIQUE, SPECTRAL
}

// PUBLIC API ENTRY POINT
void SUB_TYPED(sublimation)(SUB_TYPE *restrict arr, size_t n) {
    if (n <= 1) return;

    sub_profile_t profile;
    if (SUB_TYPED(fast_path_dispatch)(arr, n, &profile)) return;

    // fast_path returned false. For i64, this means either SUB_RANDOM at
    // n >= SUB_PARALLEL_THRESHOLD (fast-path guard lets large random fall
    // through for auto-parallel dispatch), or FEW_UNIQUE past counting_sort,
    // or SPECTRAL.
#ifdef SUB_TYPE_IS_I64
    if (n >= SUB_PARALLEL_THRESHOLD) {
        size_t workers = sub_default_num_workers();
        if (workers >= 2) {
            sublimation_i64_parallel(arr, n, workers);
            return;
        }
        // Only 1 worker available (taskset/cgroup). Restore the AVX2 PCF
        // random expert for large random data -- it is faster than the
        // generic adaptive flow on a single core.
#if defined(__AVX2__)
        if (profile.disorder == SUB_RANDOM && n >= 64) {
            sub_random_sort_i64(arr, n);
            return;
        }
#endif
    }
#endif

    sub_adaptive_t state;
    sub_adaptive_init(&state, n);
    SUB_TYPED(sub_sort_internal)(arr, n, &state);
}
