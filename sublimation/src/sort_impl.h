// sort_impl.h -- Template body for the main sort (included once per type)
//
// Requires SUB_TYPE and SUB_SUFFIX to be defined before inclusion.

// Per-type parallel-radix threshold. Defaults to the shared
// SUB_RADIX_PARALLEL_MIN, so a type that says nothing behaves exactly as it did
// when the constant was read directly. A type whose serial radix has a
// different cache profile defines SUB_RADIX_PAR_MIN_T before including this
// template; it is #undef'd at the bottom so each inclusion re-derives it and
// one type's override cannot leak into the next.
#ifndef SUB_RADIX_PAR_MIN_T
#define SUB_RADIX_PAR_MIN_T SUB_RADIX_PARALLEL_MIN
#define SUB_RADIX_PAR_MIN_T_DEFAULTED
#endif

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

// COMPARISON RANK: branchless bucket resolution, O(k) with k <= 8
//
// Returns the sorted rank of val among the k distinct values -- how many are
// strictly less, which is its bucket index. A flat comparison chain, no
// constraint solver: compiles to CMOVcc/ADD, zero branch mispredictions, the
// pipeline never stalls.
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

    // Phase 1: Discovery
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

    // Phase 2: Histogram (O(1) per element)
    memset(histogram, 0, k * sizeof(size_t));

    // find_bucket_small ranks by value comparison (`>`), which disagrees with
    // discovery's bitwise key_eq for NaN and signed zero: a single NaN then
    // mis-buckets even finite values, silently corrupting the multiset. The hash
    // bucket is bitwise-consistent with discovery, so float types always take it.
    // Integers (value-compare == bitwise) keep the faster branchless path.
#ifdef SUB_TYPE_IS_FLOAT
    const bool use_small = false;
#else
    const bool use_small = (k <= 8);
#endif
    if (use_small) {
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

    // Phase 3: Scatter
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
            SUB_TYPED(sub_radix_sort)(arr, boundary);
            state->comparisons += boundary;
        }
    }

    if (suffix_len > 1) {
        SUB_TYPED(sub_radix_sort)(arr + boundary, suffix_len);
        state->comparisons += suffix_len;
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

// NEARLY_SORTED routing, shared by sub_sort_internal and fast_path_dispatch:
// rotation -> O(n) fix, few runs -> spectral merge, otherwise a gap-sized
// insertion vs light sort. cmp/swp receive the work counts (fast_path_dispatch
// discards them into locals; the full sort folds them into state).
static void SUB_TYPED(sort_nearly_sorted)(SUB_TYPE *arr, size_t n,
                                          const sub_profile_t *profile,
                                          uint64_t *cmp, uint64_t *swp) {
    if (profile->rotation_point > 0) {
        SUB_TYPED(fix_rotation)(arr, n, profile->rotation_point, swp);
        return;
    }
    if (profile->run_count <= 16) {
        SUB_TYPED(sub_spectral_merge)(arr, n, cmp);
    } else {
        size_t sqrt_n = 1;
        while (sqrt_n * sqrt_n < n) sqrt_n++;
        if (profile->max_descent_gap <= (int64_t)sqrt_n) {
            SUB_TYPED(binary_isort)(arr, n);
        } else {
            SUB_TYPED(light_sort)(arr, n);
        }
    }
}

// INTERNAL SORT ENTRY
// `profile_in`: the caller's classification of arr (NULL = classify here).
// Threading the profile through keeps classification at once per public sort
// call; the public entries pass the profile fast_path_dispatch already built.
void SUB_TYPED(sub_sort_internal)(SUB_TYPE *restrict arr, size_t n, sub_adaptive_t *state,
                                  const sub_profile_t *profile_in) {
    if (n <= 1) return;

    sub_profile_t profile = profile_in ? *profile_in
                                       : SUB_TYPED(sub_classify_internal)(arr, n);

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
        SUB_TYPED(sort_nearly_sorted)(arr, n, &profile, &state->comparisons, &state->swaps);
        return;

    case SUB_FEW_UNIQUE:
        if (SUB_TYPED(counting_sort_few_unique)(arr, n, &state->comparisons, &state->swaps)) {
            return;
        }
        // Too many distinct values for counting: radix (distribution-agnostic)
        SUB_TYPED(sub_radix_sort)(arr, n);
        state->comparisons += (uint64_t)n * 4;
        return;

    case SUB_RANDOM:
        // Pure-random arm. The classifier found no structure to exploit, so the
        // comparison model has no edge: distribute by radix (radix.c), the tuned
        // LSD sort gated to exactly this regime. All types, distribution-
        // agnostic (radix coarsens to insertion below n=32).
        SUB_TYPED(sub_radix_sort)(arr, n);
        state->comparisons += (uint64_t)n * 4;  // radix is comparison-free; estimate for stats
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

    // NEARLY_SORTED / PHASED: serial exploit below the parallel threshold; at
    // scale, defer so the public entry routes to the parallel STRUCTURED sort
    // (the structured pole -- fork chunks, close with the R_eff merge).
    if (out_profile->disorder == SUB_NEARLY_SORTED) {
        if (n >= SUB_PARALLEL_THRESHOLD) return false;
        uint64_t cmp = 0, swp = 0;
        SUB_TYPED(sort_nearly_sorted)(arr, n, out_profile, &cmp, &swp);
        return true;
    }

    if (out_profile->disorder == SUB_PHASED) {
        if (n >= SUB_PARALLEL_THRESHOLD) return false;
        sub_adaptive_t state;
        sub_adaptive_init(&state, n);
        SUB_TYPED(sort_phased)(arr, n, out_profile->phase_boundary, &state);
        return true;
    }

    // SUB_RANDOM (and deferred large structured) fall through so the public
    // entry routes to the two parallel poles: random -> radix, structured ->
    // the merge DFS.
    return false; // caller handles RANDOM, deferred structured, FEW_UNIQUE, SPECTRAL
}

// PUBLIC API ENTRY POINT
void SUB_TYPED(sublimation)(SUB_TYPE *restrict arr, size_t n) {
    if (n <= 1) return;

#ifdef SUB_TYPE_IS_FLOAT
    // A comparison sort cannot order NaN (every `<` against NaN is false), so an
    // interspersed NaN acts as a poison pivot that scrambles the finite values
    // around it. Partition NaNs to the tail (their bit-multiset is preserved;
    // order among them is meaningless) and sort only the finite prefix --
    // numpy's contract: sorted finite values, NaNs trailing.
    {
        size_t w = 0;
        for (size_t i = 0; i < n; i++) {
            if (!isnan(arr[i])) {
                if (i != w) { SUB_SWAP(SUB_TYPE, arr[i], arr[w]); }
                w++;
            }
        }
        if (w <= 1) return;   // 0 or 1 finite value: nothing left to order
        n = w;                // sort only the finite prefix; NaNs already trail
    }
#endif

    sub_profile_t profile;
    if (SUB_TYPED(fast_path_dispatch)(arr, n, &profile)) return;

    // fast_path returned false: what remains at scale is SUB_RANDOM, a deferred
    // large structured input (nearly-sorted / phased), FEW_UNIQUE past counting,
    // or SPECTRAL. This is the TWO-POLE parallel dispatch -- axis 1 by the cheap
    // classifier (Pillar B replaces it with the fused entropy scalar):
    //   high-entropy / random -> parallel RADIX (American Flag MSD)
    //   structured / anything else -> parallel MERGE DFS (fork chunks, R_eff close)
    // both ride the one work-stealing engine. Below the threshold or with one
    // worker it falls to the serial arm in sub_sort_internal.
    if (n >= SUB_PARALLEL_THRESHOLD) {
        size_t workers = sub_default_num_workers();
        if (workers >= 2) {
            if (profile.disorder != SUB_RANDOM) {
                // Structured pole: the serial merge is slow, so the parallel
                // merge DFS pays off from SUB_PARALLEL_THRESHOLD.
                SUB_TYPED(sub_smerge_par)(arr, n, workers);
                return;
            }
            if (n >= SUB_RADIX_PAR_MIN_T) {
                // Random pole: the serial LSD radix is cache-fast, so the
                // parallel radix only wins once the serial arm stops fitting
                // cache; below SUB_RADIX_PAR_MIN_T the serial tail is faster.
                // Per-TYPE, because that crossover is a function of the element
                // width: an 8-byte type spills L3 at a smaller n than a 4-byte
                // one, so they do not cross over at the same place.
                SUB_TYPED(sub_radix_sort_par)(arr, n, workers);
                return;
            }
        }
    }

    sub_adaptive_t state;
    sub_adaptive_init(&state, n);
    SUB_TYPED(sub_sort_internal)(arr, n, &state, &profile);
}

// Clear the per-type threshold so the next inclusion starts from the default.
#undef SUB_RADIX_PAR_MIN_T
#ifdef SUB_RADIX_PAR_MIN_T_DEFAULTED
#undef SUB_RADIX_PAR_MIN_T_DEFAULTED
#endif
