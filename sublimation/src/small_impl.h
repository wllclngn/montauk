// small_impl.h -- Template body for small-array sort (included once per type)
//
// Requires SUB_TYPE and SUB_SUFFIX to be defined before inclusion.
// AVX2 paths are only used for int64_t (guard with SUB_TYPE_IS_I64).

// BRANCHLESS CONDITIONAL SWAP
SUB_INLINE void SUB_TYPED(cswap)(SUB_TYPE *a, SUB_TYPE *b) {
    SUB_TYPE va = *a, vb = *b;
    int less = va > vb;
    *a = less ? vb : va;
    *b = less ? va : vb;
}

#define SUB_TYPED_CS(i, j) SUB_TYPED(cswap)(&arr[i], &arr[j])

// OPTIMAL SORTING NETWORKS

SUB_INLINE void SUB_TYPED(sort2)(SUB_TYPE *arr) { SUB_TYPED_CS(0,1); }

SUB_INLINE void SUB_TYPED(sort3)(SUB_TYPE *arr) {
    SUB_TYPED_CS(0,1); SUB_TYPED_CS(1,2); SUB_TYPED_CS(0,1);
}

SUB_INLINE void SUB_TYPED(sort4)(SUB_TYPE *arr) {
    SUB_TYPED_CS(0,1); SUB_TYPED_CS(2,3); SUB_TYPED_CS(0,2); SUB_TYPED_CS(1,3); SUB_TYPED_CS(1,2);
}

SUB_INLINE void SUB_TYPED(sort5)(SUB_TYPE *arr) {
    SUB_TYPED_CS(0,1); SUB_TYPED_CS(3,4); SUB_TYPED_CS(2,4); SUB_TYPED_CS(2,3); SUB_TYPED_CS(0,3);
    SUB_TYPED_CS(0,2); SUB_TYPED_CS(1,4); SUB_TYPED_CS(1,3); SUB_TYPED_CS(1,2);
}

SUB_INLINE void SUB_TYPED(sort6)(SUB_TYPE *arr) {
    SUB_TYPED_CS(0,5); SUB_TYPED_CS(1,3); SUB_TYPED_CS(2,4);
    SUB_TYPED_CS(1,2); SUB_TYPED_CS(3,4); SUB_TYPED_CS(0,3);
    SUB_TYPED_CS(2,5); SUB_TYPED_CS(0,1); SUB_TYPED_CS(2,3);
    SUB_TYPED_CS(4,5); SUB_TYPED_CS(1,2); SUB_TYPED_CS(3,4);
}

SUB_INLINE void SUB_TYPED(sort7)(SUB_TYPE *arr) {
    SUB_TYPED_CS(1,2); SUB_TYPED_CS(3,4); SUB_TYPED_CS(5,6);
    SUB_TYPED_CS(0,2); SUB_TYPED_CS(3,5); SUB_TYPED_CS(4,6);
    SUB_TYPED_CS(0,1); SUB_TYPED_CS(4,5); SUB_TYPED_CS(2,6);
    SUB_TYPED_CS(0,4); SUB_TYPED_CS(1,5); SUB_TYPED_CS(0,3);
    SUB_TYPED_CS(2,5); SUB_TYPED_CS(1,3); SUB_TYPED_CS(2,4);
    SUB_TYPED_CS(2,3);
}

SUB_INLINE void SUB_TYPED(sort8)(SUB_TYPE *arr) {
    SUB_TYPED_CS(0,1); SUB_TYPED_CS(2,3); SUB_TYPED_CS(4,5); SUB_TYPED_CS(6,7);
    SUB_TYPED_CS(0,2); SUB_TYPED_CS(1,3); SUB_TYPED_CS(4,6); SUB_TYPED_CS(5,7);
    SUB_TYPED_CS(1,2); SUB_TYPED_CS(5,6); SUB_TYPED_CS(0,4); SUB_TYPED_CS(3,7);
    SUB_TYPED_CS(1,5); SUB_TYPED_CS(2,6); SUB_TYPED_CS(1,4); SUB_TYPED_CS(3,6);
    SUB_TYPED_CS(2,4); SUB_TYPED_CS(3,5); SUB_TYPED_CS(3,4);
}

#undef SUB_TYPED_CS

// SORTING NETWORK DISPATCH for n = 9-16
static void SUB_TYPED(network_sort_9_16)(SUB_TYPE *arr, size_t n) {
#if defined(__AVX2__) && defined(SUB_TYPE_IS_I64)
    if (n == 16) {
        sort16_avx2(arr);
        return;
    }
    sort8_avx2(arr);
#else
    SUB_TYPED(sort8)(arr);
#endif
    // insertion sort the remaining elements into the sorted prefix
    for (size_t i = 8; i < n; i++) {
        SUB_TYPE key = arr[i];
        size_t j = i;
        while (j > 0 && arr[j - 1] > key) {
            arr[j] = arr[j - 1];
            j--;
        }
        arr[j] = key;
    }
}

// INSERTION SORT for n = 17-32
static void SUB_TYPED(insertion_sort)(SUB_TYPE *arr, size_t n,
                                       uint64_t *comparisons, uint64_t *swaps) {
    for (size_t i = 1; i < n; i++) {
        SUB_TYPE key = arr[i];
        size_t j = i;
        while (j > 0) {
            (*comparisons)++;
            if (arr[j - 1] <= key) break;
            arr[j] = arr[j - 1];
            (*swaps)++;
            j--;
        }
        arr[j] = key;
    }
}

// ENTRY POINT
void SUB_TYPED(sub_small_sort)(SUB_TYPE *arr, size_t n,
                                uint64_t *comparisons, uint64_t *swaps) {
    switch (n) {
    case 0: case 1: return;
    case 2: SUB_TYPED(sort2)(arr); *comparisons += 1; return;
    case 3: SUB_TYPED(sort3)(arr); *comparisons += 3; return;
#if defined(__AVX2__) && defined(SUB_TYPE_IS_I64)
    case 4: sort4_avx2(arr); *comparisons += 5; return;
    case 5: SUB_TYPED(sort5)(arr); *comparisons += 9; return;
    case 6: SUB_TYPED(sort6)(arr); *comparisons += 12; return;
    case 7: SUB_TYPED(sort7)(arr); *comparisons += 16; return;
    case 8: sort8_avx2(arr); *comparisons += 19; return;
#else
    case 4: SUB_TYPED(sort4)(arr); *comparisons += 5; return;
    case 5: SUB_TYPED(sort5)(arr); *comparisons += 9; return;
    case 6: SUB_TYPED(sort6)(arr); *comparisons += 12; return;
    case 7: SUB_TYPED(sort7)(arr); *comparisons += 16; return;
    case 8: SUB_TYPED(sort8)(arr); *comparisons += 19; return;
#endif
    default: break;
    }

    if (n <= 16) {
        SUB_TYPED(network_sort_9_16)(arr, n);
        *comparisons += 19 + (n - 8) * 4;
        return;
    }

#if defined(__AVX2__) && defined(SUB_TYPE_IS_I64)
    if (n == 32) {
        sort32_avx2(arr);
        *comparisons += 95;  // bitonic sort-32 comparison count
        return;
    }
    if (n > 16 && n < 32) {
        // Sort 16, then insertion sort the tail (16..n)
        sort16_avx2(arr);
        for (size_t i = 16; i < n; i++) {
            int64_t key = arr[i];
            size_t j = i;
            while (j > 0 && arr[j - 1] > key) {
                arr[j] = arr[j - 1];
                j--;
            }
            arr[j] = key;
        }
        *comparisons += 60 + (n - 16) * 5;
        return;
    }
#endif

    // n = 17-32 fallback: insertion sort
    SUB_TYPED(insertion_sort)(arr, n, comparisons, swaps);
}
