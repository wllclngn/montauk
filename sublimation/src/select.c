// select.c -- the value-search leg of sublimation: k-th selection (quickselect)
// and binary search into a sorted array. Selection partitions in place like
// std::nth_element; searchsorted is std::lower_bound (side 0) / upper_bound
// (side 1). One typed entry per element type, no comparator indirection.
#include "sublimation.h"

// Hoare-partition quickselect. Signed indices internally so the j-- never wraps.
// Pivot is a *value* copy of the middle element, so partition swaps can't move
// it out from under us. After the loop arr[k] holds the k-th smallest.
#define DEF_SELECT(NAME, T)                                               \
T NAME(T *arr, size_t n, size_t k) {                                      \
    if (n == 0) return (T)0;                                              \
    if (k >= n) k = n - 1;                                                \
    long left = 0, right = (long)n - 1, kk = (long)k;                     \
    while (left < right) {                                                \
        T pivot = arr[(left + right) / 2];                                \
        long i = left, j = right;                                         \
        while (i <= j) {                                                  \
            while (arr[i] < pivot) ++i;                                   \
            while (pivot < arr[j]) --j;                                   \
            if (i <= j) { T t = arr[i]; arr[i] = arr[j]; arr[j] = t; ++i; --j; } \
        }                                                                 \
        if (kk <= j)      right = j;                                      \
        else if (kk >= i) left = i;                                       \
        else break;                                                       \
    }                                                                     \
    return arr[k];                                                        \
}

// Binary search. side 0 -> lower_bound (first i with sorted[i] >= value);
// side 1 -> upper_bound (first i with sorted[i] > value).
#define DEF_SEARCHSORTED(NAME, T)                                         \
size_t NAME(const T *sorted, size_t n, T value, int side) {               \
    size_t lo = 0, hi = n;                                                \
    while (lo < hi) {                                                     \
        size_t mid = lo + ((hi - lo) >> 1);                               \
        int go_right = side ? (sorted[mid] <= value) : (sorted[mid] < value); \
        if (go_right) lo = mid + 1; else hi = mid;                        \
    }                                                                     \
    return lo;                                                            \
}

DEF_SELECT(sublimation_select_i32, int32_t)
DEF_SELECT(sublimation_select_i64, int64_t)
DEF_SELECT(sublimation_select_u32, uint32_t)
DEF_SELECT(sublimation_select_u64, uint64_t)
DEF_SELECT(sublimation_select_f32, float)
DEF_SELECT(sublimation_select_f64, double)

DEF_SEARCHSORTED(sublimation_searchsorted_i32, int32_t)
DEF_SEARCHSORTED(sublimation_searchsorted_i64, int64_t)
DEF_SEARCHSORTED(sublimation_searchsorted_u32, uint32_t)
DEF_SEARCHSORTED(sublimation_searchsorted_u64, uint64_t)
DEF_SEARCHSORTED(sublimation_searchsorted_f32, float)
DEF_SEARCHSORTED(sublimation_searchsorted_f64, double)
