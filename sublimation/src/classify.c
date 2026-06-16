// classify.c -- Initial BFS: input classification and disorder profiling
//
// Type-generic via macro template instantiation.
// Each inclusion of classify_impl.h generates a full set of typed functions.
#include "internal/sort_internal.h"
#include <stdlib.h>
#include <math.h>

// int32_t
#define SUB_TYPE int32_t
#define SUB_SUFFIX _i32
#include "classify_impl.h"
#undef SUB_TYPE
#undef SUB_SUFFIX

// int64_t
#define SUB_TYPE int64_t
#define SUB_SUFFIX _i64
#include "classify_impl.h"
#undef SUB_TYPE
#undef SUB_SUFFIX

// uint32_t
#define SUB_TYPE uint32_t
#define SUB_SUFFIX _u32
#include "classify_impl.h"
#undef SUB_TYPE
#undef SUB_SUFFIX

// uint64_t
#define SUB_TYPE uint64_t
#define SUB_SUFFIX _u64
#include "classify_impl.h"
#undef SUB_TYPE
#undef SUB_SUFFIX

// float
#define SUB_TYPE float
#define SUB_SUFFIX _f32
#include "classify_impl.h"
#undef SUB_TYPE
#undef SUB_SUFFIX

// double
#define SUB_TYPE double
#define SUB_SUFFIX _f64
#include "classify_impl.h"
#undef SUB_TYPE
#undef SUB_SUFFIX

// Public API wrappers. Each runs the type-specific classifier and, for
// ambiguous inputs within the tableau-computation window, augments the
// profile with the full Young tableau shape (LDS, info-theoretic bound,
// interleave detection). These are the diagnostic entry points -- the
// internal sort path skips the tableau for performance.
#define DEFINE_PUBLIC_CLASSIFY(T, SUFFIX)                                  \
    sub_profile_t sublimation_classify_##SUFFIX(const T *arr, size_t n) { \
        sub_profile_t p = sub_classify_internal_##SUFFIX(arr, n);         \
        if (n >= SUB_PATIENCE_THRESHOLD && n <= SUB_TABLEAU_MAX_N) {      \
            patience_sort_with_tableau_##SUFFIX(arr, n, &p);              \
        }                                                                  \
        return p;                                                          \
    }

DEFINE_PUBLIC_CLASSIFY(int32_t,  i32)
DEFINE_PUBLIC_CLASSIFY(int64_t,  i64)
DEFINE_PUBLIC_CLASSIFY(uint32_t, u32)
DEFINE_PUBLIC_CLASSIFY(uint64_t, u64)
DEFINE_PUBLIC_CLASSIFY(float,    f32)
DEFINE_PUBLIC_CLASSIFY(double,   f64)

#undef DEFINE_PUBLIC_CLASSIFY
