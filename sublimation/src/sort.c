#define _POSIX_C_SOURCE 199309L
// sort.c -- Flow-model sort entry point
//
// Type-generic via macro template instantiation.
// Each inclusion of sort_impl.h generates a full set of typed functions.
#include "internal/sort_internal.h"
#include "internal/dfspool.h"
#include "internal/radix.h"
#include <math.h>          // isnan, in the float NaN-partition path
#include <stdlib.h>
#include <string.h>
#include <time.h>


// Wall-clock nanoseconds (POSIX) -- used by sublimation_i64_stats.
static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}


// TYPE-GENERIC SORT (all types via template)

// int32_t
#define SUB_TYPE int32_t
#define SUB_SUFFIX _i32
#include "sort_impl.h"
#undef SUB_TYPE
#undef SUB_SUFFIX

// int64_t (with parallel + spectral fallback)
#define SUB_TYPE int64_t
#define SUB_SUFFIX _i64
#define SUB_TYPE_IS_I64
#include "sort_impl.h"
#undef SUB_TYPE_IS_I64
#undef SUB_TYPE
#undef SUB_SUFFIX

// uint32_t
#define SUB_TYPE uint32_t
#define SUB_SUFFIX _u32
#include "sort_impl.h"
#undef SUB_TYPE
#undef SUB_SUFFIX

// uint64_t
#define SUB_TYPE uint64_t
#define SUB_SUFFIX _u64
#define SUB_TYPE_IS_U64
#include "sort_impl.h"
#undef SUB_TYPE_IS_U64
#undef SUB_TYPE
#undef SUB_SUFFIX

// float
#define SUB_TYPE float
#define SUB_SUFFIX _f32
#define SUB_TYPE_IS_FLOAT
#include "sort_impl.h"
#undef SUB_TYPE_IS_FLOAT
#undef SUB_TYPE
#undef SUB_SUFFIX

// double
#define SUB_TYPE double
#define SUB_SUFFIX _f64
#define SUB_TYPE_IS_FLOAT
#include "sort_impl.h"
#undef SUB_TYPE_IS_FLOAT
#undef SUB_TYPE
#undef SUB_SUFFIX

// PUBLIC API: parallel sort (i64 only)

void sublimation_i64_parallel(int64_t *restrict arr, size_t n, size_t num_threads) {
    if (n <= 1) return;

    // Multi-threaded entry point. Classify first (the structured fast paths are
    // cheap and spare a needless parallel pass over already-ordered data); large
    // random then distributes across cores through the parallel radix, and
    // everything else takes the serial adaptive path.
    sub_profile_t profile;
    if (fast_path_dispatch_i64(arr, n, &profile)) return;

    if (num_threads >= 2 && n >= SUB_RADIX_PARALLEL_MIN
        && profile.disorder == SUB_RANDOM) {
        // The parallel radix only beats the cache-fast serial radix past
        // SUB_RADIX_PARALLEL_MIN (well above the structured pole's threshold).
        sub_radix_sort_par_i64(arr, n, num_threads);
        return;
    }

    sub_adaptive_t state;
    sub_adaptive_init(&state, n);
    sub_sort_internal_i64(arr, n, &state, &profile);
}

// PUBLIC API: per-type sort with stats.
// Runs classification, then the full adaptive sort, then populates the
// user-supplied sub_stats_t with comparison counts, the hook-length info-
// theoretic bound, and the resulting comparison_efficiency ratio.
#define DEFINE_PUBLIC_STATS(T, SUFFIX)                                       \
    void sublimation_##SUFFIX##_stats(T *restrict arr, size_t n,            \
                                       sub_stats_t *stats) {                \
        uint64_t t0 = now_ns();                                             \
                                                                             \
        sub_adaptive_t state;                                               \
        sub_adaptive_init(&state, n);                                       \
                                                                             \
        sub_profile_t profile = sub_classify_internal_##SUFFIX(arr, n);     \
        sub_sort_internal_##SUFFIX(arr, n, &state, &profile);               \
                                                                             \
        uint64_t t1 = now_ns();                                             \
                                                                             \
        if (stats) {                                                        \
            stats->comparisons = state.comparisons;                         \
            stats->swaps = state.swaps;                                     \
            stats->levels_built = state.levels_built;                       \
            stats->gap_prunes = state.gap_prunes;                           \
            stats->rescans = state.rescans;                                 \
            stats->spectral_decompositions = 0;                             \
            stats->spectral_gap = 0.0;                                      \
            stats->info_theoretic_bound = (double)profile.info_theoretic_bound; \
            stats->comparison_efficiency = 0.0;                             \
            if (stats->comparisons > 0 && stats->info_theoretic_bound > 0.0) { \
                stats->comparison_efficiency =                              \
                    stats->info_theoretic_bound / (double)stats->comparisons; \
            }                                                                \
            stats->disorder = profile.disorder;                             \
            stats->wall_ns = (double)(t1 - t0);                             \
        }                                                                    \
    }

DEFINE_PUBLIC_STATS(int32_t,  i32)
DEFINE_PUBLIC_STATS(int64_t,  i64)
DEFINE_PUBLIC_STATS(uint32_t, u32)
DEFINE_PUBLIC_STATS(uint64_t, u64)
DEFINE_PUBLIC_STATS(float,    f32)
DEFINE_PUBLIC_STATS(double,   f64)

#undef DEFINE_PUBLIC_STATS

// PUBLIC API: version

int sublimation_api_version(void) {
    return SUBLIMATION_API_VERSION;
}

const char *sublimation_version(void) {
    return SUBLIMATION_VERSION_STRING;
}
