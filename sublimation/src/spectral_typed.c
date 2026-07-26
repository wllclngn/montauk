// spectral_typed.c -- typed front-ends to the spectral kernel: the spectral gap
// and the int64 comparison-Laplacian builder (spectral_typed_impl.h) that feeds
// the shared eigensolver. Only int64 is instantiated: every caller (the
// randomness battery's spectral-flatness lens) widens its samples to int64
// first, so the other five typed builders had no consumer.
#include "internal/sort_internal.h"     // SUB_TYPED
#include "internal/spectral_kernel.h"
#include <string.h>
#include <math.h>

// lambda_2 (algebraic connectivity) from ascending eigenvalues.
double sub_spectral_gap(const double *eigenvalues, size_t n) {
    if (n < 2) return 0.0;
    return eigenvalues[1];
}

#define SUB_TYPE int64_t
#define SUB_SUFFIX _i64
#include "spectral_typed_impl.h"
#undef SUB_TYPE
#undef SUB_SUFFIX
