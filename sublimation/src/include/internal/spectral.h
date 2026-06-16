// spectral.h -- Laplacian eigendecomposition for sorting
//
// Three sorting primitives from one matrix factorization:
//   1. Fiedler vector = sorted order (spectral seriation)
//   2. Eigenvalues = convergence rates (wave dynamics)
//   3. Spectral gap = partition quality predictor
#ifndef SUB_SPECTRAL_H
#define SUB_SPECTRAL_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "c23_compat.h"

// Thresholds
SUB_CONSTEXPR size_t  SUB_SPECTRAL_MIN_N         = 64;
SUB_CONSTEXPR size_t  SUB_SPECTRAL_MAX_N         = 512;
SUB_CONSTEXPR double  SUB_JACOBI_TOLERANCE       = 1e-12;
SUB_CONSTEXPR size_t  SUB_JACOBI_MAX_ITER_MULT   = 100;
SUB_CONSTEXPR double  SUB_EIGENVALUE_ZERO_THRESH  = 1e-8;
SUB_CONSTEXPR double  SUB_SPECTRAL_GAP_GOOD      = 0.15;
SUB_CONSTEXPR double  SUB_SPECTRAL_GAP_POOR      = 0.02;
SUB_CONSTEXPR double  SUB_JACOBI_NEAR_EQUAL      = 1e-15;

// Pre-allocated workspace (no hot-path malloc)
typedef struct {
    double  *matrix;       // n*n row-major: Laplacian, then overwritten with eigenvectors
    double  *eigenvalues;  // n eigenvalues (sorted ascending after decomposition)
    double  *work;         // n*n scratch for Jacobi rotations
    size_t  *perm;         // n-element permutation (argsort of Fiedler vector)
    int64_t *scratch;      // n-element scratch for permutation application
    size_t   capacity;     // max n this workspace can handle
} sub_spectral_ws_t;

// Result of spectral analysis
typedef struct {
    double  spectral_gap;       // lambda_2 (algebraic connectivity)
    double  lambda_max;         // largest eigenvalue
    double  gap_ratio;          // lambda_2 / lambda_n (quality metric, 0..1)
    size_t  jacobi_iterations;  // iterations to convergence
    bool    converged;          // did Jacobi converge within budget?
    bool    gap_sufficient;     // was gap_ratio >= SUB_SPECTRAL_GAP_POOR?
} sub_spectral_result_t;

// Forward declaration -- full definition is in sort_internal.h
// spectral.h is included by sort_internal.h before the struct is defined,
// so we use an opaque pointer in the function signature.
typedef struct sub_adaptive_tag sub_adaptive_fwd_t;

// Workspace lifecycle (these allocate -- called outside hot paths only)
SUB_NODISCARD
sub_spectral_ws_t *sub_spectral_ws_alloc(size_t max_n);
void              sub_spectral_ws_free(sub_spectral_ws_t *ws);

// Build Laplacian of comparison graph from sampled comparisons
// L: n*n row-major, zeroed on entry, filled on return
// seed: deterministic RNG seed for reproducible sampling
void sub_build_comparison_laplacian(const int64_t *arr, size_t n,
                                    double *L, uint64_t seed);

// Jacobi eigendecomposition of symmetric matrix A (n*n row-major)
// On return: eigenvalues[0..n-1] sorted ascending
//            A columns hold corresponding eigenvectors
// work: n*n scratch buffer
// Returns iteration count (0 on failure)
size_t sub_jacobi_eigendecompose(double *A, double *eigenvalues,
                                 size_t n, double *work);

// Argsort Fiedler vector: perm[k] = index of k-th smallest Fiedler entry
void sub_fiedler_argsort(const double *fiedler, size_t *perm, size_t n);

// Apply permutation: arr becomes arr[perm[0]], arr[perm[1]], ...
void sub_apply_permutation_i64(int64_t *arr, const size_t *perm, size_t n,
                               int64_t *scratch);

// Extract spectral gap from sorted eigenvalue array
double sub_spectral_gap(const double *eigenvalues, size_t n);

// Top-level spectral sort of subarray
// Pre: ws->capacity >= n
// Post: arr[0..n-1] is sorted (via seriation + insertion sort cleanup)
sub_spectral_result_t sub_spectral_sort_i64(
    int64_t *restrict arr, size_t n,
    sub_spectral_ws_t *ws,
    void *adaptive_state);

#endif // SUB_SPECTRAL_H
