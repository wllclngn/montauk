// spectral_kernel.h -- the shared spectral kernel (internal face)
//
// One home for the graph-spectral math: the cyclic-Jacobi eigensolver, the
// Laplacian, effective resistance, the Fiedler vector and spectral clustering
// (double-based core, in spectral_kernel.c), plus the typed front-end that
// builds a comparison Laplacian from a T[] array (spectral_typed.c). The public
// face (effective_resistance / fiedler / eigh / spectral_cluster / laplacian) is
// in sublimation_spectral.h over the same code.
#ifndef SUB_SPECTRAL_KERNEL_H
#define SUB_SPECTRAL_KERNEL_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "c23_compat.h"

// Minimum n for the randomness battery's spectral-flatness lens (below it the
// comparison graph is too small to read); the eigenvalue-zero threshold for the
// Jacobi core.
SUB_CONSTEXPR size_t SUB_SPECTRAL_MIN_N         = 64;
SUB_CONSTEXPR double SUB_EIGENVALUE_ZERO_THRESH = 1e-8;

// SHARED DOUBLE-BASED CORE (spectral_kernel.c)

uint64_t sub_sm_next(uint64_t *s);                              // splitmix64
void sub_spectral_jacobi(double *A, size_t n, double *eval, double *V);  // A destroyed
void sub_spectral_laplacian(const double *W, size_t n, double *L);        // L = D - W

// TYPED FRONT-ENDS (spectral_typed.c)

double sub_spectral_gap(const double *eigenvalues, size_t n);

// Comparison-graph Laplacian from an int64 array (L: n*n, filled). The one type
// the randomness battery's spectral-flatness lens needs: every typed entry point
// widens its samples to int64 before building the graph, so a single i64 builder
// serves all six -- no per-type instantiation earns its keep.
void sub_build_comparison_laplacian_i64(const int64_t *arr, size_t n, double *L, uint64_t seed);

#endif // SUB_SPECTRAL_KERNEL_H
