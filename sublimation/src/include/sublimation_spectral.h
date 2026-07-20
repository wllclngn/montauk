// sublimation_spectral.h -- Public API for sublimation's spectral lane.
//
// The graph-spectral core: a symmetric Jacobi eigensolver, effective resistance
// (the Kyng-Dinic commute-time distance) via the Laplacian pseudoinverse, the
// Fiedler value with a spectral-gap partition count, and Ng-Jordan-Weiss
// spectral clustering. Pure algorithm, zero weights. Matrices are row-major,
// n by n; output buffers are caller-allocated. Inputs are never modified.
// These back montauk_similar (effective-resistance nearest) and the ANALYZER
// cross-run novelty score.
#ifndef SUBLIMATION_SPECTRAL_H
#define SUBLIMATION_SPECTRAL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Symmetric eigendecomposition of A (n*n, must be symmetric) by cyclic Jacobi.
// eval[n] is filled ascending; V[n*n] holds the eigenvectors as columns, so
// eigenvector k is V[i*n + k] over i. Returns 0 on success, nonzero on OOM.
int sublimation_eigh(const double *A, size_t n, double *eval, double *V);

// Effective resistance between every pair of nodes of a weighted graph, from a
// symmetric non-negative adjacency W (zero diagonal). Builds the Laplacian
// L = D - W, forms its Moore-Penrose pseudoinverse over the non-null modes, and
// fills reff[n*n] with R_eff(i,j) = Lp[i,i] + Lp[j,j] - 2*Lp[i,j]. Returns 0 on
// success, nonzero on OOM.
int sublimation_effective_resistance(const double *W, size_t n, double *reff);

// Fiedler value (second-smallest Laplacian eigenvalue, the algebraic
// connectivity) and the natural partition count from the largest spectral gap,
// from a symmetric non-negative adjacency W. Either output pointer may be NULL.
// Returns 0 on success, nonzero on OOM.
int sublimation_fiedler(const double *W, size_t n, double *lambda2,
                        size_t *partitions);

// Ng-Jordan-Weiss spectral clustering of a symmetric non-negative affinity W
// into k groups: normalized Laplacian, k smallest eigenvectors, row-normalized
// embedding, Lloyd k-means with k-means++ seeding (deterministic given seed).
// labels[n] is filled with the cluster index of each node. Returns 0 on
// success, nonzero on bad arguments or OOM.
int sublimation_spectral_cluster(const double *W, size_t n, size_t k,
                                 uint64_t seed, int32_t *labels);

#ifdef __cplusplus
}
#endif

#endif  // SUBLIMATION_SPECTRAL_H
