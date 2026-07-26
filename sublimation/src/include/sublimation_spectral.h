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

#include "internal/c23_compat.h"   // SUB_API

#ifdef __cplusplus
extern "C" {
#endif

// Symmetric eigendecomposition of A (n*n, must be symmetric) by cyclic Jacobi.
// eval[n] is filled ascending; V[n*n] holds the eigenvectors as columns, so
// eigenvector k is V[i*n + k] over i. Returns 0 on success, nonzero on OOM.
SUB_API int sublimation_eigh(const double *A, size_t n, double *eval, double *V);

// Graph Laplacian L = D - W (n*n) from a symmetric non-negative adjacency W
// (zero diagonal) -- the building block behind effective resistance, the
// Fiedler value and clustering, exposed for callers that want it directly.
SUB_API void sublimation_laplacian(const double *W, size_t n, double *L);

// Self-tuning (local-scaling) RBF affinity over a feature matrix x (n rows by d
// feature columns, row-major). Columns are standardized internally, then each
// row i gets a LOCAL bandwidth sigma_i = the distance to its knn-th nearest
// neighbor (the Zelnik-Manor/Perona scale), and the affinity is
// W(i,k) = exp(-||xi-xk||^2 / (sigma_i * sigma_k)) + a small connectivity floor,
// with a zero diagonal. Unlike one global bandwidth -- which collapses every
// edge of an extreme outlier to ~0 and makes commute-time distance from that
// outlier degenerate -- the local scale keeps an outlier's own nearest neighbors
// meaningfully connected. This builds the graph montauk_similar feeds to
// effective resistance. W is n*n, caller-allocated. knn is clamped to [1, n-1].
// Returns 0 on success, nonzero on OOM.
SUB_API int sublimation_self_tuning_affinity(const double *x, size_t n, size_t d,
                                             unsigned knn, double *W);

// Effective resistance between every pair of nodes of a weighted graph, from a
// symmetric non-negative adjacency W (zero diagonal). Builds the Laplacian
// L = D - W, forms its Moore-Penrose pseudoinverse over the non-null modes, and
// fills reff[n*n] with R_eff(i,j) = Lp[i,i] + Lp[j,j] - 2*Lp[i,j]. Returns 0 on
// success, nonzero on OOM.
SUB_API int sublimation_effective_resistance(const double *W, size_t n, double *reff);

// Fiedler value (second-smallest Laplacian eigenvalue, the algebraic
// connectivity) and the natural partition count from the largest spectral gap,
// from a symmetric non-negative adjacency W. Either output pointer may be NULL.
// Returns 0 on success, nonzero on OOM.
SUB_API int sublimation_fiedler(const double *W, size_t n, double *lambda2,
                                size_t *partitions);

// Ng-Jordan-Weiss spectral clustering of a symmetric non-negative affinity W
// into k groups: normalized Laplacian, k smallest eigenvectors, row-normalized
// embedding, Lloyd k-means with k-means++ seeding (deterministic given seed).
// labels[n] is filled with the cluster index of each node. Returns 0 on
// success, nonzero on bad arguments or OOM.
SUB_API int sublimation_spectral_cluster(const double *W, size_t n, size_t k,
                                         uint64_t seed, int32_t *labels);

#ifdef __cplusplus
}
#endif

#endif  // SUBLIMATION_SPECTRAL_H
