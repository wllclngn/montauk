// spectral_kernel.c -- the shared spectral kernel.
//
// One home for the graph-spectral math every caller needs: the cyclic-Jacobi
// eigensolver, the graph Laplacian, effective resistance, the Fiedler vector
// and spectral clustering, over double matrices. Callers -- the learn lane
// (montauk_similar, clustering), the randomness battery (comparison-Laplacian
// spectral-flatness lens) -- all link this one implementation; the int64
// front-end that builds a comparison Laplacian from an array lives in
// spectral_typed.c and feeds this core. (The sort's spectral merge uses the
// closed-form path R_eff directly, not this core.)
//
// The double core is the research-proven code (tests/test_spectral.py gates the
// eigenvalues, reconstruction, effective resistance and Fiedler value against
// numpy to 1e-8, the clustering behaviorally). The cyclic-sweep Jacobi is the
// single eigensolver -- the sort's old classical-pivot variant is retired.
#include "internal/spectral_kernel.h"
#include "sublimation_spectral.h"
#include "sublimation.h"          // sublimation_select_f64 for the knn scale

#include <math.h>
#include <stdlib.h>
#include <string.h>

uint64_t sub_sm_next(uint64_t *s) {
    uint64_t z = (*s += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

// Cyclic symmetric Jacobi. A (n*n, destroyed) -> eval[n], V (n*n eigenvectors
// as columns), sorted ascending by eigenvalue.
void sub_spectral_jacobi(double *A, size_t n, double *eval, double *V) {
    for (size_t i = 0; i < n * n; i++) V[i] = 0.0;
    for (size_t i = 0; i < n; i++) V[i * n + i] = 1.0;
    for (int sweep = 0; sweep < 100; sweep++) {
        double off = 0.0;
        for (size_t p = 0; p < n; p++)
            for (size_t q = p + 1; q < n; q++) off += A[p * n + q] * A[p * n + q];
        if (off < 1e-30) break;
        for (size_t p = 0; p < n; p++)
            for (size_t q = p + 1; q < n; q++) {
                double apq = A[p * n + q];
                if (fabs(apq) < 1e-300) continue;
                double app = A[p * n + p], aqq = A[q * n + q];
                double theta = (aqq - app) / (2.0 * apq);
                double t = (theta >= 0.0 ? 1.0 : -1.0) /
                           (fabs(theta) + sqrt(theta * theta + 1.0));
                double c = 1.0 / sqrt(t * t + 1.0), s = t * c;
                for (size_t k = 0; k < n; k++) {
                    if (k == p || k == q) continue;
                    double akp = A[k * n + p], akq = A[k * n + q];
                    A[k * n + p] = A[p * n + k] = c * akp - s * akq;
                    A[k * n + q] = A[q * n + k] = s * akp + c * akq;
                }
                A[p * n + p] = c * c * app - 2.0 * s * c * apq + s * s * aqq;
                A[q * n + q] = s * s * app + 2.0 * s * c * apq + c * c * aqq;
                A[p * n + q] = A[q * n + p] = 0.0;
                for (size_t k = 0; k < n; k++) {
                    double vkp = V[k * n + p], vkq = V[k * n + q];
                    V[k * n + p] = c * vkp - s * vkq;
                    V[k * n + q] = s * vkp + c * vkq;
                }
            }
    }
    for (size_t i = 0; i < n; i++) eval[i] = A[i * n + i];
    for (size_t i = 0; i < n; i++)
        for (size_t j = i + 1; j < n; j++)
            if (eval[j] < eval[i]) {
                double te = eval[i]; eval[i] = eval[j]; eval[j] = te;
                for (size_t k = 0; k < n; k++) {
                    double tv = V[k * n + i]; V[k * n + i] = V[k * n + j]; V[k * n + j] = tv;
                }
            }
}

// L = D - W into L (n*n), from a symmetric non-negative adjacency W.
void sub_spectral_laplacian(const double *W, size_t n, double *L) {
    for (size_t i = 0; i < n; i++) {
        double deg = 0.0;
        for (size_t j = 0; j < n; j++) if (j != i) deg += W[i * n + j];
        for (size_t j = 0; j < n; j++)
            L[i * n + j] = (i == j) ? deg - W[i * n + j] : -W[i * n + j];
    }
}

// Public face of the Laplacian builder (see sublimation_spectral.h).
void sublimation_laplacian(const double *W, size_t n, double *L) {
    sub_spectral_laplacian(W, n, L);
}

int sublimation_eigh(const double *A, size_t n, double *eval, double *V) {
    if (n == 0) return 1;
    double *work = malloc(n * n * sizeof(double));
    if (!work) return 1;
    memcpy(work, A, n * n * sizeof(double));
    sub_spectral_jacobi(work, n, eval, V);
    free(work);
    return 0;
}

int sublimation_self_tuning_affinity(const double *x, size_t n, size_t d,
                                     unsigned knn, double *W) {
    if (n == 0 || d == 0) return 1;
    double *z = malloc(n * d * sizeof(double));
    double *d2 = malloc(n * n * sizeof(double));
    double *sigma = malloc(n * sizeof(double));
    double *row = malloc(n * sizeof(double));
    if (!z || !d2 || !sigma || !row) { free(z); free(d2); free(sigma); free(row); return 1; }
    memcpy(z, x, n * d * sizeof(double));

    // Standardize each feature column (z-score) so no raw scale dominates.
    for (size_t j = 0; j < d; j++) {
        double mean = 0.0;
        for (size_t i = 0; i < n; i++) mean += z[i * d + j];
        mean /= (double)n;
        double var = 0.0;
        for (size_t i = 0; i < n; i++) { double e = z[i * d + j] - mean; var += e * e; }
        double sd = sqrt(var / (double)n);
        for (size_t i = 0; i < n; i++)
            z[i * d + j] = sd > 0.0 ? (z[i * d + j] - mean) / sd : 0.0;
    }

    // Pairwise squared distances over the standardized rows.
    for (size_t i = 0; i < n; i++) {
        d2[i * n + i] = 0.0;
        for (size_t k = i + 1; k < n; k++) {
            double s = 0.0;
            for (size_t j = 0; j < d; j++) { double e = z[i * d + j] - z[k * d + j]; s += e * e; }
            d2[i * n + k] = d2[k * n + i] = s;
        }
    }

    // Local bandwidth per node: distance to its knn-th nearest neighbor. Large
    // for an outlier, so the outlier's nearest neighbors keep real affinity
    // rather than every edge collapsing to ~0 under one global sigma.
    unsigned kk = knn == 0 ? 1 : knn;
    if ((size_t)kk > n - 1) kk = (unsigned)(n - 1);
    for (size_t i = 0; i < n; i++) {
        size_t m = 0;
        for (size_t k = 0; k < n; k++) if (k != i) row[m++] = d2[i * n + k];
        double kth = m ? sublimation_select_f64(row, m, (size_t)kk - 1) : 0.0;
        double sig = sqrt(kth);
        sigma[i] = sig > 0.0 ? sig : 1.0;   // guard an all-identical neighborhood
    }

    // Local-scaled affinity, zero diagonal, with a small connectivity floor.
    for (size_t i = 0; i < n; i++) {
        W[i * n + i] = 0.0;
        for (size_t k = 0; k < n; k++) {
            if (i == k) continue;
            W[i * n + k] = exp(-d2[i * n + k] / (sigma[i] * sigma[k])) + 1e-3;
        }
    }
    free(z); free(d2); free(sigma); free(row);
    return 0;
}

int sublimation_effective_resistance(const double *W, size_t n, double *reff) {
    if (n == 0) return 1;
    double *L = malloc(n * n * sizeof(double));
    double *eval = malloc(n * sizeof(double));
    double *V = malloc(n * n * sizeof(double));
    double *Lp = calloc(n * n, sizeof(double));
    if (!L || !eval || !V || !Lp) { free(L); free(eval); free(V); free(Lp); return 1; }
    sub_spectral_laplacian(W, n, L);
    sub_spectral_jacobi(L, n, eval, V);
    double emax = eval[n - 1] > 0.0 ? eval[n - 1] : 1.0;
    double tol = emax * (double)n * 1e-12;          // drop the near-zero null mode
    for (size_t k = 0; k < n; k++) {
        if (eval[k] <= tol) continue;
        double inv = 1.0 / eval[k];
        for (size_t i = 0; i < n; i++)
            for (size_t j = 0; j < n; j++)
                Lp[i * n + j] += inv * V[i * n + k] * V[j * n + k];
    }
    for (size_t i = 0; i < n; i++)
        for (size_t j = 0; j < n; j++)
            reff[i * n + j] = Lp[i * n + i] + Lp[j * n + j] - 2.0 * Lp[i * n + j];
    free(L); free(eval); free(V); free(Lp);
    return 0;
}

int sublimation_fiedler(const double *W, size_t n, double *lambda2,
                        size_t *partitions) {
    if (n == 0) return 1;
    double *L = malloc(n * n * sizeof(double));
    double *eval = malloc(n * sizeof(double));
    double *V = malloc(n * n * sizeof(double));
    if (!L || !eval || !V) { free(L); free(eval); free(V); return 1; }
    sub_spectral_laplacian(W, n, L);
    sub_spectral_jacobi(L, n, eval, V);
    if (lambda2) *lambda2 = n > 1 ? eval[1] : 0.0;
    if (partitions) {
        size_t gap_at = 1;
        double gap = -1.0;
        for (size_t i = 1; i < n; i++) {
            double g = eval[i] - eval[i - 1];
            if (g > gap) { gap = g; gap_at = i; }
        }
        *partitions = n > 1 ? gap_at : 1;
    }
    free(L); free(eval); free(V);
    return 0;
}

static void kmeans(const double *U, size_t n, size_t K, size_t d,
                   uint64_t seed, int32_t *lab) {
    double *cent = malloc(K * d * sizeof(double));
    double *dist = malloc(n * sizeof(double));
    uint64_t rng = seed;
    size_t first = (size_t)(sub_sm_next(&rng) % (uint64_t)n);
    memcpy(cent, U + first * d, d * sizeof(double));
    for (size_t c = 1; c < K; c++) {                // k-means++ seeding
        double tot = 0.0;
        for (size_t i = 0; i < n; i++) {
            double best = INFINITY;
            for (size_t cc = 0; cc < c; cc++) {
                double sq = 0.0;
                for (size_t k = 0; k < d; k++) {
                    double e = U[i * d + k] - cent[cc * d + k]; sq += e * e;
                }
                if (sq < best) best = sq;
            }
            dist[i] = best; tot += best;
        }
        double target = (double)(sub_sm_next(&rng) >> 11) * (1.0 / 9007199254740992.0) * tot;
        size_t pick = n - 1;
        double acc = 0.0;
        for (size_t i = 0; i < n; i++) { acc += dist[i]; if (acc >= target) { pick = i; break; } }
        memcpy(cent + c * d, U + pick * d, d * sizeof(double));
    }
    for (size_t i = 0; i < n; i++) lab[i] = 0;
    for (int it = 0; it < 100; it++) {
        int moved = 0;
        for (size_t i = 0; i < n; i++) {
            double best = INFINITY; int32_t bc = 0;
            for (size_t c = 0; c < K; c++) {
                double sq = 0.0;
                for (size_t k = 0; k < d; k++) {
                    double e = U[i * d + k] - cent[c * d + k]; sq += e * e;
                }
                if (sq < best) { best = sq; bc = (int32_t)c; }
            }
            if (lab[i] != bc) { lab[i] = bc; moved = 1; }
        }
        for (size_t c = 0; c < K * d; c++) cent[c] = 0.0;
        size_t *cnt = calloc(K, sizeof(size_t));
        for (size_t i = 0; i < n; i++) {
            cnt[lab[i]]++;
            for (size_t k = 0; k < d; k++) cent[(size_t)lab[i] * d + k] += U[i * d + k];
        }
        for (size_t c = 0; c < K; c++)
            if (cnt[c]) for (size_t k = 0; k < d; k++) cent[c * d + k] /= (double)cnt[c];
        free(cnt);
        if (!moved) break;
    }
    free(cent); free(dist);
}

int sublimation_spectral_cluster(const double *W, size_t n, size_t k,
                                 uint64_t seed, int32_t *labels) {
    if (n == 0 || k == 0 || k > n) return 1;
    double *deg = malloc(n * sizeof(double));
    double *Ls = malloc(n * n * sizeof(double));
    double *eval = malloc(n * sizeof(double));
    double *V = malloc(n * n * sizeof(double));
    double *U = malloc(n * k * sizeof(double));
    if (!deg || !Ls || !eval || !V || !U) {
        free(deg); free(Ls); free(eval); free(V); free(U); return 1;
    }
    for (size_t i = 0; i < n; i++) {
        double d = 0.0;
        for (size_t j = 0; j < n; j++) d += W[i * n + j];
        deg[i] = d > 0.0 ? 1.0 / sqrt(d) : 0.0;
    }
    for (size_t i = 0; i < n; i++)                  // normalized Laplacian I - D^-1/2 W D^-1/2
        for (size_t j = 0; j < n; j++)
            Ls[i * n + j] = (i == j ? 1.0 : 0.0) - deg[i] * W[i * n + j] * deg[j];
    sub_spectral_jacobi(Ls, n, eval, V);
    for (size_t i = 0; i < n; i++) {                // k smallest eigenvectors, row-normalized
        double norm = 0.0;
        for (size_t c = 0; c < k; c++) { double v = V[i * n + c]; U[i * k + c] = v; norm += v * v; }
        norm = norm > 0.0 ? sqrt(norm) : 1.0;
        for (size_t c = 0; c < k; c++) U[i * k + c] /= norm;
    }
    kmeans(U, n, k, k, seed, labels);
    free(deg); free(Ls); free(eval); free(V); free(U);
    return 0;
}
