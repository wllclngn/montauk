// spectral.c -- sublimation spectral lane: the graph-spectral core.
//
// Ported from the proven research prototype (tests/research/learn/
// spectral_research.c), whose oracle (tests/test_spectral.py) proves the
// eigenvalues, the reconstruction, the effective resistance and the Fiedler
// value against numpy, and the clustering behaviorally.
#include "sublimation_spectral.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>

static inline uint64_t sm_next(uint64_t *s) {
    uint64_t z = (*s += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

// Cyclic symmetric Jacobi. A (n*n, destroyed) -> eval[n], V (n*n eigenvectors as
// columns), sorted ascending by eigenvalue.
static void jacobi(double *A, size_t n, double *eval, double *V) {
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
static void laplacian(const double *W, size_t n, double *L) {
    for (size_t i = 0; i < n; i++) {
        double deg = 0.0;
        for (size_t j = 0; j < n; j++) if (j != i) deg += W[i * n + j];
        for (size_t j = 0; j < n; j++)
            L[i * n + j] = (i == j) ? deg - W[i * n + j] : -W[i * n + j];
    }
}

int sublimation_eigh(const double *A, size_t n, double *eval, double *V) {
    if (n == 0) return 1;
    double *work = malloc(n * n * sizeof(double));
    if (!work) return 1;
    memcpy(work, A, n * n * sizeof(double));
    jacobi(work, n, eval, V);
    free(work);
    return 0;
}

int sublimation_effective_resistance(const double *W, size_t n, double *reff) {
    if (n == 0) return 1;
    double *L = malloc(n * n * sizeof(double));
    double *eval = malloc(n * sizeof(double));
    double *V = malloc(n * n * sizeof(double));
    double *Lp = calloc(n * n, sizeof(double));
    if (!L || !eval || !V || !Lp) { free(L); free(eval); free(V); free(Lp); return 1; }
    laplacian(W, n, L);
    jacobi(L, n, eval, V);
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
    laplacian(W, n, L);
    jacobi(L, n, eval, V);
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
    size_t first = (size_t)(sm_next(&rng) % (uint64_t)n);
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
        double target = (double)(sm_next(&rng) >> 11) * (1.0 / 9007199254740992.0) * tot;
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
    jacobi(Ls, n, eval, V);
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
