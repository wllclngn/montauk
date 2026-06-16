// spectral.c -- Laplacian eigendecomposition for sorting
//
// Three sorting primitives from one matrix factorization:
//   1. Fiedler vector (eigenvector of lambda_2) gives sorted order
//   2. Eigenvalues give wave-equation convergence rates
//   3. Spectral gap predicts partition quality
//
// Jacobi eigendecomposition computes the spectral structure of a
// comparison graph to recover sorted order via seriation (Atkins et al. 1998).
#include "internal/sort_internal.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>

// WORKSPACE LIFECYCLE

sub_spectral_ws_t *sub_spectral_ws_alloc(size_t max_n) {
    sub_spectral_ws_t *ws = calloc(1, sizeof(sub_spectral_ws_t));
    if (!ws) return nullptr;

    size_t nn;
    if (ckd_mul(&nn, max_n, max_n)) {
        free(ws);
        return nullptr;
    }
    ws->matrix      = calloc(nn, sizeof(double));
    ws->eigenvalues = calloc(max_n, sizeof(double));
    ws->work        = calloc(nn, sizeof(double));
    ws->perm        = calloc(max_n, sizeof(size_t));
    ws->scratch     = calloc(max_n, sizeof(int64_t));
    ws->capacity    = max_n;

    if (!ws->matrix || !ws->eigenvalues || !ws->work || !ws->perm || !ws->scratch) {
        sub_spectral_ws_free(ws);
        return nullptr;
    }

    return ws;
}

void sub_spectral_ws_free(sub_spectral_ws_t *ws) {
    if (!ws) return;
    free(ws->matrix);
    free(ws->eigenvalues);
    free(ws->work);
    free(ws->perm);
    free(ws->scratch);
    free(ws);
}

// COMPARISON GRAPH LAPLACIAN
//
// Build a comparison graph by sampling O(n * sqrt(n)) pairs, then
// construct the graph Laplacian L = D - W.
//
// Strategy: compare each element against O(sqrt(n)) sampled splitters
// plus O(log n) random neighbors. Edge weight encodes ordering distance:
// w(i,j) = 1.0 if i < j (comparison result known), 0 otherwise.
// The Laplacian of this comparison graph encodes the partial order.
void sub_build_comparison_laplacian(const int64_t *arr, size_t n,
                                    double *L, uint64_t seed) {
    // zero the matrix
    memset(L, 0, n * n * sizeof(double));

    // helper: add undirected edge (i,j) with weight w to Laplacian
    #define ADD_EDGE(i, j, w) do {       \
        L[(i)*n + (j)] -= (w);           \
        L[(j)*n + (i)] -= (w);           \
        L[(i)*n + (i)] += (w);           \
        L[(j)*n + (j)] += (w);           \
    } while (0)

    // sample sqrt(n) splitter indices
    size_t num_splitters = 1;
    {
        size_t s = n;
        while (s > 1) { s >>= 2; num_splitters++; }
    }
    if (num_splitters > n) num_splitters = n;

    // compare each element against splitters
    size_t stride = n / num_splitters;
    if (stride < 1) stride = 1;

    for (size_t i = 0; i < n; i++) {
        for (size_t s = 0; s < num_splitters; s++) {
            size_t j = s * stride;
            if (j >= n) j = n - 1;
            if (i == j) continue;

            // edge weight: 1.0 for a known comparison
            // the direction (i < j or i > j) is encoded in the Laplacian
            // structure: we just need the edge to exist
            ADD_EDGE(i, j, 1.0);
        }
    }

    // also compare each element against O(log n) random neighbors
    size_t log_n = 1;
    { size_t t = n; while (t > 1) { t >>= 1; log_n++; } }

    uint64_t rng = seed ^ 0x5DEECE66Dull;
    for (size_t i = 0; i < n; i++) {
        for (size_t k = 0; k < log_n; k++) {
            rng = rng * 6364136223846793005ull + 1442695040888963407ull;
            size_t j = (size_t)(rng >> 33) % n;
            if (i == j) continue;

            ADD_EDGE(i, j, 1.0);
        }
    }

    #undef ADD_EDGE

    // weight edges by comparison result: if arr[i] < arr[j], the edge
    // encodes ordering information. We re-weight by inverse distance
    // in value space: nearby values get higher weight.
    // Find value range for normalization
    int64_t vmin = arr[0], vmax = arr[0];
    for (size_t i = 1; i < n; i++) {
        if (arr[i] < vmin) vmin = arr[i];
        if (arr[i] > vmax) vmax = arr[i];
    }
    double range = (double)(vmax - vmin);
    if (range < 1.0) range = 1.0;

    // re-weight: for each off-diagonal entry, scale by value proximity
    for (size_t i = 0; i < n; i++) {
        double diag_correction = 0.0;
        L[i * n + i] = 0.0; // will recompute
        for (size_t j = 0; j < n; j++) {
            if (i == j) continue;
            if (L[i * n + j] < 0.0) {
                // edge exists: re-weight by value proximity
                double dist = fabs((double)(arr[i] - arr[j])) / range;
                double w = 1.0 / (1.0 + dist * (double)n);
                L[i * n + j] = -w;
                diag_correction += w;
            }
        }
        L[i * n + i] = diag_correction;
    }
    // symmetrize (ensure L[i][j] == L[j][i])
    for (size_t i = 0; i < n; i++) {
        for (size_t j = i + 1; j < n; j++) {
            double avg = 0.5 * (L[i * n + j] + L[j * n + i]);
            L[i * n + j] = avg;
            L[j * n + i] = avg;
        }
        // recompute diagonal from off-diagonals
        double d = 0.0;
        for (size_t j = 0; j < n; j++) {
            if (j != i) d -= L[i * n + j];
        }
        L[i * n + i] = d;
    }
}

// JACOBI EIGENDECOMPOSITION
//
// Classic Jacobi rotation method for symmetric matrices.
//
// On entry: A is n*n symmetric, row-major.
// On exit: eigenvalues[0..n-1] sorted ascending,
//          A columns hold corresponding eigenvectors.
// work: n*n scratch buffer (used for eigenvector accumulation).
// Returns iteration count (0 on failure).
size_t sub_jacobi_eigendecompose(double *A, double *eigenvalues,
                                 size_t n, double *work) {
    // work buffer holds eigenvector matrix V (initially identity)
    double *V = work;
    memset(V, 0, n * n * sizeof(double));
    for (size_t i = 0; i < n; i++) {
        V[i * n + i] = 1.0;
    }

    size_t max_iter = SUB_JACOBI_MAX_ITER_MULT * n * n;
    size_t iter = 0;

    for (; iter < max_iter; iter++) {
        // find largest off-diagonal element
        double max_val = 0.0;
        size_t p = 0, q = 1;
        for (size_t i = 0; i < n; i++) {
            for (size_t j = i + 1; j < n; j++) {
                double val = fabs(A[i * n + j]);
                if (val > max_val) {
                    max_val = val;
                    p = i;
                    q = j;
                }
            }
        }

        // convergence check
        if (max_val < SUB_JACOBI_TOLERANCE) break;

        // compute Givens rotation angle
        double app = A[p * n + p];
        double aqq = A[q * n + q];
        double apq = A[p * n + q];

        double c, s;
        if (fabs(app - aqq) < SUB_JACOBI_NEAR_EQUAL) {
            // near-equal diagonal: 45 degree rotation
            c = 0.70710678118654752; // cos(pi/4)
            s = 0.70710678118654752; // sin(pi/4)
        } else {
            double theta = 0.5 * atan2(2.0 * apq, app - aqq);
            c = cos(theta);
            s = sin(theta);
        }

        // apply rotation to A: rows and columns p, q
        for (size_t i = 0; i < n; i++) {
            if (i == p || i == q) continue;
            double aip = A[i * n + p];
            double aiq = A[i * n + q];
            A[i * n + p] =  c * aip + s * aiq;
            A[p * n + i] = A[i * n + p]; // symmetry
            A[i * n + q] = -s * aip + c * aiq;
            A[q * n + i] = A[i * n + q]; // symmetry
        }

        // update diagonal and off-diagonal (p,q) block
        A[p * n + p] = c * c * app + 2.0 * s * c * apq + s * s * aqq;
        A[q * n + q] = s * s * app - 2.0 * s * c * apq + c * c * aqq;
        A[p * n + q] = 0.0;
        A[q * n + p] = 0.0;

        // accumulate eigenvectors: V <- V * R
        for (size_t i = 0; i < n; i++) {
            double vip = V[i * n + p];
            double viq = V[i * n + q];
            V[i * n + p] =  c * vip + s * viq;
            V[i * n + q] = -s * vip + c * viq;
        }
    }

    // extract eigenvalues from diagonal
    for (size_t i = 0; i < n; i++) {
        eigenvalues[i] = A[i * n + i];
    }

    // sort eigenvalues ascending and reorder eigenvector columns
    // simple selection sort (n <= 512)
    for (size_t i = 0; i < n; i++) {
        size_t min_idx = i;
        for (size_t j = i + 1; j < n; j++) {
            if (eigenvalues[j] < eigenvalues[min_idx]) {
                min_idx = j;
            }
        }
        if (min_idx != i) {
            // swap eigenvalues
            double tmp = eigenvalues[i];
            eigenvalues[i] = eigenvalues[min_idx];
            eigenvalues[min_idx] = tmp;

            // swap eigenvector columns
            for (size_t r = 0; r < n; r++) {
                double vtmp = V[r * n + i];
                V[r * n + i] = V[r * n + min_idx];
                V[r * n + min_idx] = vtmp;
            }
        }
    }

    // copy sorted eigenvectors back into A (caller reads A columns)
    memcpy(A, V, n * n * sizeof(double));

    return (iter < max_iter) ? iter + 1 : 0;
}

// SPECTRAL GAP
//
// Returns lambda_2 (second smallest eigenvalue) from sorted array.
// For a connected graph, lambda_1 ~= 0 and lambda_2 > 0.
double sub_spectral_gap(const double *eigenvalues, size_t n) {
    if (n < 2) return 0.0;
    // eigenvalues are sorted ascending; [0] is ~0 (null space), [1] is lambda_2
    return eigenvalues[1];
}

// FIEDLER VECTOR ARGSORT
//
// The Fiedler vector is the eigenvector corresponding to lambda_2.
// Sorting elements by their Fiedler vector components recovers the
// approximate ordering (exact for Robinson matrices, Atkins et al. 1998).
//
// Produces perm[k] = index of k-th smallest Fiedler entry.
void sub_fiedler_argsort(const double *fiedler, size_t *perm, size_t n) {
    // initialize identity permutation
    for (size_t i = 0; i < n; i++) {
        perm[i] = i;
    }

    // insertion sort on Fiedler values (n <= 512, fast enough)
    for (size_t i = 1; i < n; i++) {
        size_t key = perm[i];
        double key_val = fiedler[key];
        size_t j = i;
        while (j > 0 && fiedler[perm[j - 1]] > key_val) {
            perm[j] = perm[j - 1];
            j--;
        }
        perm[j] = key;
    }
}

// APPLY PERMUTATION
//
// Rearrange arr according to perm using scratch buffer.
void sub_apply_permutation_i64(int64_t *arr, const size_t *perm, size_t n,
                               int64_t *scratch) {
    for (size_t i = 0; i < n; i++) {
        scratch[i] = arr[perm[i]];
    }
    memcpy(arr, scratch, n * sizeof(int64_t));
}

// INSERTION SORT CLEANUP
//
// After spectral seriation, the data should be nearly sorted.
// Insertion sort is O(n * max_displacement), which is O(n) if
// seriation was good.
static void insertion_cleanup_i64(int64_t *arr, size_t n, uint64_t *comparisons) {
    for (size_t i = 1; i < n; i++) {
        int64_t key = arr[i];
        size_t j = i;
        while (j > 0 && arr[j - 1] > key) {
            (*comparisons)++;
            arr[j] = arr[j - 1];
            j--;
        }
        (*comparisons)++; // final comparison (element in place or shifted)
        arr[j] = key;
    }
}

// TOP-LEVEL SPECTRAL SORT
//
// Full pipeline:
//   1. Build comparison Laplacian from sampled comparisons
//   2. Jacobi eigendecompose
//   3. Check spectral gap (bail if poor)
//   4. Extract Fiedler vector, argsort
//   5. Apply permutation (produces near-sorted order)
//   6. Insertion sort cleanup
sub_spectral_result_t sub_spectral_sort_i64(
    int64_t *restrict arr, size_t n,
    sub_spectral_ws_t *ws,
    void *adaptive_state) {

    sub_adaptive_t *state = (sub_adaptive_t *)adaptive_state;
    sub_spectral_result_t result = {0};

    // 1. build comparison Laplacian
    // Deterministic seed: fixed constant XOR array size ensures
    // reproducible sampling while varying with input size.
    sub_build_comparison_laplacian(arr, n, ws->matrix,
                                  0x12345678ull ^ (uint64_t)n);

    // 2. Jacobi eigendecompose
    result.jacobi_iterations = sub_jacobi_eigendecompose(
        ws->matrix, ws->eigenvalues, n, ws->work);
    result.converged = (result.jacobi_iterations > 0);

    if (!result.converged) {
        // Jacobi failed to converge -- bail, let caller fall back
        return result;
    }

    // 3. spectral gap analysis
    result.spectral_gap = sub_spectral_gap(ws->eigenvalues, n);
    result.lambda_max = ws->eigenvalues[n - 1];
    if (result.lambda_max > SUB_EIGENVALUE_ZERO_THRESH) {
        result.gap_ratio = result.spectral_gap / result.lambda_max;
    }
    result.gap_sufficient = (result.gap_ratio >= SUB_SPECTRAL_GAP_POOR);

    if (state) {
        state->last_spectral_gap = (float)result.gap_ratio;
    }

    if (!result.gap_sufficient) {
        // poor spectral gap: comparison graph doesn't encode clear ordering
        // bail and let caller use standard partition sort
        return result;
    }

    // 4. Fiedler vector argsort
    // Fiedler vector = column 1 of eigenvector matrix (column 0 is null space)
    // After Jacobi, ws->matrix columns hold eigenvectors
    // Extract column 1 into a temporary (use first n entries of scratch area)
    double *fiedler = ws->work; // reuse work buffer (Jacobi is done)
    for (size_t i = 0; i < n; i++) {
        fiedler[i] = ws->matrix[i * n + 1];
    }

    sub_fiedler_argsort(fiedler, ws->perm, n);

    // 5. apply permutation
    sub_apply_permutation_i64(arr, ws->perm, n, ws->scratch);

    // 6. insertion sort cleanup
    insertion_cleanup_i64(arr, n, state ? &state->comparisons : &(uint64_t){0});

    if (state) {
        state->levels_built++;
    }

    return result;
}
