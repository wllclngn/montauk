// spectral_typed_impl.h -- templated typed front-end for the spectral kernel.
// Included per type by spectral_typed.c with SUB_TYPE / SUB_SUFFIX set. Builds
// the comparison Laplacian from a T[] array, feeding the shared double core
// (sub_spectral_jacobi) used by the randomness battery's spectral lens. No guard.

// Comparison-graph Laplacian: sample O(sqrt(n)) splitters + O(log n) neighbors
// per element, weight edges by value proximity w = 1/(1 + dist*n), symmetrize.
void SUB_TYPED(sub_build_comparison_laplacian)(const SUB_TYPE *arr, size_t n,
                                               double *L, uint64_t seed) {
    memset(L, 0, n * n * sizeof(double));
    #define ADD_EDGE(i, j, w) do {   \
        L[(i)*n + (j)] -= (w);       \
        L[(j)*n + (i)] -= (w);       \
        L[(i)*n + (i)] += (w);       \
        L[(j)*n + (j)] += (w);       \
    } while (0)

    size_t num_splitters = 1;
    { size_t s = n; while (s > 1) { s >>= 2; num_splitters++; } }
    if (num_splitters > n) num_splitters = n;
    size_t stride = n / num_splitters;
    if (stride < 1) stride = 1;
    for (size_t i = 0; i < n; i++)
        for (size_t s = 0; s < num_splitters; s++) {
            size_t j = s * stride;
            if (j >= n) j = n - 1;
            if (i == j) continue;
            ADD_EDGE(i, j, 1.0);
        }

    size_t log_n = 1;
    { size_t t = n; while (t > 1) { t >>= 1; log_n++; } }
    uint64_t rng = seed ^ 0x5DEECE66Dull;
    for (size_t i = 0; i < n; i++)
        for (size_t k = 0; k < log_n; k++) {
            size_t j = sub_lcg_index(&rng, n);
            if (i == j) continue;
            ADD_EDGE(i, j, 1.0);
        }
    #undef ADD_EDGE

    SUB_TYPE vmin = arr[0], vmax = arr[0];
    for (size_t i = 1; i < n; i++) {
        if (arr[i] < vmin) vmin = arr[i];
        if (arr[i] > vmax) vmax = arr[i];
    }
    double range = (double)vmax - (double)vmin;
    if (range < 1.0) range = 1.0;

    for (size_t i = 0; i < n; i++) {
        double diag = 0.0;
        L[i * n + i] = 0.0;
        for (size_t j = 0; j < n; j++) {
            if (i == j) continue;
            if (L[i * n + j] < 0.0) {
                double dist = fabs((double)arr[i] - (double)arr[j]) / range;
                double w = 1.0 / (1.0 + dist * (double)n);
                L[i * n + j] = -w;
                diag += w;
            }
        }
        L[i * n + i] = diag;
    }
    for (size_t i = 0; i < n; i++) {
        for (size_t j = i + 1; j < n; j++) {
            double avg = 0.5 * (L[i * n + j] + L[j * n + i]);
            L[i * n + j] = avg;
            L[j * n + i] = avg;
        }
        double d = 0.0;
        for (size_t j = 0; j < n; j++) if (j != i) d -= L[i * n + j];
        L[i * n + i] = d;
    }
}
