// test_affinity.c -- self-tuning (local-scaling) affinity for montauk_similar.
// The degeneracy fix: an extreme-outlier query keeps a defined neighborhood, so
// commute-time (effective-resistance) distances from it stay ORDERED by feature
// proximity instead of saturating to one value, the way a single global RBF
// bandwidth leaves them (every edge of the outlier collapsing to the floor).
// Behavioral, not a numeric oracle: the affinity is a graph-construction
// heuristic, so the contract is the ordering and the non-degeneracy, not exact
// values.
#include "sublimation_spectral.h"
#include <stdio.h>

static int failures = 0;
#define CHECK(c, m) do { if (!(c)) { \
    fprintf(stderr, "FAIL: %s (%s:%d)\n", m, __FILE__, __LINE__); failures++; } } while (0)

int main(void) {
    // 10 processes, 3 features (cpu, rss, gpu): a tight bulk near the origin, one
    // BRIDGE partway out along feature 0, and one EXTREME OUTLIER far out along
    // it -- the query. In feature space the outlier is nearer the bridge (gap 50)
    // than any bulk node (gap ~98), and a correct affinity must preserve that.
    enum { N = 10, D = 3 };
    double x[N * D] = {
        1, 1, 0,  2, 1, 0,  1, 2, 1,  2, 2, 0,  1, 1, 1,
        2, 1, 1,  1, 2, 0,  2, 2, 1,          // 0..7 bulk
        50,  1, 0,                            // 8 bridge
        100, 1, 0,                            // 9 outlier (query)
    };
    double W[N * N], reff[N * N];
    CHECK(sublimation_self_tuning_affinity(x, N, D, 7, W) == 0, "affinity build");
    CHECK(sublimation_effective_resistance(W, N, reff) == 0, "effective resistance");

    const size_t q = 9, bridge = 8;
    double r_bridge = reff[q * N + bridge];
    double r_bulk_min = 1e300;
    for (size_t j = 0; j < 8; j++)
        if (reff[q * N + j] < r_bulk_min) r_bulk_min = reff[q * N + j];
    CHECK(r_bridge < r_bulk_min, "outlier: bridge nearer than any bulk node");

    // The pre-fix failure was every resistance from the outlier landing on one
    // saturated value. A real neighborhood spreads them.
    double rmin = 1e300, rmax = -1e300;
    for (size_t j = 0; j < N; j++) {
        if (j == q) continue;
        double r = reff[q * N + j];
        if (r < rmin) rmin = r;
        if (r > rmax) rmax = r;
    }
    CHECK(rmax - rmin > 1e-6, "outlier resistances are not saturated");

    if (failures == 0) printf("test_affinity: OK\n");
    return failures ? 1 : 0;
}
