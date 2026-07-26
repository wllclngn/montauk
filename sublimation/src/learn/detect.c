// detect.c -- sublimation learn lane: pure-algorithm anomaly detectors.
//
// Ported from the proven research prototype (tests/research/learn/
// learn_research.c): the byte-parity oracle (tests/test_learn.py) proves every
// output here matches an independent numpy reference, and the Half-Space Trees
// scores are byte-identical to a splitmix64-shared Python re-implementation.
#include "sublimation_learn.h"
#include "sublimation.h"
#include "sublimation_pack.h"   // sublimation_pack_sort_f64 -- the rank sort

#include <math.h>
#include <stdlib.h>
#include <stdint.h>

static inline uint64_t sm_next(uint64_t *s) {
    uint64_t z = (*s += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}
static inline double sm_double(uint64_t *s) {
    return (double)(sm_next(s) >> 11) * (1.0 / 9007199254740992.0);
}

void sublimation_col_moments(const double *x, size_t n, size_t d,
                             double *mean, double *var_pop) {
    double *m2 = calloc(d, sizeof(double));
    for (size_t j = 0; j < d; j++) { mean[j] = 0.0; m2[j] = 0.0; }
    for (size_t i = 0; i < n; i++) {
        double cnt = (double)(i + 1);
        for (size_t j = 0; j < d; j++) {
            double v = x[i * d + j];
            double delta = v - mean[j];
            mean[j] += delta / cnt;
            m2[j] += delta * (v - mean[j]);
        }
    }
    for (size_t j = 0; j < d; j++) var_pop[j] = n ? m2[j] / (double)n : 0.0;
    free(m2);
}

void sublimation_standardize(const double *x, size_t n, size_t d, double *out) {
    double *mean = malloc(d * sizeof(double));
    double *var = malloc(d * sizeof(double));
    sublimation_col_moments(x, n, d, mean, var);
    for (size_t i = 0; i < n; i++)
        for (size_t j = 0; j < d; j++) {
            double sd = sqrt(var[j]);
            out[i * d + j] = sd > 0.0 ? (x[i * d + j] - mean[j]) / sd : 0.0;
        }
    free(mean); free(var);
}

static double median_sorted(const double *v, size_t n) {
    return (n & 1) ? v[n / 2] : 0.5 * (v[n / 2 - 1] + v[n / 2]);
}

void sublimation_mad_scores(const double *x, size_t n, size_t d, double *scores) {
    double *med = malloc(d * sizeof(double));
    double *scale = malloc(d * sizeof(double));
    double *col = malloc(n * sizeof(double));
    for (size_t j = 0; j < d; j++) {
        for (size_t i = 0; i < n; i++) col[i] = x[i * d + j];
        sublimation_f64(col, n);
        med[j] = median_sorted(col, n);
        double meanad = 0.0;
        for (size_t i = 0; i < n; i++) {
            col[i] = fabs(x[i * d + j] - med[j]);
            meanad += col[i];
        }
        meanad = n ? meanad / (double)n : 0.0;
        sublimation_f64(col, n);
        double mad = median_sorted(col, n);
        scale[j] = mad > 0.0 ? mad / 0.6745
                             : (meanad > 0.0 ? 1.2533141373155003 * meanad : 0.0);
    }
    for (size_t i = 0; i < n; i++) {
        double s = 0.0;
        for (size_t j = 0; j < d; j++) {
            if (scale[j] <= 0.0) continue;
            double z = fabs(x[i * d + j] - med[j]) / scale[j];
            if (z > s) s = z;
        }
        scores[i] = s;
    }
    free(med); free(scale); free(col);
}

void sublimation_ewma_scores(const double *x, size_t n, size_t d, double alpha,
                             double *scores) {
    double *level = malloc(d * sizeof(double));
    double *var = malloc(d * sizeof(double));
    const double eps = 1e-12;
    for (size_t i = 0; i < n; i++) {
        double s = 0.0;
        for (size_t j = 0; j < d; j++) {
            double v = x[i * d + j];
            if (i == 0) { level[j] = v; var[j] = 0.0; continue; }
            double resid = v - level[j];
            double z = fabs(resid) / sqrt(var[j] + eps);
            if (z > s) s = z;
            var[j] = (1.0 - alpha) * (var[j] + alpha * resid * resid);
            level[j] += alpha * resid;
        }
        scores[i] = s;
    }
    free(level); free(var);
}

static int chol(const double *A, double *L, size_t c) {
    for (size_t i = 0; i < c; i++)
        for (size_t j = 0; j <= i; j++) {
            double s = A[i * c + j];
            for (size_t k = 0; k < j; k++) s -= L[i * c + k] * L[j * c + k];
            if (i == j) {
                if (s <= 0.0) return 1;
                L[i * c + j] = sqrt(s);
            } else {
                L[i * c + j] = s / L[j * c + j];
            }
        }
    return 0;
}

int sublimation_mahalanobis(const double *x, size_t n, size_t d, double ridge,
                            double *d2) {
    double *mean = calloc(d, sizeof(double));
    double *cov = calloc(d * d, sizeof(double));
    if (!mean || !cov) { free(mean); free(cov); return 1; }
    for (size_t i = 0; i < n; i++)
        for (size_t j = 0; j < d; j++) mean[j] += x[i * d + j];
    for (size_t j = 0; j < d; j++) mean[j] /= (double)n;
    for (size_t i = 0; i < n; i++)
        for (size_t a = 0; a < d; a++) {
            double da = x[i * d + a] - mean[a];
            for (size_t b = 0; b < d; b++)
                cov[a * d + b] += da * (x[i * d + b] - mean[b]);
        }
    for (size_t k = 0; k < d * d; k++) cov[k] /= (double)n;
    for (size_t j = 0; j < d; j++) cov[j * d + j] += ridge;
    double *L = calloc(d * d, sizeof(double));
    if (!L) { free(mean); free(cov); return 1; }
    if (chol(cov, L, d)) { free(mean); free(cov); free(L); return 1; }
    double *y = malloc(d * sizeof(double));
    if (!y) { free(mean); free(cov); free(L); return 1; }
    for (size_t i = 0; i < n; i++) {
        for (size_t a = 0; a < d; a++) {
            double s = x[i * d + a] - mean[a];
            for (size_t k = 0; k < a; k++) s -= L[a * d + k] * y[k];
            y[a] = s / L[a * d + a];
        }
        double v = 0.0;
        for (size_t a = 0; a < d; a++) v += y[a] * y[a];
        d2[i] = v;
    }
    free(mean); free(cov); free(L); free(y);
    return 0;
}

typedef struct { uint32_t *q; double *p; uint64_t *r; uint64_t *l; } hs_tree;

static void hs_build(hs_tree *t, size_t idx, unsigned depth, unsigned H,
                     uint32_t D, double *wmin, double *wmax, uint64_t *rng) {
    if (depth == H) return;
    uint32_t q = (uint32_t)(sm_next(rng) % D);
    double p = 0.5 * (wmin[q] + wmax[q]);
    t->q[idx] = q; t->p[idx] = p;
    double save = wmax[q]; wmax[q] = p;
    hs_build(t, 2 * idx + 1, depth + 1, H, D, wmin, wmax, rng);
    wmax[q] = save;
    save = wmin[q]; wmin[q] = p;
    hs_build(t, 2 * idx + 2, depth + 1, H, D, wmin, wmax, rng);
    wmin[q] = save;
}

int sublimation_hstrees(const double *x, size_t n, size_t d, unsigned trees,
                        unsigned depth, size_t window, uint64_t size_limit,
                        uint64_t seed, double *scores) {
    if (trees == 0 || depth == 0 || d == 0) return 1;
    size_t nodes = ((size_t)1 << (depth + 1)) - 1;
    double *xn = malloc(n * d * sizeof(double));
    if (!xn) return 1;
    for (size_t j = 0; j < d; j++) {
        double mn = x[j], mx = x[j];
        for (size_t i = 1; i < n; i++) {
            double v = x[i * d + j]; if (v < mn) mn = v; if (v > mx) mx = v;
        }
        double range = mx - mn;
        for (size_t i = 0; i < n; i++)
            xn[i * d + j] = range > 0.0 ? (x[i * d + j] - mn) / range : 0.5;
    }
    hs_tree *tr = calloc(trees, sizeof(hs_tree));  // zeroed: NULL fields free safely
    double *wmin = malloc(d * sizeof(double));
    double *wmax = malloc(d * sizeof(double));
    if (!tr || !wmin || !wmax) { free(xn); free(wmin); free(wmax); free(tr); return 1; }
    uint64_t rng = seed;
    for (unsigned ti = 0; ti < trees; ti++) {
        tr[ti].q = calloc(nodes, sizeof(uint32_t));
        tr[ti].p = calloc(nodes, sizeof(double));
        tr[ti].r = calloc(nodes, sizeof(uint64_t));
        tr[ti].l = calloc(nodes, sizeof(uint64_t));
        if (!tr[ti].q || !tr[ti].p || !tr[ti].r || !tr[ti].l) {
            free(xn); free(wmin); free(wmax);
            for (unsigned tj = 0; tj <= ti; tj++) {
                free(tr[tj].q); free(tr[tj].p); free(tr[tj].r); free(tr[tj].l);
            }
            free(tr);
            return 1;
        }
        for (size_t j = 0; j < d; j++) {
            double sq = sm_double(&rng);
            double mg = sq > 1.0 - sq ? sq : 1.0 - sq;
            wmin[j] = sq - 2.0 * mg; wmax[j] = sq + 2.0 * mg;
        }
        hs_build(&tr[ti], 0, 0, depth, (uint32_t)d, wmin, wmax, &rng);
    }
    for (size_t i = 0; i < n; i++) {
        const double *row = &xn[i * d];
        uint64_t score = 0;
        for (unsigned ti = 0; ti < trees; ti++) {
            hs_tree *t = &tr[ti];
            size_t idx = 0; unsigned dp = 0;
            for (;;) {
                uint64_t rm = t->r[idx];
                if (dp == depth || rm <= size_limit) { score += rm << dp; break; }
                idx = row[t->q[idx]] < t->p[idx] ? 2 * idx + 1 : 2 * idx + 2;
                dp++;
            }
        }
        for (unsigned ti = 0; ti < trees; ti++) {
            hs_tree *t = &tr[ti];
            size_t idx = 0; unsigned dp = 0;
            for (;;) {
                t->l[idx]++;
                if (dp == depth) break;
                idx = row[t->q[idx]] < t->p[idx] ? 2 * idx + 1 : 2 * idx + 2;
                dp++;
            }
        }
        if (window && (i + 1) % window == 0)
            for (unsigned ti = 0; ti < trees; ti++)
                for (size_t k = 0; k < nodes; k++) {
                    tr[ti].r[k] = tr[ti].l[k]; tr[ti].l[k] = 0;
                }
        scores[i] = (double)score;
    }
    free(xn); free(wmin); free(wmax);
    for (unsigned ti = 0; ti < trees; ti++) {
        free(tr[ti].q); free(tr[ti].p); free(tr[ti].r); free(tr[ti].l);
    }
    free(tr);
    return 0;
}

// Rank-normalize v[n] into r[n] on [0,1] (0 = lowest, 1 = highest), ties sharing
// one averaged rank. Ranking rides sublimation's own index sort (pack_sort_f64),
// not a comparison callback; idx[n] is caller scratch.
static void sub_rank_normalize(const double *v, size_t n, uint32_t *idx, double *r) {
    for (size_t i = 0; i < n; i++) idx[i] = (uint32_t)i;
    sublimation_pack_sort_f64(v, idx, n, false);              // ascending by v
    const double denom = (n > 1) ? (double)(n - 1) : 1.0;
    for (size_t i = 0; i < n;) {
        size_t j = i + 1;
        while (j < n && v[idx[j]] == v[idx[i]]) j++;           // [i,j) tie on one value
        const double val = (n > 1) ? (0.5 * (double)(i + j - 1)) / denom : 0.0;
        for (size_t k = i; k < j; k++) r[idx[k]] = val;
        i = j;
    }
}

int sublimation_anomaly_fuse(const double *x, size_t n, size_t d,
                             double *scores, int8_t *axes) {
    if (n == 0) return 0;
    double  *sc  = (double  *)malloc(n * 6 * sizeof(double));  // mad,maha,hst,rm,rh,rhst
    double  *neg = (double  *)malloc(n * sizeof(double));
    uint32_t *idx = (uint32_t *)malloc(n * sizeof(uint32_t));
    double  *ms  = (double  *)malloc(d * 2 * sizeof(double));  // col mean, col sd
    if (!sc || !neg || !idx || !ms) { free(sc); free(neg); free(idx); free(ms); return 1; }
    double *mad = sc, *maha = sc + n, *hst = sc + 2 * n;
    double *rm = sc + 3 * n, *rh = sc + 4 * n, *rhst = sc + 5 * n;
    double *mean = ms, *sd = ms + d;

    // Three spatial detectors, each a lens the others cannot see through (MAD:
    // single-axis extremes; Mahalanobis: unusual axis COMBINATIONS, elliptical;
    // HST: density/isolation, no shape assumption). EWMA stays out -- it is
    // temporal, a different axis, and belongs to the changepoint field.
    sublimation_mad_scores(x, n, d, mad);
    if (sublimation_mahalanobis(x, n, d, 1e-3, maha) != 0)
        for (size_t i = 0; i < n; i++) maha[i] = 0.0;         // degenerate cov -> neutral
    const int hst_ok = (sublimation_hstrees(x, n, d, 25, 12, 200, 25, 1729ull, hst) == 0);

    sub_rank_normalize(mad, n, idx, rm);
    sub_rank_normalize(maha, n, idx, rh);
    if (hst_ok) {
        for (size_t i = 0; i < n; i++) neg[i] = -hst[i];      // HST: lower = more anomalous
        sub_rank_normalize(neg, n, idx, rhst);
    }

    // Per-column standardization drives the dominant-axis attribution.
    for (size_t j = 0; j < d; j++) mean[j] = 0.0;
    for (size_t i = 0; i < n; i++)
        for (size_t j = 0; j < d; j++) mean[j] += x[i * d + j];
    for (size_t j = 0; j < d; j++) mean[j] /= (double)n;
    for (size_t j = 0; j < d; j++) sd[j] = 0.0;
    for (size_t i = 0; i < n; i++)
        for (size_t j = 0; j < d; j++) { double e = x[i * d + j] - mean[j]; sd[j] += e * e; }
    for (size_t j = 0; j < d; j++) sd[j] = sqrt(sd[j] / (double)n);

    for (size_t i = 0; i < n; i++) {
        scores[i] = hst_ok ? (rm[i] + rh[i] + rhst[i]) / 3.0
                           : (rm[i] + rh[i]) / 2.0;
        int axis = -1;
        double best = 0.0;
        for (size_t j = 0; j < d; j++) {
            if (sd[j] <= 0.0) continue;
            double z = fabs((x[i * d + j] - mean[j]) / sd[j]);
            if (z > best) { best = z; axis = (int)j; }
        }
        axes[i] = (int8_t)axis;
    }

    free(sc); free(neg); free(idx); free(ms);
    return 0;
}
