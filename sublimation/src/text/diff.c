// diff.c -- the edit between two line sequences.
//
// Myers' greedy algorithm (An O(ND) Difference Algorithm and Its Variations,
// Algorithmica 1986) over hashed lines, with the common prefix and suffix
// trimmed before the search runs. The trim is not an optimization detail: the
// case every caller actually has is a small change in a large file, and the
// trim turns that into a diff of the changed region rather than of the file.
//
// Lines are hashed to 64 bits and compared by hash, then by bytes when the
// hashes agree. A collision costs a comparison; it never costs correctness.
//
// C23.

#include "sublimation_text.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const char *ptr;
    size_t      len;
    uint64_t    hash;
} sub_line;

// FNV-1a. The distribution only has to be good enough that equal-hash pairs
// are rare; equality is decided by the byte compare below, never by the hash.
static uint64_t line_hash(const char *p, size_t n) {
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < n; i++) {
        h ^= (unsigned char)p[i];
        h *= 1099511628211ULL;
    }
    return h;
}

static void fill_lines(sub_line *out, const char *const *src, const size_t *lens, size_t n) {
    for (size_t i = 0; i < n; i++) {
        out[i].ptr = src[i];
        out[i].len = lens ? lens[i] : strlen(src[i]);
        out[i].hash = line_hash(out[i].ptr, out[i].len);
    }
}

static bool line_eq(const sub_line *x, const sub_line *y) {
    return x->hash == y->hash && x->len == y->len &&
           memcmp(x->ptr, y->ptr, x->len) == 0;
}

// One emitted hunk, coalesced with the previous when the op matches so a run
// of single-line deletes arrives as one hunk rather than as N.
typedef struct {
    sublimation_diff_hunk *out;
    int                    max;
    int                    count;
    sublimation_diff_op    last_op;
    bool                   has_last;
} hunk_sink;

// The run state lives in the sink, so a counting pass (max 0) coalesces
// identically to a writing one and the count a caller sizes its buffer from is
// the count it receives.
static void emit(hunk_sink *sink, sublimation_diff_op op,
                 size_t a_start, size_t a_count, size_t b_start, size_t b_count) {
    if (a_count == 0 && b_count == 0) return;

    if (sink->has_last && sink->last_op == op) {
        if (sink->count > 0 && sink->count - 1 < sink->max) {
            sink->out[sink->count - 1].a_count += a_count;
            sink->out[sink->count - 1].b_count += b_count;
        }
        return;
    }

    if (sink->count < sink->max)
        sink->out[sink->count] = (sublimation_diff_hunk){
            op, a_start, a_count, b_start, b_count };
    sink->count++;
    sink->last_op = op;
    sink->has_last = true;
}

int sublimation_diff_lines(const char *const *a, const size_t *alen, size_t na,
                           const char *const *b, const size_t *blen, size_t nb,
                           sublimation_diff_hunk *out, int max_out,
                           long max_cost) {
    if (max_out < 0) max_out = 0;
    if (!out) max_out = 0;

    hunk_sink sink = { out, max_out, 0, SUBLIMATION_DIFF_EQUAL, false };

    if (na == 0 && nb == 0) return 0;

    sub_line *la = na ? malloc(na * sizeof *la) : NULL;
    sub_line *lb = nb ? malloc(nb * sizeof *lb) : NULL;
    if ((na && !la) || (nb && !lb)) { free(la); free(lb); return -1; }
    fill_lines(la, a, alen, na);
    fill_lines(lb, b, blen, nb);

    // Trim the common prefix and suffix. Everything after this is the part
    // that actually differs, which is usually a small fraction of the input.
    size_t pre = 0;
    while (pre < na && pre < nb && line_eq(&la[pre], &lb[pre])) pre++;

    size_t suf = 0;
    while (suf < na - pre && suf < nb - pre &&
           line_eq(&la[na - 1 - suf], &lb[nb - 1 - suf])) suf++;

    const size_t ma = na - pre - suf;
    const size_t mb = nb - pre - suf;

    if (pre) emit(&sink, SUBLIMATION_DIFF_EQUAL, 0, pre, 0, pre);

    if (ma == 0 || mb == 0) {
        // One side is empty: a pure insert or a pure delete, no search needed.
        if (ma) emit(&sink, SUBLIMATION_DIFF_DELETE, pre, ma, pre, 0);
        if (mb) emit(&sink, SUBLIMATION_DIFF_INSERT, pre, 0, pre, mb);
        if (suf) emit(&sink, SUBLIMATION_DIFF_EQUAL, na - suf, suf, nb - suf, suf);
        free(la); free(lb);
        return sink.count;
    }

    const long budget = max_cost > 0 ? max_cost : (long)(ma + mb);
    const long maxd = (long)(ma + mb) < budget ? (long)(ma + mb) : budget;
    const size_t vsize = (size_t)(2 * maxd + 3);

    // One V row per d, retained so the path can be walked back. This is the
    // memory Myers' basic form costs, and the reason max_cost exists.
    int *trace = malloc(vsize * (size_t)(maxd + 1) * sizeof *trace);
    int *v = malloc(vsize * sizeof *v);
    if (!trace || !v) { free(trace); free(v); free(la); free(lb); return -1; }

    const long off = maxd + 1;
    memset(v, 0, vsize * sizeof *v);

    long found = -1;
    for (long d = 0; d <= maxd && found < 0; d++) {
        for (long k = -d; k <= d; k += 2) {
            long x;
            if (k == -d || (k != d && v[off + k - 1] < v[off + k + 1]))
                x = v[off + k + 1];
            else
                x = v[off + k - 1] + 1;
            long y = x - k;
            while ((size_t)x < ma && (size_t)y < mb &&
                   line_eq(&la[pre + x], &lb[pre + y])) { x++; y++; }
            v[off + k] = (int)x;
            if ((size_t)x >= ma && (size_t)y >= mb) { found = d; break; }
        }
        memcpy(trace + (size_t)d * vsize, v, vsize * sizeof *v);
    }

    if (found < 0) { free(trace); free(v); free(la); free(lb); return -1; }

    // Walk the trace backwards into (x, y) moves, then replay them forwards so
    // hunks come out in source order.
    // Every diagonal move is a step too, and those are bounded by the shorter
    // side rather than by the edit distance: two files differing only at their
    // first and last lines have an edit distance of four and a thousand
    // diagonals between them. Sizing this by `found` alone overflows exactly
    // there.
    const size_t diag_max = ma < mb ? ma : mb;
    size_t steps_cap = (size_t)found + diag_max + 4;
    long (*steps)[4] = malloc(steps_cap * sizeof *steps);
    if (!steps) { free(trace); free(v); free(la); free(lb); return -1; }
    size_t nsteps = 0;

    long x = (long)ma, y = (long)mb;
    for (long d = found; d > 0; d--) {
        const int *row = trace + (size_t)(d - 1) * vsize;
        const long k = x - y;
        long prev_k;
        if (k == -d || (k != d && row[off + k - 1] < row[off + k + 1]))
            prev_k = k + 1;
        else
            prev_k = k - 1;
        const long prev_x = row[off + prev_k];
        const long prev_y = prev_x - prev_k;

        while (x > prev_x && y > prev_y) { steps[nsteps][0] = --x; steps[nsteps][1] = --y;
                                           steps[nsteps][2] = 0; nsteps++; }
        steps[nsteps][0] = prev_x; steps[nsteps][1] = prev_y;
        steps[nsteps][2] = (x > prev_x) ? 1 : 2;   // 1 = delete, 2 = insert
        nsteps++;
        x = prev_x; y = prev_y;
    }
    while (x > 0 && y > 0) { steps[nsteps][0] = --x; steps[nsteps][1] = --y;
                             steps[nsteps][2] = 0; nsteps++; }

    for (size_t i = nsteps; i-- > 0;) {
        const long sx = steps[i][0], sy = steps[i][1];
        switch (steps[i][2]) {
            case 0: emit(&sink, SUBLIMATION_DIFF_EQUAL, pre + (size_t)sx, 1,
                         pre + (size_t)sy, 1); break;
            case 1: emit(&sink, SUBLIMATION_DIFF_DELETE, pre + (size_t)sx, 1,
                         pre + (size_t)sy, 0); break;
            default: emit(&sink, SUBLIMATION_DIFF_INSERT, pre + (size_t)sx, 0,
                          pre + (size_t)sy, 1); break;
        }
    }

    if (suf) emit(&sink, SUBLIMATION_DIFF_EQUAL, na - suf, suf, nb - suf, suf);

    free(steps); free(trace); free(v); free(la); free(lb);
    return sink.count;
}
