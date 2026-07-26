// Tally: distinct newline-separated records with their counts, over a bounded
// buffer, sorted high-to-low frequency. The library's FFI-shaped form of the
// CLI's tally/distinct/count verbs, so an embedder (vector) reaches them
// directly instead of shelling out. The CLI keeps its own streaming interner
// for unbounded stdin; this is the bounded, offset-returning counterpart --
// division by target, not a second copy of the same job.
#include "include/sublimation_text.h"
#include "include/sublimation.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Internal open-addressing map over (ptr, len) spans into the caller's buffer.
// FNV-1a, power-of-two capacity, grow at 50% load. Records are compared by
// bytes, so equal records share a slot and their count accumulates.
typedef struct {
    const char **kptr;   // span start (into the caller's buffer)
    size_t      *klen;   // span length
    uint64_t    *count;  // occurrences
    size_t      *seen;   // first-seen index, the tie-break
    size_t cap, used;
} tally_map;

static uint64_t fnv_span(const char *s, size_t n) {
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < n; i++) { h ^= (unsigned char)s[i]; h *= 1099511628211ULL; }
    return h;
}

static int tm_init(tally_map *m) {
    m->cap = 1024; m->used = 0;
    m->kptr  = (const char **)calloc(m->cap, sizeof(char *));
    m->klen  = (size_t *)calloc(m->cap, sizeof(size_t));
    m->count = (uint64_t *)calloc(m->cap, sizeof(uint64_t));
    m->seen  = (size_t *)calloc(m->cap, sizeof(size_t));
    if (!m->kptr || !m->klen || !m->count || !m->seen) return -1;
    return 0;
}

static void tm_free(tally_map *m) {
    free(m->kptr); free(m->klen); free(m->count); free(m->seen);
}

static int span_eq(const char *a, size_t an, const char *b, size_t bn) {
    return an == bn && memcmp(a, b, an) == 0;
}

static int tm_grow(tally_map *m) {
    size_t nc = m->cap * 2;
    const char **nk = (const char **)calloc(nc, sizeof(char *));
    size_t *nl = (size_t *)calloc(nc, sizeof(size_t));
    uint64_t *ncnt = (uint64_t *)calloc(nc, sizeof(uint64_t));
    size_t *ns = (size_t *)calloc(nc, sizeof(size_t));
    if (!nk || !nl || !ncnt || !ns) { free(nk); free(nl); free(ncnt); free(ns); return -1; }
    for (size_t j = 0; j < m->cap; j++) {
        if (!m->kptr[j]) continue;
        size_t p = fnv_span(m->kptr[j], m->klen[j]) & (nc - 1);
        while (nk[p]) p = (p + 1) & (nc - 1);
        nk[p] = m->kptr[j]; nl[p] = m->klen[j]; ncnt[p] = m->count[j]; ns[p] = m->seen[j];
    }
    tm_free(m);
    m->kptr = nk; m->klen = nl; m->count = ncnt; m->seen = ns; m->cap = nc;
    return 0;
}

// Bump the count for span (s, len), inserting on first sight with the next
// first-seen index. Returns 0 on success, -1 on allocation failure.
static int tm_bump(tally_map *m, const char *s, size_t len) {
    if ((m->used + 1) * 2 >= m->cap && tm_grow(m) != 0) return -1;
    size_t p = fnv_span(s, len) & (m->cap - 1);
    while (m->kptr[p] && !span_eq(m->kptr[p], m->klen[p], s, len))
        p = (p + 1) & (m->cap - 1);
    if (m->kptr[p]) { m->count[p]++; return 0; }
    m->kptr[p] = s; m->klen[p] = len; m->count[p] = 1; m->seen[p] = m->used++;
    return 0;
}

size_t sublimation_tally(const char *data, size_t n, sub_tally_t *out,
                         size_t out_cap, uint64_t *total) {
    if (total) *total = 0;
    tally_map m;
    if (tm_init(&m) != 0) return 0;

    // Split on '\n'; a trailing record with no newline still counts. An empty
    // buffer has no records; a lone "\n" is one empty record, matching the CLI.
    uint64_t records = 0;
    size_t start = 0;
    for (size_t i = 0; i <= n; i++) {
        if (i == n) {
            if (i > start) { if (tm_bump(&m, data + start, i - start) != 0) { tm_free(&m); return 0; } records++; }
            break;
        }
        if (data[i] == '\n') {
            if (tm_bump(&m, data + start, i - start) != 0) { tm_free(&m); return 0; }
            records++;
            start = i + 1;
        }
    }
    if (total) *total = records;

    // Pack (count, tie) into a u64 and sort ascending with the library's own
    // sort, then read descending: highest count first, ties by first-seen (the
    // low bits invert the first-seen index so a lower index emerges first on the
    // descending read). first-seen is dense and unique, so no two packs collide.
    // count and the index are each capped to 32 bits, ample for a bounded
    // in-conversation buffer -- the CLI owns the unbounded stream. A seen->slot
    // table recovers the map slot (offset/length/real count) after the sort, so
    // no parallel permutation is needed.
    if (m.used == 0) { tm_free(&m); return 0; }
    size_t distinct = m.used;
    uint64_t *packed    = (uint64_t *)malloc(distinct * sizeof(uint64_t));
    size_t   *seen2slot = (size_t *)malloc(distinct * sizeof(size_t));
    if (!packed || !seen2slot) { free(packed); free(seen2slot); tm_free(&m); return 0; }
    size_t d = 0;
    for (size_t j = 0; j < m.cap; j++) {
        if (!m.kptr[j]) continue;
        uint64_t c = m.count[j] > 0xFFFFFFFFULL ? 0xFFFFFFFFULL : m.count[j];
        packed[d++] = (c << 32) | (0xFFFFFFFFULL - m.seen[j]);
        seen2slot[m.seen[j]] = j;
    }
    sublimation_u64(packed, distinct);  // ascending
    size_t written = 0;
    for (size_t r = distinct; r-- > 0 && written < out_cap; ) {
        size_t s = (size_t)(0xFFFFFFFFULL - (packed[r] & 0xFFFFFFFFULL));
        size_t j = seen2slot[s];
        out[written].offset = (size_t)(m.kptr[j] - data);
        out[written].length = m.klen[j];
        out[written].count  = m.count[j];
        written++;
    }
    free(packed); free(seen2slot); tm_free(&m);
    return distinct;
}
