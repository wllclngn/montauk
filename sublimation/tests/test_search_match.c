// test_search_match.c -- exercises the shipped sublimation_search API only.
// Reads a face + k + pattern from argv and the haystack from stdin, then prints
// the result of one API call. The byte-parity driver (test_search_match.py) drives
// this against independent Python oracles.
//
//   test_search_match count <fixed|regex|fuzzy> <k> <pattern>   -> match count
//   test_search_match find  <fixed|regex|fuzzy> <k> <pattern>   -> "start end"
//   test_search_match full  <fixed|regex|fuzzy> <k> <pattern>   -> 0 or 1
//
// Pattern arrives as raw argv bytes (the driver passes bytes untouched), so binary
// and high-byte patterns survive.
#include "sublimation_text.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned char *slurp_stdin(size_t *out_len) {
    size_t cap = 1u << 20, len = 0;
    unsigned char *buf = malloc(cap);
    if (!buf) { perror("malloc"); exit(2); }
    for (;;) {
        if (len == cap) { cap *= 2; buf = realloc(buf, cap); if (!buf) { perror("realloc"); exit(2); } }
        size_t got = fread(buf + len, 1, cap - len, stdin);
        len += got;
        if (got == 0) break;
    }
    *out_len = len;
    return buf;
}

int main(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr, "usage: %s count|find|full <fixed|regex|fuzzy> <k> <pattern>\n", argv[0]);
        return 2;
    }
    const char *op = argv[1];
    const char *face = argv[2];
    int k = atoi(argv[3]);
    const char *pat = argv[4];
    size_t plen = strlen(pat);

    unsigned flags = 0;
    if (strcmp(face, "fixed") == 0) flags |= SUBLIMATION_SEARCH_FIXED;
    else if (strcmp(face, "fixedi") == 0) flags |= SUBLIMATION_SEARCH_FIXED | SUBLIMATION_SEARCH_ICASE;
    else if (strcmp(face, "regexi") == 0) flags |= SUBLIMATION_SEARCH_ICASE;
    else if (strcmp(face, "fuzzy") == 0) { /* fuzzy selected by k > 0 below */ }
    else if (strcmp(face, "regex") != 0) { fprintf(stderr, "bad face: %s\n", face); return 2; }

    sublimation_search s;
    sublimation_search_compile(&s, pat, plen, flags, k);

    size_t n; unsigned char *hay = slurp_stdin(&n);

    if (!sublimation_search_valid(&s)) { printf("-1\n"); free(hay); return 0; }

    if (strcmp(op, "count") == 0) {
        printf("%zu\n", sublimation_search_count(&s, (const char *)hay, n));
    } else if (strcmp(op, "find") == 0) {
        long end = -1;
        long start = sublimation_search_find(&s, (const char *)hay, n, &end);
        if (start < 0) printf("-1\n");
        else printf("%ld %ld\n", start, end);
    } else if (strcmp(op, "full") == 0) {
        printf("%d\n", sublimation_search_full_match(&s, (const char *)hay, n));
    } else if (strcmp(op, "findfrom") == 0) {
        // Walk find_from over every start offset in [0, n] in one process, so a
        // continuation-restart bug (a shifted anchor, a missed leftmost match on
        // resume) shows as a divergence at some `from` against the oracle.
        for (size_t from = 0; from <= n; from++) {
            long end = -1;
            long start = sublimation_search_find_from(&s, (const char *)hay, n, from, &end);
            printf("%zu %ld\n", from, start);
        }
    } else {
        fprintf(stderr, "bad op: %s\n", op);
        free(hay);
        return 2;
    }
    free(hay);
    return 0;
}
