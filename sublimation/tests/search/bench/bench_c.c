// Cross-language search bench, C standard library point.
// literal: glibc memmem (two-way). regex: POSIX regcomp/regexec.
// Protocol: <corpusfile> <pattern> <runs> <literal|regex>
// Output: one JSON line {"algo","count","mb_s"}.
#define _GNU_SOURCE
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static unsigned char *slurp(const char *path, size_t *n) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror("open"); exit(1); }
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    unsigned char *b = malloc((size_t)sz + 1);
    if (fread(b, 1, (size_t)sz, f) != (size_t)sz) { exit(1); }
    b[sz] = 0; *n = (size_t)sz; fclose(f);
    return b;
}

static size_t count_literal(const unsigned char *hay, size_t n, const char *pat) {
    size_t m = strlen(pat), c = 0;
    const unsigned char *p = hay, *end = hay + n;
    while (p + m <= end) {
        unsigned char *hit = memmem(p, (size_t)(end - p), pat, m);
        if (!hit) break;
        c++; p = hit + 1;                       // overlapping occurrences
    }
    return c;
}

static size_t count_regex(const unsigned char *hay, regex_t *re) {
    size_t c = 0;
    const char *p = (const char *)hay;
    regmatch_t mt;
    int first = 1;
    while (*p && regexec(re, p, 1, &mt, first ? 0 : REG_NOTBOL) == 0) {
        c++;
        regoff_t step = mt.rm_eo > 0 ? mt.rm_eo : 1;   // non-overlapping leftmost
        p += step;
        first = 0;
    }
    return c;
}

static double median9(double *d) {
    for (int a = 0; a < 9; a++) for (int b = a + 1; b < 9; b++)
        if (d[b] < d[a]) { double t = d[a]; d[a] = d[b]; d[b] = t; }
    return d[4];
}

int main(int argc, char **argv) {
    if (argc < 5) { fprintf(stderr, "usage: %s file pat runs literal|regex\n", argv[0]); return 2; }
    size_t n; unsigned char *hay = slurp(argv[1], &n);
    const char *pat = argv[2];
    int is_regex = strcmp(argv[4], "regex") == 0;
    regex_t re;
    if (is_regex && regcomp(&re, pat, REG_EXTENDED) != 0) { fprintf(stderr, "bad regex\n"); return 1; }

    size_t count = is_regex ? count_regex(hay, &re) : count_literal(hay, n, pat);
    double dt[9];
    for (int r = 0; r < 9; r++) {
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        volatile size_t s = is_regex ? count_regex(hay, &re) : count_literal(hay, n, pat);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        (void)s;
        dt[r] = (double)(t1.tv_sec - t0.tv_sec) + (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;
    }
    double mb = (double)n / 1e6 / median9(dt);
    printf("{\"algo\":\"c_%s\",\"count\":%zu,\"mb_s\":%.0f}\n",
           is_regex ? "posix_regex" : "memmem", count, mb);
    return 0;
}
