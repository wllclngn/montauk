// sublimation -- command-line front door to the flow-model sort sub-system.
//
// Reads a numeric stream on stdin, runs one sublimation primitive, writes the
// result to stdout. This is the data-side answer to "stop reaching for awk and
// sort": ordering, percentiles, k-th selection, value lookup, disorder
// classification, structural location, and a max-entropy randomness verdict --
// all through the flow-model library, no shell-stats pipeline.
//
//   sublimation sort        [--field N] [--delim D] [--desc]
//   sublimation quantile Q  [--field N] [--delim D]      (Q in 0..1)
//   sublimation select K    [--field N] [--delim D]      (K-th smallest, 0-based)
//   sublimation searchsorted V [--field N] [--delim D]   (insertion index of V)
//   sublimation classify    [--field N] [--delim D]
//   sublimation locate CLASS [--field N] [--window W] [--stride S]
//   sublimation rand        [--field N] [--delim D]
//   sublimation grep PATTERN                             (regex line filter, via the NFA)
//   sublimation contains STR                             (substring line filter, via Boyer-Moore)
//
// CLASS is one of: sorted reversed nearly-sorted few-unique random phased spectral
// --field N pulls the N-th (1-based) delimited column per line, so awk's column
// extraction is folded in -- no `awk '{print $N}' | ...` needed.
//
// The numeric commands read one value per line (or per --field column). grep and
// contains instead read whole text lines and print the matches -- the order-free
// search side of sublimation, so the one tool covers grep too, not just awk/sort.

#include "sublimation.h"
#include "sublimation_search.h"
#include "sublimation_randomness.h"
#include "sublimation_text.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static void usage(FILE *out) {
    fputs(
        "usage: sublimation COMMAND [options]   (reads numbers on stdin)\n"
        "\n"
        "  sort                  order ascending (or --desc)\n"
        "  quantile Q            the Q-quantile, Q in 0..1 (e.g. 0.99)\n"
        "  select K              the K-th smallest value, 0-based\n"
        "  searchsorted V        insertion index of V in the sorted input\n"
        "  classify              disorder class + profile of the stream\n"
        "  locate CLASS          windows whose disorder class == CLASS\n"
        "  rand                  max-entropy randomness confidence\n"
        "  grep PATTERN          print stdin lines matching the regex (via the NFA)\n"
        "  contains STR          print stdin lines containing STR (Boyer-Moore, case-insensitive)\n"
        "\n"
        "  CLASS: sorted reversed nearly-sorted few-unique random phased spectral\n"
        "\n"
        "options:\n"
        "  --field N             pull the N-th (1-based) delimited column per line\n"
        "  --delim D             column delimiter chars (default: whitespace)\n"
        "  --desc                sort descending\n"
        "  --window W            window size for locate (default 512)\n"
        "  --stride S            window stride for locate (default = window)\n",
        out);
}

// Grow-on-demand double buffer.
typedef struct { double *v; size_t n, cap; } Vec;
static void vec_push(Vec *a, double x) {
    if (a->n == a->cap) {
        a->cap = a->cap ? a->cap * 2 : 1024;
        a->v = (double *)realloc(a->v, a->cap * sizeof(double));
        if (!a->v) { fputs("sublimation: out of memory\n", stderr); exit(1); }
    }
    a->v[a->n++] = x;
}

// Pull the field-th (1-based) token of `line` split on any char in `delim`;
// field<=0 means the whole line. Returns NULL if the field is absent.
static char *field_token(char *line, int field, const char *delim) {
    if (field <= 0) return line;
    char *save = NULL;
    char *tok = strtok_r(line, delim, &save);
    for (int i = 1; tok && i < field; i++) tok = strtok_r(NULL, delim, &save);
    return tok;
}

// Read stdin into `out`, parsing one double per line (or per --field column).
// Lines whose field does not parse as a number are skipped (and counted).
static size_t read_values(Vec *out, int field, const char *delim) {
    char *line = NULL;
    size_t cap = 0;
    ssize_t len;
    size_t skipped = 0;
    while ((len = getline(&line, &cap, stdin)) != -1) {
        char buf[4096];
        // strtok mutates; work on a bounded copy so long lines are safe.
        const char *src = line;
        if (field > 0) {
            size_t n = (size_t)len < sizeof(buf) ? (size_t)len : sizeof(buf) - 1;
            memcpy(buf, line, n);
            buf[n] = '\0';
            char *tok = field_token(buf, field, delim);
            if (!tok) { skipped++; continue; }
            src = tok;
        }
        char *end = NULL;
        double x = strtod(src, &end);
        if (end == src) { skipped++; continue; }  // no number here
        vec_push(out, x);
    }
    free(line);
    return skipped;
}

static int parse_class(const char *s, sub_disorder_t *out) {
    if (!strcmp(s, "sorted"))        { *out = SUB_SORTED;        return 1; }
    if (!strcmp(s, "reversed"))      { *out = SUB_REVERSED;      return 1; }
    if (!strcmp(s, "nearly-sorted")) { *out = SUB_NEARLY_SORTED; return 1; }
    if (!strcmp(s, "few-unique"))    { *out = SUB_FEW_UNIQUE;    return 1; }
    if (!strcmp(s, "random"))        { *out = SUB_RANDOM;        return 1; }
    if (!strcmp(s, "phased"))        { *out = SUB_PHASED;        return 1; }
    if (!strcmp(s, "spectral"))      { *out = SUB_SPECTRAL;      return 1; }
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2 || !strcmp(argv[1], "-h") || !strcmp(argv[1], "--help")) {
        usage(stdout);
        return 0;
    }
    const char *cmd = argv[1];

    int field = 0;
    const char *delim = " \t";
    int desc = 0;
    size_t window = 512, stride = 0;
    const char *pos = NULL;  // positional arg (Q / K / V / CLASS)

    for (int i = 2; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "--field") && i + 1 < argc) field = atoi(argv[++i]);
        else if (!strcmp(a, "--delim") && i + 1 < argc) delim = argv[++i];
        else if (!strcmp(a, "--desc")) desc = 1;
        else if (!strcmp(a, "--window") && i + 1 < argc) window = strtoull(argv[++i], NULL, 10);
        else if (!strcmp(a, "--stride") && i + 1 < argc) stride = strtoull(argv[++i], NULL, 10);
        else if (a[0] == '-') { fprintf(stderr, "sublimation: unknown option '%s'\n", a); return 2; }
        else if (!pos) pos = a;
        else { fprintf(stderr, "sublimation: unexpected argument '%s'\n", a); return 2; }
    }
    if (stride == 0) stride = window;

    // Text commands are line filters, not numeric streams: read whole lines and
    // print the ones that match. This is the order-free search side -- grep's job,
    // now sublimation's, through the same engines montauk uses.
    if (!strcmp(cmd, "grep") || !strcmp(cmd, "contains")) {
        if (!pos) {
            fprintf(stderr, "sublimation: %s needs a %s\n", cmd,
                    !strcmp(cmd, "grep") ? "PATTERN" : "STR");
            return 2;
        }
        int is_grep = !strcmp(cmd, "grep");
        sublimation_nfa nfa;
        sublimation_bmh bmh;
        if (is_grep) {
            sublimation_nfa_compile(&nfa, pos, strlen(pos));
            if (!sublimation_nfa_valid(&nfa)) {
                fprintf(stderr, "sublimation: bad regex '%s'\n", pos);
                return 2;
            }
        } else {
            sublimation_bmh_compile(&bmh, pos, strlen(pos));
        }
        char *line = NULL;
        size_t cap = 0;
        ssize_t len;
        while ((len = getline(&line, &cap, stdin)) != -1) {
            size_t mlen = (size_t)len;
            if (mlen && line[mlen - 1] == '\n') mlen--;  // match without the trailing newline
            long hit = is_grep ? sublimation_nfa_find(&nfa, line, mlen, NULL)
                               : sublimation_bmh_search(&bmh, line, mlen);
            if (hit >= 0) fwrite(line, 1, (size_t)len, stdout);
        }
        free(line);
        return 0;
    }

    Vec data = {0};
    read_values(&data, field, delim);
    if (data.n == 0) {
        fputs("sublimation: no numeric values on stdin\n", stderr);
        return 1;
    }

    if (!strcmp(cmd, "sort")) {
        sublimation_f64(data.v, data.n);
        if (desc) for (size_t i = 0; i < data.n; i++) printf("%.12g\n", data.v[data.n - 1 - i]);
        else      for (size_t i = 0; i < data.n; i++) printf("%.12g\n", data.v[i]);

    } else if (!strcmp(cmd, "quantile")) {
        if (!pos) { fputs("sublimation: quantile needs Q (0..1)\n", stderr); return 2; }
        double q = strtod(pos, NULL);
        if (q < 0.0 || q > 1.0) { fputs("sublimation: Q must be in 0..1\n", stderr); return 2; }
        sublimation_f64(data.v, data.n);
        size_t idx = (size_t)(q * (double)data.n);
        if (idx >= data.n) idx = data.n - 1;
        printf("%.12g\n", data.v[idx]);

    } else if (!strcmp(cmd, "select")) {
        if (!pos) { fputs("sublimation: select needs K (0-based)\n", stderr); return 2; }
        long long k = atoll(pos);
        if (k < 0 || (size_t)k >= data.n) {
            fprintf(stderr, "sublimation: K out of range (0..%zu)\n", data.n - 1);
            return 2;
        }
        printf("%.12g\n", sublimation_select_f64(data.v, data.n, (size_t)k));

    } else if (!strcmp(cmd, "searchsorted")) {
        if (!pos) { fputs("sublimation: searchsorted needs a value\n", stderr); return 2; }
        double target = strtod(pos, NULL);
        sublimation_f64(data.v, data.n);  // searchsorted needs sorted input
        printf("%zu\n", sublimation_searchsorted_f64(data.v, data.n, target, 0));

    } else if (!strcmp(cmd, "classify")) {
        sub_profile_t p = sublimation_classify_f64(data.v, data.n);
        printf("%s  n=%zu  inversion_ratio=%.3f  lis=%zu  distinct~%zu  runs=%zu",
               sublimation_disorder_name(p.disorder), data.n,
               (double)p.inversion_ratio, p.lis_length, p.distinct_estimate, p.run_count);
        if (p.phase_boundary) printf("  phase_boundary=%zu", p.phase_boundary);
        putchar('\n');

    } else if (!strcmp(cmd, "locate")) {
        sub_disorder_t target;
        if (!pos || !parse_class(pos, &target)) {
            fputs("sublimation: locate needs CLASS (sorted reversed nearly-sorted "
                  "few-unique random phased spectral)\n", stderr);
            return 2;
        }
        if (window > data.n) {
            fprintf(stderr, "sublimation: --window %zu exceeds input length %zu\n", window, data.n);
            return 2;
        }
        size_t cap = data.n / stride + 2;
        sub_match_t *m = (sub_match_t *)malloc(cap * sizeof(sub_match_t));
        size_t k = sublimation_locate_f64(data.v, data.n, window, stride, target, m, cap);
        printf("%zu window(s) matching %s:\n", k, sublimation_disorder_name(target));
        for (size_t i = 0; i < k; i++)
            printf("  [%zu,%zu)  inv=%.2f  distinct~%zu\n",
                   m[i].start, m[i].start + m[i].len,
                   (double)m[i].inversion_ratio, m[i].distinct_estimate);
        free(m);

    } else if (!strcmp(cmd, "rand")) {
        sub_randomness_t r = sublimation_randomness_f64(data.v, data.n);
        static const char *lens[SUB_RANDOMNESS_LENSES] =
            {"hook", "lis", "inv", "distinct", "hvg", "bandt-pompe"};
        printf("confidence=%.3f  (k=%u/%u agree)\n", (double)r.confidence,
               r.agree_count, r.lens_count);
        for (int i = 0; i < SUB_RANDOMNESS_LENSES; i++) {
            if (r.lens_available[i]) printf("  %-12s %.2f\n", lens[i], (double)r.lens[i]);
            else                     printf("  %-12s --\n", lens[i]);
        }

    } else {
        fprintf(stderr, "sublimation: unknown command '%s'\n\n", cmd);
        usage(stderr);
        free(data.v);
        return 2;
    }

    free(data.v);
    return 0;
}
