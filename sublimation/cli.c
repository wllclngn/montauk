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
//   sublimation sum|mean|min|max [--field N]             (column reduction -- awk '{s+=$N}...')
//   sublimation count                                    (line count -- wc -l)
//   sublimation classify    [--field N] [--delim D]
//   sublimation characterize [--field N] [--delim D]     (structural verdict -- class, rand, efficiency)
//   sublimation locate CLASS [--field N] [--window W] [--stride S]
//   sublimation rand        [--field N] [--delim D]
//   sublimation grep PATTERN  [-i] [-o] [-v] [-c] [-n]   (regex line filter, via the NFA)
//   sublimation contains STR  [-v] [-c] [-n]             (substring line filter, Boyer-Moore)
//   sublimation field N[,M..] [--delim D]                (column(s) -- awk '{print $N}', '{print $1,$3}')
//   sublimation where 'N OP V' [--delim D]               (numeric column filter -- awk '$N OP V')
//
// CLASS is one of: sorted reversed nearly-sorted few-unique random phased spectral
// --field N pulls the N-th (1-based) delimited column per line, so awk's column
// extraction is folded in -- no `awk '{print $N}' | ...` needed.
//
// The numeric commands read one value per line (or per --field column). grep,
// contains, and field read whole text lines; grep/contains print matches (the
// order-free search side), field prints a column. One tool for sort, awk, and grep.

#include "sublimation.h"
#include "sublimation_search.h"
#include "sublimation_randomness.h"
#include "sublimation_text.h"

#include "util/sink.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>

// Data output (stdout) drains through one buffered sink instead of a syscall
// per printf; stderr diagnostics stay on stderr unchanged.
static montauk_sink g_out;
static void drain_out(void) { montauk_sink_drain(&g_out); }

static void usage(FILE *out) {
    fputs(
        "usage: sublimation COMMAND [options]   (reads numbers on stdin)\n"
        "\n"
        "  sort                  order ascending (or --desc)\n"
        "  quantile Q            the Q-quantile, Q in 0..1 (e.g. 0.99); --nearest for nearest-rank\n"
        "  select K              the K-th smallest value, 0-based\n"
        "  searchsorted V        insertion index of V in the sorted input\n"
        "  sum / mean            sum / mean of the value stream\n"
        "  stdev / variance      sample (n-1) standard deviation / variance\n"
        "  min / max             minimum / maximum value\n"
        "  count                 number of input lines (wc -l)\n"
        "  distinct              count of distinct tokens (sort | uniq | wc -l)\n"
        "  tally                 per-token frequency, high to low (sort | uniq -c | sort -rn)\n"
        "  classify              disorder class + profile of the stream\n"
        "  locate CLASS          windows whose disorder class == CLASS\n"
        "  rand                  max-entropy randomness confidence\n"
        "  characterize          structural verdict: class, rand confidence, sort efficiency\n"
        "  grep PATTERN [FILE..] lines matching the regex (Thompson NFA); stdin or FILE(s)\n"
        "  contains STR [FILE..] lines containing STR (Boyer-Moore-Horspool); stdin or FILE(s)\n"
        "  field N[,M..] [FILE..] the N-th column, or a comma-list, of each line (awk '{print $N}')\n"
        "  where 'N OP V' [FILE] lines where field N OP V (awk '$N OP V'; OP: < <= > >= == !=)\n"
        "\n"
        "  CLASS: sorted reversed nearly-sorted few-unique random phased spectral\n"
        "\n"
        "options:\n"
        "  --field N             pull the N-th (1-based) delimited column per line\n"
        "  --delim D             column delimiter chars (default: whitespace)\n"
        "  --desc                sort descending\n"
        "  --window W            window size for locate (default 512)\n"
        "  --stride S            window stride for locate (default = window)\n"
        "  -v / -c / -n          grep/contains: invert match / count only / line number\n"
        "  -i / -o               grep: case-insensitive regex / print only the match\n"
        "  -q / -m N             grep: quiet (exit status only) / stop after N matches\n"
        "  -E                    grep: extended regex (already the default; accepted for compat)\n"
        "  short flags bundle    -iE == -i -E, -vn == -v -n, ...\n"
        "  --nearest             quantile: nearest-rank order statistic (not the estimator)\n"
        "\n"
        "exit: grep/contains/field return 0 when something matched, 1 when nothing did.\n",
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

    // One stdout sink for all data output; atexit covers every return/exit path,
    // streaming loops drain periodically (below) to bound memory.
    montauk_sink_init(&g_out, 1);
    atexit(drain_out);

    int field = 0;
    const char *delim = " \t";
    int desc = 0;
    size_t window = 512, stride = 0;
    int invert = 0, count_only = 0, number = 0;  // grep/contains line-filter flags
    int icase = 0, only_match = 0;                // grep -i (regex case-fold), grep -o (matches only)
    int quiet = 0;                                // grep -q: exit status only, no output
    long max_count = 0;                           // grep -m N: stop after N matches (0 = unlimited)
    int nearest = 0;                              // quantile --nearest: nearest-rank, not estimator
    const char *pos = NULL;  // positional arg (Q / K / V / CLASS / N)
    const char *files[256];  // grep/contains/field: input files after the pattern
    int nfiles = 0;          // 0 -> read stdin (the pipe case)

    for (int i = 2; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "--field") && i + 1 < argc) field = atoi(argv[++i]);
        else if (!strcmp(a, "--delim") && i + 1 < argc) delim = argv[++i];
        else if (!strcmp(a, "--desc")) desc = 1;
        else if (!strcmp(a, "--window") && i + 1 < argc) window = strtoull(argv[++i], NULL, 10);
        else if (!strcmp(a, "--stride") && i + 1 < argc) stride = strtoull(argv[++i], NULL, 10);
        else if (!strcmp(a, "--nearest")) nearest = 1;  // quantile: nearest-rank order statistic
        else if (!strcmp(a, "-m") && i + 1 < argc) max_count = strtol(argv[++i], NULL, 10);  // grep -m N
        else if (a[0] == '-' && a[1] && a[1] != '-') {
            // Bundled short flags, getopt-style: -iE == -i -E, -vn == -v -n. Each
            // char is one boolean grep flag. -E (extended regex) is a no-op:
            // sublimation's NFA is already RE2-lineage ERE, so it is accepted for
            // grep compatibility rather than switching dialects.
            for (const char *f = a + 1; *f; f++) {
                switch (*f) {
                    case 'v': invert = 1; break;       // grep -v: print non-matching
                    case 'c': count_only = 1; break;   // grep -c: count, not lines
                    case 'n': number = 1; break;       // grep -n: 1-based line number
                    case 'i': icase = 1; break;        // grep -i: ASCII case-insensitive
                    case 'o': only_match = 1; break;   // grep -o: print only the match
                    case 'q': quiet = 1; break;        // grep -q: exit status only, no output
                    case 'E': break;                   // grep -E: already extended; accept, no-op
                    default:
                        fprintf(stderr, "sublimation: unknown option '-%c'\n", *f);
                        return 2;
                }
            }
        }
        else if (a[0] == '-') { fprintf(stderr, "sublimation: unknown option '%s'\n", a); return 2; }
        else if (!pos) pos = a;
        else if (nfiles < 256) files[nfiles++] = a;   // extra positionals = input files
        else { fprintf(stderr, "sublimation: too many file arguments\n"); return 2; }
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
        size_t plen = strlen(pos);
        sublimation_nfa nfa;
        sublimation_bmh bmh;
        if (is_grep) {
            sublimation_nfa_compile_ex(&nfa, pos, plen, icase);   // -i folds ASCII case
            if (!sublimation_nfa_valid(&nfa)) {
                fprintf(stderr, "sublimation: bad regex '%s'\n", pos);
                return 2;
            }
        } else {
            sublimation_bmh_compile(&bmh, pos, plen);  // contains is ASCII case-insensitive already
        }
        char *line = NULL;
        size_t cap = 0;
        ssize_t len;
        long matches = 0;
        int done = 0;                     // -q / -m N: stop early once satisfied
        int multi = nfiles > 1;           // prefix "file:" when grepping several files
        // Read each named file, or stdin when none were given. A single named file
        // is the common `grep PATTERN file` idiom -- sublimation serves it directly
        // now instead of treating the path as an unexpected argument. Traversal
        // (-r, globs) is still the real grep's job, by target.
        for (int fi = 0; (nfiles == 0 ? fi < 1 : fi < nfiles) && !done; fi++) {
            FILE *in = stdin;
            const char *fname = NULL;
            if (nfiles > 0) {
                fname = files[fi];
                in = fopen(fname, "r");
                if (!in) { fprintf(stderr, "sublimation: cannot open '%s'\n", fname); continue; }
            }
            long lineno = 0;
            while (!done && (len = getline(&line, &cap, in)) != -1) {
                lineno++;
                size_t mlen = (size_t)len;
                if (mlen && line[mlen - 1] == '\n') mlen--;  // match without the trailing newline

                if (only_match) {
                    // grep -o: emit each non-overlapping match span, one per line.
                    size_t off = 0;
                    while (off <= mlen) {
                        long end = -1;
                        long s = is_grep ? sublimation_nfa_find(&nfa, line + off, mlen - off, &end)
                                         : sublimation_bmh_search(&bmh, line + off, mlen - off);
                        if (s < 0) break;
                        size_t mstart = off + (size_t)s;
                        size_t mend = is_grep ? off + (size_t)end : mstart + plen;
                        if (mend > mstart) {
                            matches++;
                            if (!quiet && !count_only) {
                                if (multi) montauk_sink_appendf(&g_out, "%s:", fname);
                                if (number) montauk_sink_appendf(&g_out, "%ld:", lineno);
                                montauk_sink_append(&g_out, line + mstart, mend - mstart);
                                montauk_sink_appendc(&g_out, '\n');
                                if (g_out.len >= (1u << 16)) montauk_sink_drain(&g_out);
                            }
                            off = mend;            // continue after the match (non-overlapping)
                            if (quiet || (max_count && matches >= max_count)) { done = 1; break; }
                        } else {
                            off = mstart + 1;      // zero-width match: step past to make progress
                        }
                    }
                    continue;
                }

                long hit = is_grep ? sublimation_nfa_find(&nfa, line, mlen, NULL)
                                   : sublimation_bmh_search(&bmh, line, mlen);
                int show = (hit >= 0);
                if (invert) show = !show;     // grep -v
                if (show) {
                    matches++;
                    if (!quiet && !count_only) {
                        if (multi) montauk_sink_appendf(&g_out, "%s:", fname);
                        if (number) montauk_sink_appendf(&g_out, "%ld:", lineno);   // grep -n
                        montauk_sink_append(&g_out, line, (size_t)len);
                        if (g_out.len >= (1u << 16)) montauk_sink_drain(&g_out);  // bound memory
                    }
                    if (quiet || (max_count && matches >= max_count)) done = 1;  // grep -q / -m
                }
            }
            if (in != stdin) fclose(in);
        }
        free(line);
        if (count_only) montauk_sink_appendf(&g_out, "%ld\n", matches);
        // grep exit semantics: 0 if anything matched, 1 if nothing did -- so
        // `if ... | sublimation grep` and `&&` chains are correct without a
        // caller-side buffering hack.
        return matches ? 0 : 1;
    }

    // Column projection: print the N-th delimited field, or a comma-list of
    // fields, of each line. `field N` is awk '{print $N}'; `field 1,3` is awk
    // '{print $1,$3}': the requested column(s) joined by a single space (awk's
    // default OFS), an empty string for a missing column, one line per record --
    // byte-identical to awk for one or many columns. Splits on any --delim char
    // (default whitespace).
    if (!strcmp(cmd, "field")) {
        if (!pos) { fputs("sublimation: field needs N or a comma-list N,M,... (1-based)\n", stderr); return 2; }
        int cols[64], ncol = 0;
        for (const char *p = pos; *p; ) {
            char *e;
            long c = strtol(p, &e, 10);
            if (e == p || c < 1 || ncol >= 64) {
                fputs("sublimation: field needs N or a comma-list N,M,... (1-based)\n", stderr);
                return 2;
            }
            cols[ncol++] = (int)c;
            p = e;
            if (*p == ',') p++;
            else if (*p) { fputs("sublimation: field columns are comma-separated (e.g. 1,3)\n", stderr); return 2; }
        }
        char *line = NULL;
        size_t cap = 0;
        ssize_t len;
        long printed = 0;
        for (int fi = 0; nfiles == 0 ? fi < 1 : fi < nfiles; fi++) {
            FILE *in = stdin;
            if (nfiles > 0) {
                in = fopen(files[fi], "r");
                if (!in) { fprintf(stderr, "sublimation: cannot open '%s'\n", files[fi]); continue; }
            }
            while ((len = getline(&line, &cap, in)) != -1) {
                size_t mlen = (size_t)len;
                if (mlen && line[mlen - 1] == '\n') mlen--;
                // awk-exact: capture the requested column(s), print them joined by a
                // single space (awk's default OFS), empty for a missing column, one
                // line per record -- so `field N` matches `{print $N}` even when a
                // line is blank or short.
                const char *got[64];
                size_t gotlen[64];
                for (int k = 0; k < ncol; k++) { got[k] = NULL; gotlen[k] = 0; }
                size_t i = 0;
                int f = 0;
                while (i < mlen) {
                    while (i < mlen && strchr(delim, line[i])) i++;       // skip delims
                    if (i >= mlen) break;
                    size_t start = i;
                    while (i < mlen && !strchr(delim, line[i])) i++;      // token body
                    f++;
                    for (int k = 0; k < ncol; k++)
                        if (cols[k] == f) { got[k] = line + start; gotlen[k] = i - start; }
                }
                for (int k = 0; k < ncol; k++) {
                    if (k) montauk_sink_appendc(&g_out, ' ');
                    if (got[k]) montauk_sink_append(&g_out, got[k], gotlen[k]);
                }
                montauk_sink_appendc(&g_out, '\n');
                if (g_out.len >= (1u << 16)) montauk_sink_drain(&g_out);  // bound memory
                printed++;
            }
            if (in != stdin) fclose(in);
        }
        free(line);
        return printed ? 0 : 1;
    }

    // Numeric column predicate: print lines whose field N satisfies one numeric
    // comparison -- awk '$N OP V'. Single predicate ONLY by design: the moment it
    // grows && / || / ~ it has rebuilt awk's expression evaluator, so compound
    // logic is two `where`s in a pipe or it is real awk. OP in < <= > >= == !=. A
    // missing or non-numeric field coerces to 0 (awk's numeric context), so
    // `where '2 > 100'` is byte-identical to `awk '$2 > 100'` on numeric columns.
    if (!strcmp(cmd, "where")) {
        if (!pos) {
            fputs("sublimation: where needs 'N OP V' (quote it -- the shell eats >), e.g. '2 > 100'\n", stderr);
            return 2;
        }
        const char *p = pos;
        while (*p == ' ') p++;
        char *e;
        long col = strtol(p, &e, 10);
        if (e == p || col < 1) {
            fputs("sublimation: where: predicate starts with a 1-based column, e.g. '2 > 100'\n", stderr);
            return 2;
        }
        p = e;
        while (*p == ' ') p++;
        enum { OP_LT, OP_LE, OP_GT, OP_GE, OP_EQ, OP_NE } op;
        if      (p[0] == '<' && p[1] == '=') { op = OP_LE; p += 2; }
        else if (p[0] == '>' && p[1] == '=') { op = OP_GE; p += 2; }
        else if (p[0] == '=' && p[1] == '=') { op = OP_EQ; p += 2; }
        else if (p[0] == '!' && p[1] == '=') { op = OP_NE; p += 2; }
        else if (p[0] == '<')                { op = OP_LT; p += 1; }
        else if (p[0] == '>')                { op = OP_GT; p += 1; }
        else { fputs("sublimation: where: operator must be one of < <= > >= == !=\n", stderr); return 2; }
        while (*p == ' ') p++;
        char *ve;
        double val = strtod(p, &ve);
        if (ve == p) { fputs("sublimation: where needs a numeric value, e.g. '2 > 100'\n", stderr); return 2; }
        char *line = NULL;
        size_t cap = 0;
        ssize_t len;
        long matches = 0;
        int multi = nfiles > 1;
        for (int fi = 0; nfiles == 0 ? fi < 1 : fi < nfiles; fi++) {
            FILE *in = stdin;
            const char *fname = NULL;
            if (nfiles > 0) {
                fname = files[fi];
                in = fopen(fname, "r");
                if (!in) { fprintf(stderr, "sublimation: cannot open '%s'\n", fname); continue; }
            }
            while ((len = getline(&line, &cap, in)) != -1) {
                char buf[4096];
                size_t n = (size_t)len < sizeof(buf) ? (size_t)len : sizeof(buf) - 1;
                memcpy(buf, line, n);
                buf[n] = '\0';
                char *tok = field_token(buf, (int)col, delim);
                double x = tok ? strtod(tok, NULL) : 0.0;  // missing / non-numeric -> 0
                int keep;
                switch (op) {
                    case OP_LT: keep = x <  val; break;
                    case OP_LE: keep = x <= val; break;
                    case OP_GT: keep = x >  val; break;
                    case OP_GE: keep = x >= val; break;
                    case OP_EQ: keep = x == val; break;
                    default:    keep = x != val; break;  // OP_NE
                }
                if (keep) {
                    matches++;
                    if (multi) montauk_sink_appendf(&g_out, "%s:", fname);
                    montauk_sink_append(&g_out, line, (size_t)len);
                }
            }
            if (in != stdin) fclose(in);
        }
        free(line);
        return matches ? 0 : 1;
    }

    // Numeric/structural commands read stdin only; a leftover file argument here
    // is a mistake (grep/contains/field consumed theirs above). Error rather than
    // silently reading stdin and ignoring the path.
    if (nfiles > 0) {
        fprintf(stderr, "sublimation: %s reads stdin; '%s' is an unexpected "
                "argument\n", cmd, files[0]);
        return 2;
    }

    // tally / distinct: frequency and distinct-count over TEXT tokens -- the
    // --field column, or the whole line. tally is sort | uniq -c | sort -rn;
    // distinct is sort | uniq | wc -l (so "1.0" and "1" are distinct lines, as
    // those tools see them). Grouping is a single-pass open-addressing hash;
    // tally orders the counts through the in-tree u64 sort.
    if (!strcmp(cmd, "tally") || !strcmp(cmd, "distinct")) {
        size_t hcap = 1024, used = 0;
        char  **keys = (char **)calloc(hcap, sizeof(char *));
        size_t *cnts = (size_t *)calloc(hcap, sizeof(size_t));
        if (!keys || !cnts) { fputs("sublimation: out of memory\n", stderr); return 1; }
        char *line = NULL; size_t lcap = 0; ssize_t len;
        while ((len = getline(&line, &lcap, stdin)) != -1) {
            if (len > 0 && line[len - 1] == '\n') line[--len] = '\0';
            char buf[4096];
            const char *tok = line;
            if (field > 0) {
                size_t n = (size_t)len < sizeof(buf) ? (size_t)len : sizeof(buf) - 1;
                memcpy(buf, line, n); buf[n] = '\0';
                char *t = field_token(buf, field, delim);
                if (!t) continue;  // missing column -- skip, like read_values
                tok = t;
            }
            if ((used + 1) * 2 >= hcap) {  // grow at 50% load
                size_t ncap = hcap * 2;
                char  **nk = (char **)calloc(ncap, sizeof(char *));
                size_t *nc = (size_t *)calloc(ncap, sizeof(size_t));
                if (!nk || !nc) { fputs("sublimation: out of memory\n", stderr); return 1; }
                for (size_t i = 0; i < hcap; i++) {
                    if (!keys[i]) continue;
                    uint64_t h = 1469598103934665603ULL;
                    for (const char *p = keys[i]; *p; p++) { h ^= (unsigned char)*p; h *= 1099511628211ULL; }
                    size_t j = (size_t)h & (ncap - 1);
                    while (nk[j]) j = (j + 1) & (ncap - 1);
                    nk[j] = keys[i]; nc[j] = cnts[i];
                }
                free(keys); free(cnts); keys = nk; cnts = nc; hcap = ncap;
            }
            uint64_t h = 1469598103934665603ULL;
            for (const char *p = tok; *p; p++) { h ^= (unsigned char)*p; h *= 1099511628211ULL; }
            size_t i = (size_t)h & (hcap - 1);
            while (keys[i] && strcmp(keys[i], tok) != 0) i = (i + 1) & (hcap - 1);
            if (keys[i]) cnts[i]++;
            else { keys[i] = strdup(tok); cnts[i] = 1; used++; }
        }
        free(line);

        if (!strcmp(cmd, "distinct")) {
            montauk_sink_appendf(&g_out, "%zu\n", used);
        } else if (used > 0) {
            // Compact to dense (key,count); order by count desc through the u64
            // sort. pack = (count << 32) | dense_index -- both fit a line stream.
            char    **dk     = (char **)malloc(used * sizeof(char *));
            uint64_t *packed = (uint64_t *)malloc(used * sizeof(uint64_t));
            if (!dk || !packed) { fputs("sublimation: out of memory\n", stderr); return 1; }
            size_t d = 0;
            for (size_t i = 0; i < hcap; i++)
                if (keys[i]) { dk[d] = keys[i]; packed[d] = ((uint64_t)cnts[i] << 32) | (uint64_t)d; d++; }
            sublimation_u64(packed, used);             // ascending
            for (size_t i = used; i-- > 0;) {          // descending = highest count first
                unsigned long long count = (unsigned long long)(packed[i] >> 32);
                size_t idx = (size_t)(packed[i] & 0xFFFFFFFFULL);
                montauk_sink_appendf(&g_out, "%llu %s\n", count, dk[idx]);
            }
            free(dk); free(packed);
        }
        for (size_t i = 0; i < hcap; i++) free(keys[i]);
        free(keys); free(cnts);
        return 0;
    }

    Vec data = {0};
    size_t skipped = read_values(&data, field, delim);

    // count -- lines (records): wc -l / awk NR. No numeric parse, so it works on
    // all-text input; handled before the numeric-required guard below. Every
    // getline iteration either parsed a value or was skipped, so data.n + skipped
    // is the total line count.
    if (!strcmp(cmd, "count")) {
        montauk_sink_appendf(&g_out, "%zu\n", data.n + skipped);
        free(data.v);
        return 0;
    }

    if (data.n == 0) {
        fputs("sublimation: no numeric values on stdin\n", stderr);
        return 1;
    }

    if (!strcmp(cmd, "sort")) {
        sublimation_f64(data.v, data.n);
        if (desc) for (size_t i = 0; i < data.n; i++) montauk_sink_appendf(&g_out, "%.12g\n", data.v[data.n - 1 - i]);
        else      for (size_t i = 0; i < data.n; i++) montauk_sink_appendf(&g_out, "%.12g\n", data.v[i]);

    } else if (!strcmp(cmd, "sum")) {     // awk '{s+=$N} END{print s}'
        double s = 0.0;
        for (size_t i = 0; i < data.n; i++) s += data.v[i];
        montauk_sink_appendf(&g_out, "%.12g\n", s);

    } else if (!strcmp(cmd, "mean")) {    // awk '{s+=$N} END{print s/NR}' (over the parsed values)
        double s = 0.0;
        for (size_t i = 0; i < data.n; i++) s += data.v[i];
        montauk_sink_appendf(&g_out, "%.12g\n", s / (double)data.n);

    } else if (!strcmp(cmd, "variance") || !strcmp(cmd, "stdev")) {
        // SAMPLE variance / stdev (n-1 denominator), matching the convention the
        // PANDEMONIUM suite's mean_stdev() uses so it is an exact drop-in. n<2 has
        // no spread -> 0.0 (same as mean_stdev). Two-pass for numerical stability.
        if (data.n < 2) { montauk_sink_appendf(&g_out, "0\n"); }
        else {
            double s = 0.0;
            for (size_t i = 0; i < data.n; i++) s += data.v[i];
            double mean = s / (double)data.n;
            double ss = 0.0;
            for (size_t i = 0; i < data.n; i++) {
                double d = data.v[i] - mean;
                ss += d * d;
            }
            double var = ss / (double)(data.n - 1);
            montauk_sink_appendf(&g_out, "%.12g\n", !strcmp(cmd, "stdev") ? sqrt(var) : var);
        }

    } else if (!strcmp(cmd, "min")) {     // running minimum
        double m = data.v[0];
        for (size_t i = 1; i < data.n; i++) if (data.v[i] < m) m = data.v[i];
        montauk_sink_appendf(&g_out, "%.12g\n", m);

    } else if (!strcmp(cmd, "max")) {     // running maximum
        double m = data.v[0];
        for (size_t i = 1; i < data.n; i++) if (data.v[i] > m) m = data.v[i];
        montauk_sink_appendf(&g_out, "%.12g\n", m);

    } else if (!strcmp(cmd, "quantile")) {
        if (!pos) { fputs("sublimation: quantile needs Q (0..1)\n", stderr); return 2; }
        double q = strtod(pos, NULL);
        if (q < 0.0 || q > 1.0) { fputs("sublimation: Q must be in 0..1\n", stderr); return 2; }
        sublimation_f64(data.v, data.n);
        size_t idx;
        if (nearest) {
            // Nearest-rank: the smallest value at or below which q of the data
            // falls -- k = ceil(q*n) - 1, clamped. This is the exact convention
            // the PANDEMONIUM suite's percentile() uses (k = ceil(pct/100*n)-1),
            // so `quantile Q --nearest` is a bit-exact drop-in. The default
            // (estimator) path is unchanged for existing callers.
            double kk = ceil(q * (double)data.n) - 1.0;
            if (kk < 0.0) kk = 0.0;
            idx = (size_t)kk;
        } else {
            idx = (size_t)(q * (double)data.n);
        }
        if (idx >= data.n) idx = data.n - 1;
        montauk_sink_appendf(&g_out, "%.12g\n", data.v[idx]);

    } else if (!strcmp(cmd, "select")) {
        if (!pos) { fputs("sublimation: select needs K (0-based)\n", stderr); return 2; }
        long long k = atoll(pos);
        if (k < 0 || (size_t)k >= data.n) {
            fprintf(stderr, "sublimation: K out of range (0..%zu)\n", data.n - 1);
            return 2;
        }
        montauk_sink_appendf(&g_out, "%.12g\n", sublimation_select_f64(data.v, data.n, (size_t)k));

    } else if (!strcmp(cmd, "searchsorted")) {
        if (!pos) { fputs("sublimation: searchsorted needs a value\n", stderr); return 2; }
        double target = strtod(pos, NULL);
        sublimation_f64(data.v, data.n);  // searchsorted needs sorted input
        montauk_sink_appendf(&g_out, "%zu\n", sublimation_searchsorted_f64(data.v, data.n, target, 0));

    } else if (!strcmp(cmd, "classify")) {
        sub_profile_t p = sublimation_classify_f64(data.v, data.n);
        montauk_sink_appendf(&g_out, "%s  n=%zu  inversion_ratio=%.3f  lis=%zu  distinct~%zu  runs=%zu",
               sublimation_disorder_name(p.disorder), data.n,
               (double)p.inversion_ratio, p.lis_length, p.distinct_estimate, p.run_count);
        if (p.phase_boundary) montauk_sink_appendf(&g_out, "  phase_boundary=%zu", p.phase_boundary);
        montauk_sink_appendc(&g_out, '\n');

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
        montauk_sink_appendf(&g_out, "%zu window(s) matching %s:\n", k, sublimation_disorder_name(target));
        for (size_t i = 0; i < k; i++)
            montauk_sink_appendf(&g_out, "  [%zu,%zu)  inv=%.2f  distinct~%zu\n",
                   m[i].start, m[i].start + m[i].len,
                   (double)m[i].inversion_ratio, m[i].distinct_estimate);
        free(m);

    } else if (!strcmp(cmd, "rand")) {
        sub_randomness_t r = sublimation_randomness_f64(data.v, data.n);
        static const char *lens[SUB_RANDOMNESS_LENSES] =
            {"hook", "lis", "inv", "distinct", "hvg", "bandt-pompe"};
        montauk_sink_appendf(&g_out, "confidence=%.3f  (k=%u/%u agree)\n", (double)r.confidence,
               r.agree_count, r.lens_count);
        for (int i = 0; i < SUB_RANDOMNESS_LENSES; i++) {
            if (r.lens_available[i]) montauk_sink_appendf(&g_out, "  %-12s %.2f\n", lens[i], (double)r.lens[i]);
            else                     montauk_sink_appendf(&g_out, "  %-12s --\n", lens[i]);
        }

    } else if (!strcmp(cmd, "characterize")) {
        // The honest structural verdict -- the move awk cannot make, because awk
        // never knew the shape. One line built on the blessed structure
        // primitives: the disorder class, the max-entropy randomness confidence
        // (1.0 = structureless noise -- the honesty awk lacks), the flow sort's
        // comparison_efficiency against the hook-length bound, and that
        // information-theoretic bound in bits. rand runs on the original order;
        // the stats sort then classifies and measures it.
        sub_randomness_t r = sublimation_randomness_f64(data.v, data.n);
        sub_stats_t st = {0};
        sublimation_f64_stats(data.v, data.n, &st);   // sorts data.v in place, fills st
        // Honesty at the floor: the class and the randomness confidence are always
        // reported; the hook-length efficiency only when it was actually computed
        // -- the fast paths skip it, and a 0 there is "not measured", not "zero".
        montauk_sink_appendf(&g_out, "%s  rand_confidence=%.3f  n=%zu",
               sublimation_disorder_name(st.disorder), (double)r.confidence, data.n);
        if (st.info_theoretic_bound > 0.0)
            montauk_sink_appendf(&g_out, "  comparison_efficiency=%.3f  info_bound=%.1f bits",
                   st.comparison_efficiency, st.info_theoretic_bound);
        montauk_sink_appendc(&g_out, '\n');

    } else {
        fprintf(stderr, "sublimation: unknown command '%s'\n\n", cmd);
        usage(stderr);
        free(data.v);
        return 2;
    }

    free(data.v);
    return 0;
}
