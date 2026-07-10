// sublimation -- command-line front door to the flow-model sort sub-system.
//
// Reads a numeric stream on stdin, runs one sublimation primitive, writes the
// result to stdout. This is the data-side answer to "stop reaching for awk and
// sort": ordering, percentiles, k-th selection, value lookup, disorder
// classification, structural location, and a max-entropy randomness verdict --
// all through the flow-model library, no shell-stats pipeline.
//
//   sublimation sort        [--field N] [--delim D] [--desc] [--keyed]
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
        "  sort                  order ascending (or --desc); --keyed keeps the\n"
        "                        whole line, ordering by the key (--field N or the\n"
        "                        whole line) -- coreutils' `sort -k`, no shell round-trip\n"
        "  quantile Q            the Q-quantile, Q in 0..1 (e.g. 0.99); --nearest for nearest-rank\n"
        "  select K              the K-th smallest value, 0-based\n"
        "  searchsorted V        insertion index of V in the sorted input\n"
        "  sum / mean            sum / mean of the value stream\n"
        "  stdev / variance      sample (n-1) standard deviation / variance\n"
        "  min / max             minimum / maximum value\n"
        "  describe              count/mean/stdev/min/quartiles/max in one shot (pandas .describe)\n"
        "  outliers              values outside the Tukey IQR fences (robust outlier flag)\n"
        "  histogram             text histogram of the distribution, 10 bins (the shape)\n"
        "  count                 number of input lines (wc -l)\n"
        "  distinct              count of distinct tokens (sort | uniq | wc -l)\n"
        "  tally                 per-token frequency, high to low (sort | uniq -c | sort -rn)\n"
        "  classify              disorder class + profile of the stream\n"
        "  locate CLASS [--values]  windows whose disorder class == CLASS (--values: select-by-structure, emit the data in them)\n"
        "  rand                  max-entropy randomness confidence\n"
        "  characterize          structural verdict: class, rand confidence, sort efficiency\n"
        "  grep PATTERN [FILE..] lines matching the regex (Thompson NFA); stdin or FILE(s)\n"
        "  contains STR [FILE..] lines containing STR (Boyer-Moore-Horspool); stdin or FILE(s)\n"
        "  replace PAT REPL      regex substitution, global per line (sed s/pat/repl/g; REPL literal)\n"
        "  field N[,M..] [FILE..] the N-th column, or a comma-list, of each line (awk '{print $N}')\n"
        "  where 'N OP V' [FILE] lines where field N OP V (awk '$N OP V'; OP: < <= > >= == !=)\n"
        "  group KEY OP [VAL]    group by field KEY, aggregate field VAL (datamash -g; OP: sum|mean|count|min|max)\n"
        "  uniq [-d|-u]          collapse adjacent duplicate lines (-d dups only, -u uniques only)\n"
        "  cut LO-HI             character columns, 1-based inclusive (cut -c): N, lo-hi, lo-, -hi\n"
        "  column                align delimited input into columns (column -t)\n"
        "  tac                   reverse line order\n"
        "  paste -s              serialize lines into one tab-joined line\n"
        "  intersect FILE        lines in both stdin and FILE (set intersection)\n"
        "  subtract FILE         lines in stdin but not in FILE (set difference)\n"
        "  union FILE            distinct lines from stdin and FILE (set union)\n"
        "  join FIELD FILE       join stdin and FILE on field FIELD (relational join)\n"
        "\n"
        "  CLASS: sorted reversed nearly-sorted few-unique random phased spectral\n"
        "\n"
        "options:\n"
        "  --field N             pull the N-th (1-based) delimited column per line\n"
        "  --delim D             column delimiter chars (default: whitespace)\n"
        "  --desc                sort descending\n"
        "  --keyed               sort: keep the whole line, order by --field N (or\n"
        "                        the whole line) as the key -- a row-preserving\n"
        "                        keyed sort, not just the extracted value\n"
        "  --window W            window size for locate (default 512)\n"
        "  --stride S            window stride for locate (default = window)\n"
        "  -v / -c / -n          grep/contains: invert match / count only / line number\n"
        "  -i / -o               grep/contains: case-insensitive (-i) / grep: print only the match (-o)\n"
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

// Grow-on-demand (key, line) buffer for `sort --keyed` -- the row-preserving
// keyed sort. idx is insertion order, kept only as a stable tie-break (qsort
// makes no stability guarantee); it is never shown or compared for meaning.
typedef struct { double key; size_t idx; char *line; } KeyedLine;
typedef struct { KeyedLine *v; size_t n, cap; } KVec;
static void kvec_push(KVec *a, double key, size_t idx, char *line) {
    if (a->n == a->cap) {
        a->cap = a->cap ? a->cap * 2 : 1024;
        a->v = (KeyedLine *)realloc(a->v, a->cap * sizeof(KeyedLine));
        if (!a->v) { fputs("sublimation: out of memory\n", stderr); exit(1); }
    }
    a->v[a->n].key = key; a->v[a->n].idx = idx; a->v[a->n].line = line;
    a->n++;
}
static int keyedline_cmp_asc(const void *pa, const void *pb) {
    const KeyedLine *a = (const KeyedLine *)pa, *b = (const KeyedLine *)pb;
    if (a->key < b->key) return -1;
    if (a->key > b->key) return 1;
    return (a->idx < b->idx) ? -1 : (a->idx > b->idx ? 1 : 0);
}
static int keyedline_cmp_desc(const void *pa, const void *pb) {
    const KeyedLine *a = (const KeyedLine *)pa, *b = (const KeyedLine *)pb;
    if (a->key > b->key) return -1;
    if (a->key < b->key) return 1;
    return (a->idx < b->idx) ? -1 : (a->idx > b->idx ? 1 : 0);
}

// Open-addressing string hash map (val NULL = plain set), for the two-stream
// set ops and join. FNV-1a; grows at 50% load.
typedef struct { char **keys; char **vals; size_t cap, used; } StrMap;
static uint64_t str_fnv(const char *s) {
    uint64_t h = 1469598103934665603ULL;
    for (; *s; s++) { h ^= (unsigned char)*s; h *= 1099511628211ULL; }
    return h;
}
static void smap_init(StrMap *m) {
    m->cap = 1024; m->used = 0;
    m->keys = (char **)calloc(m->cap, sizeof(char *));
    m->vals = (char **)calloc(m->cap, sizeof(char *));
}
static size_t smap_slot(StrMap *m, const char *k) {
    size_t i = str_fnv(k) & (m->cap - 1);
    while (m->keys[i] && strcmp(m->keys[i], k)) i = (i + 1) & (m->cap - 1);
    return i;
}
static int smap_has(StrMap *m, const char *k) { return m->keys[smap_slot(m, k)] != NULL; }
static const char *smap_get(StrMap *m, const char *k) { size_t i = smap_slot(m, k); return m->keys[i] ? m->vals[i] : NULL; }
static void smap_put(StrMap *m, const char *k, const char *v) {
    if ((m->used + 1) * 2 >= m->cap) {
        size_t nc = m->cap * 2;
        char **nk = (char **)calloc(nc, sizeof(char *));
        char **nv = (char **)calloc(nc, sizeof(char *));
        for (size_t j = 0; j < m->cap; j++) if (m->keys[j]) {
            size_t p = str_fnv(m->keys[j]) & (nc - 1);
            while (nk[p]) p = (p + 1) & (nc - 1);
            nk[p] = m->keys[j]; nv[p] = m->vals[j];
        }
        free(m->keys); free(m->vals); m->keys = nk; m->vals = nv; m->cap = nc;
    }
    size_t i = smap_slot(m, k);
    if (m->keys[i]) return;  // first value per key wins
    m->keys[i] = strdup(k); m->vals[i] = v ? strdup(v) : NULL; m->used++;
}
static void smap_free(StrMap *m) {
    for (size_t i = 0; i < m->cap; i++) { free(m->keys[i]); free(m->vals[i]); }
    free(m->keys); free(m->vals);
}
// Load a file's lines (newline-stripped) into a set/map; v != 0 stores the line.
static int smap_load_file(StrMap *m, const char *path, int store_line) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char *line = NULL; size_t lcap = 0; ssize_t len;
    while ((len = getline(&line, &lcap, f)) != -1) {
        if (len > 0 && line[len - 1] == '\n') line[len - 1] = '\0';
        smap_put(m, line, store_line ? line : NULL);
    }
    free(line); fclose(f);
    return 0;
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

// Non-mutating field extractor: returns a pointer to the 1-based `field` column
// within [line, line+len) and writes its length to *flen; NULL if the column is
// absent. Matches field_token/strtok semantics (runs of delimiters collapse, no
// empty fields) but copies nothing and truncates nothing, so it is correct on
// lines of any length -- unlike the fixed-buffer copy callers used to make
// before tokenizing (which silently truncated past the buffer size).
static const char *field_span(const char *line, size_t len, int field,
                              const char *delim, size_t *flen) {
    if (field <= 0) { *flen = len; return line; }
    size_t i = 0; int col = 0;
    while (i < len) {
        while (i < len && strchr(delim, line[i])) i++;
        if (i >= len) break;
        size_t start = i;
        while (i < len && !strchr(delim, line[i])) i++;
        if (++col == field) { *flen = i - start; return line + start; }
    }
    return NULL;
}

// Read stdin into `out`, parsing one double per line (or per --field column).
// Lines whose field does not parse as a number are skipped (and counted).
static size_t read_values(Vec *out, int field, const char *delim) {
    char *line = NULL;
    size_t cap = 0;
    ssize_t len;
    size_t skipped = 0;
    while ((len = getline(&line, &cap, stdin)) != -1) {
        const char *src = line;
        if (field > 0) {
            size_t flen;
            src = field_span(line, (size_t)len, field, delim, &flen);
            if (!src) { skipped++; continue; }
            // src points into line and is followed by a delimiter/newline, so
            // strtod stops at the field boundary with no null terminator needed.
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
    int keyed = 0;                                // sort --keyed: preserve full lines, order by key
    size_t window = 512, stride = 0;
    int invert = 0, count_only = 0, number = 0;  // grep/contains line-filter flags
    int icase = 0, only_match = 0;                // grep -i (regex case-fold), grep -o (matches only)
    int quiet = 0;                                // grep -q: exit status only, no output
    long max_count = 0;                           // grep -m N: stop after N matches (0 = unlimited)
    int nearest = 0;                              // quantile --nearest: nearest-rank, not estimator
    int uniq_d = 0, uniq_u = 0;                   // uniq -d (dups only) / -u (uniques only)
    int serial = 0;                               // paste -s: serialize lines into one
    int endopts = 0;                              // after `--`, everything is positional
    int values = 0;                               // locate --values: select-by-structure (emit the data)
    const char *pos = NULL;  // positional arg (Q / K / V / CLASS / N)
    const char *files[256];  // grep/contains/field: input files after the pattern
    int nfiles = 0;          // 0 -> read stdin (the pipe case)

    for (int i = 2; i < argc; i++) {
        const char *a = argv[i];
        if (endopts) {  // after `--`, everything is a positional (lets REPL/PATTERN start with '-')
            if (!pos) pos = a;
            else if (nfiles < 256) files[nfiles++] = a;
            else { fprintf(stderr, "sublimation: too many arguments\n"); return 2; }
            continue;
        }
        if (!strcmp(a, "--")) { endopts = 1; continue; }
        if (!strcmp(a, "--field") && i + 1 < argc) field = atoi(argv[++i]);
        else if (!strcmp(a, "--delim") && i + 1 < argc) delim = argv[++i];
        else if (!strcmp(a, "--desc")) desc = 1;
        else if (!strcmp(a, "--keyed")) keyed = 1;  // sort: keep the whole line, order by the key
        else if (!strcmp(a, "--window") && i + 1 < argc) window = strtoull(argv[++i], NULL, 10);
        else if (!strcmp(a, "--stride") && i + 1 < argc) stride = strtoull(argv[++i], NULL, 10);
        else if (!strcmp(a, "--nearest")) nearest = 1;  // quantile: nearest-rank order statistic
        else if (!strcmp(a, "--values")) values = 1;    // locate: emit data, not window ranges
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
                    case 'd': uniq_d = 1; break;       // uniq -d: only duplicated lines
                    case 'u': uniq_u = 1; break;       // uniq -u: only unique lines
                    case 's': serial = 1; break;       // paste -s: serialize lines into one
                    default:
                        fprintf(stderr, "sublimation: unknown option '-%c'\n", *f);
                        return 2;
                }
            }
        }
        else if (a[0] == '-' && a[1]) { fprintf(stderr, "sublimation: unknown option '%s'\n", a); return 2; }
        else if (!pos) pos = a;   // a bare '-' falls here -- a valid positional (e.g. REPL='-')
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
            sublimation_bmh_compile_ex(&bmh, pos, plen, icase);  // -i folds; default case-sensitive (grep -F)
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
                size_t flen;
                const char *tok = field_span(line, (size_t)len, (int)col, delim, &flen);
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

    // group: groupby-aggregate (datamash `-g KEY OP VAL` / SQL GROUP BY). Group rows
    // by the KEY field's token, aggregate the VAL field with OP. Single pass -- an
    // open-addressing hash maps key -> dense group id, per-group accumulators live in
    // parallel arrays, output is in first-seen group order. `group KEY OP [VAL]`.
    if (!strcmp(cmd, "group")) {
        if (!pos || nfiles < 1) {
            fputs("sublimation: group needs KEY OP [VAL] -- e.g. 'group 1 sum 2'\n", stderr);
            return 2;
        }
        int keyf = atoi(pos);
        const char *op = files[0];
        int is_count = !strcmp(op, "count");
        if (strcmp(op, "sum") && strcmp(op, "mean") && !is_count &&
            strcmp(op, "min") && strcmp(op, "max")) {
            fprintf(stderr, "sublimation: group OP must be sum|mean|count|min|max (got '%s')\n", op);
            return 2;
        }
        if (!is_count && nfiles < 2) {
            fprintf(stderr, "sublimation: group %s needs a VAL field -- e.g. 'group 1 %s 2'\n", op, op);
            return 2;
        }
        int valf = (nfiles >= 2) ? atoi(files[1]) : 0;
        if (keyf < 1 || (!is_count && valf < 1)) {
            fputs("sublimation: group KEY/VAL fields are 1-based\n", stderr);
            return 2;
        }

        size_t hcap = 1024;
        char   **hkey = (char **)calloc(hcap, sizeof(char *));  // hash: key ptr
        size_t *hgid  = (size_t *)calloc(hcap, sizeof(size_t)); // hash: group id + 1 (0 = empty)
        size_t gcap = 256, gn = 0;                              // dense per-group state
        char   **gkey = (char **)malloc(gcap * sizeof(char *));
        size_t *grows = (size_t *)malloc(gcap * sizeof(size_t));
        size_t *gnval = (size_t *)malloc(gcap * sizeof(size_t));
        double *gsum  = (double *)malloc(gcap * sizeof(double));
        double *gmin  = (double *)malloc(gcap * sizeof(double));
        double *gmax  = (double *)malloc(gcap * sizeof(double));
        if (!hkey || !hgid || !gkey || !grows || !gnval || !gsum || !gmin || !gmax) {
            fputs("sublimation: out of memory\n", stderr); return 1;
        }

        char *line = NULL; size_t lcap = 0; ssize_t len;
        while ((len = getline(&line, &lcap, stdin)) != -1) {
            if (len > 0 && line[len - 1] == '\n') line[--len] = '\0';
            size_t klen; const char *kspan = field_span(line, (size_t)len, keyf, delim, &klen);
            if (!kspan) continue;  // no key column -> skip the row
            double val = 0.0; int have_val = 0;
            if (!is_count) {
                size_t vlen; const char *vspan = field_span(line, (size_t)len, valf, delim, &vlen);
                if (vspan) { char *end = NULL; val = strtod(vspan, &end); have_val = (end != vspan); }
                if (!have_val) continue;  // sum/mean/min/max need a numeric VAL
            }
            // Null-terminate the key field in place for the hash/strcmp/strdup
            // below; group emits aggregates, not the original line, so this is safe.
            char *ktok = (char *)kspan; ktok[klen] = '\0';
            if ((gn + 1) * 2 >= hcap) {  // grow hash at 50% load, re-insert
                size_t ncap = hcap * 2;
                char  **nk = (char **)calloc(ncap, sizeof(char *));
                size_t *ng = (size_t *)calloc(ncap, sizeof(size_t));
                if (!nk || !ng) { fputs("sublimation: out of memory\n", stderr); return 1; }
                for (size_t j = 0; j < hcap; j++) {
                    if (!hgid[j]) continue;
                    uint64_t hh = 1469598103934665603ULL;
                    for (const char *p = hkey[j]; *p; p++) { hh ^= (unsigned char)*p; hh *= 1099511628211ULL; }
                    size_t q = (size_t)hh & (ncap - 1);
                    while (nk[q]) q = (q + 1) & (ncap - 1);
                    nk[q] = hkey[j]; ng[q] = hgid[j];
                }
                free(hkey); free(hgid); hkey = nk; hgid = ng; hcap = ncap;
            }
            uint64_t h = 1469598103934665603ULL;
            for (const char *p = ktok; *p; p++) { h ^= (unsigned char)*p; h *= 1099511628211ULL; }
            size_t i = (size_t)h & (hcap - 1);
            while (hgid[i] && strcmp(hkey[i], ktok) != 0) i = (i + 1) & (hcap - 1);
            size_t gid;
            if (hgid[i]) {
                gid = hgid[i] - 1;
            } else {
                if (gn == gcap) {  // grow dense arrays (the strings they point to do not move)
                    gcap *= 2;
                    gkey = (char **)realloc(gkey, gcap * sizeof(char *));
                    grows = (size_t *)realloc(grows, gcap * sizeof(size_t));
                    gnval = (size_t *)realloc(gnval, gcap * sizeof(size_t));
                    gsum = (double *)realloc(gsum, gcap * sizeof(double));
                    gmin = (double *)realloc(gmin, gcap * sizeof(double));
                    gmax = (double *)realloc(gmax, gcap * sizeof(double));
                    if (!gkey || !grows || !gnval || !gsum || !gmin || !gmax) {
                        fputs("sublimation: out of memory\n", stderr); return 1;
                    }
                }
                gid = gn++;
                gkey[gid] = strdup(ktok);
                grows[gid] = 0; gnval[gid] = 0; gsum[gid] = 0.0; gmin[gid] = 0.0; gmax[gid] = 0.0;
                hkey[i] = gkey[gid]; hgid[i] = gid + 1;
            }
            grows[gid]++;
            if (have_val) {
                if (gnval[gid] == 0) { gmin[gid] = val; gmax[gid] = val; }
                else { if (val < gmin[gid]) gmin[gid] = val; if (val > gmax[gid]) gmax[gid] = val; }
                gsum[gid] += val; gnval[gid]++;
            }
        }
        free(line);

        for (size_t g = 0; g < gn; g++) {
            if (is_count)               montauk_sink_appendf(&g_out, "%s %zu\n", gkey[g], grows[g]);
            else if (!strcmp(op, "sum"))  montauk_sink_appendf(&g_out, "%s %.12g\n", gkey[g], gsum[g]);
            else if (!strcmp(op, "mean")) montauk_sink_appendf(&g_out, "%s %.12g\n", gkey[g],
                                                               gnval[g] ? gsum[g] / (double)gnval[g] : 0.0);
            else if (!strcmp(op, "min"))  montauk_sink_appendf(&g_out, "%s %.12g\n", gkey[g], gmin[g]);
            else                          montauk_sink_appendf(&g_out, "%s %.12g\n", gkey[g], gmax[g]);
            if (g_out.len >= (1u << 16)) montauk_sink_drain(&g_out);
        }
        for (size_t g = 0; g < gn; g++) free(gkey[g]);
        free(hkey); free(hgid); free(gkey); free(grows); free(gnval); free(gsum); free(gmin); free(gmax);
        return 0;
    }

    // uniq: collapse ADJACENT equal lines (sort first for a global dedup). -d emits
    // only lines that repeated, -u only lines that did not.
    if (!strcmp(cmd, "uniq")) {
        char *line = NULL, *prev = NULL; size_t lcap = 0, pcap = 0, plen = 0; ssize_t len;
        int have_prev = 0; long run = 0;
        while ((len = getline(&line, &lcap, stdin)) != -1) {
            size_t l = (len > 0 && line[len - 1] == '\n') ? (size_t)len - 1 : (size_t)len;
            if (have_prev && l == plen && memcmp(line, prev, l) == 0) { run++; continue; }
            if (have_prev) {
                int show = uniq_d ? (run > 1) : uniq_u ? (run == 1) : 1;
                if (show) { montauk_sink_append(&g_out, prev, plen); montauk_sink_appendc(&g_out, '\n'); }
            }
            if (l + 1 > pcap) { prev = (char *)realloc(prev, l + 1); pcap = l + 1; }
            memcpy(prev, line, l); plen = l; have_prev = 1; run = 1;
        }
        if (have_prev) {
            int show = uniq_d ? (run > 1) : uniq_u ? (run == 1) : 1;
            if (show) { montauk_sink_append(&g_out, prev, plen); montauk_sink_appendc(&g_out, '\n'); }
        }
        free(line); free(prev);
        return 0;
    }

    // tac: reverse line (arrival) order -- distinct from sort --desc (sorted order).
    if (!strcmp(cmd, "tac")) {
        char **buf = NULL; size_t bn = 0, bcap = 0;
        char *line = NULL; size_t lcap = 0; ssize_t len;
        while ((len = getline(&line, &lcap, stdin)) != -1) {
            if (bn == bcap) { bcap = bcap ? bcap * 2 : 1024; buf = (char **)realloc(buf, bcap * sizeof(char *)); }
            buf[bn] = (char *)malloc((size_t)len + 1);
            memcpy(buf[bn], line, (size_t)len); buf[bn][len] = '\0'; bn++;
        }
        free(line);
        for (size_t i = bn; i-- > 0;) {
            size_t l = strlen(buf[i]);
            montauk_sink_append(&g_out, buf[i], l);
            if (l == 0 || buf[i][l - 1] != '\n') montauk_sink_appendc(&g_out, '\n');
            free(buf[i]);
            if (g_out.len >= (1u << 16)) montauk_sink_drain(&g_out);
        }
        free(buf);
        return 0;
    }

    // cut: character columns (cut -c). RANGE is 1-based inclusive: "N", "lo-hi",
    // "lo-", "-hi". field/where own delimiter columns; this is the char-range gap.
    if (!strcmp(cmd, "cut")) {
        if (!pos) { fputs("sublimation: cut needs a char range -- e.g. 'cut 1-5'\n", stderr); return 2; }
        long clo = 1, chi = -1;  // chi = -1 means "to end of line"
        const char *dash = strchr(pos, '-');
        if (!dash) { clo = chi = atol(pos); }
        else { clo = (dash == pos) ? 1 : atol(pos); chi = *(dash + 1) ? atol(dash + 1) : -1; }
        if (clo < 1) clo = 1;
        char *line = NULL; size_t lcap = 0; ssize_t len;
        while ((len = getline(&line, &lcap, stdin)) != -1) {
            size_t l = (len > 0 && line[len - 1] == '\n') ? (size_t)len - 1 : (size_t)len;
            size_t a = (size_t)clo - 1;
            size_t b = (chi < 0) ? l : (size_t)chi;
            if (b > l) b = l;
            if (a < b) montauk_sink_append(&g_out, line + a, b - a);
            montauk_sink_appendc(&g_out, '\n');
            if (g_out.len >= (1u << 16)) montauk_sink_drain(&g_out);
        }
        free(line);
        return 0;
    }

    // column: align delim/whitespace-separated input into columns (column -t).
    // Buffers the input to compute per-column widths.
    if (!strcmp(cmd, "column")) {
        char **lines = NULL; size_t ln = 0, lcapn = 0;
        char *line = NULL; size_t lcap = 0; ssize_t len;
        size_t maxw[256]; for (size_t i = 0; i < 256; i++) maxw[i] = 0;
        while ((len = getline(&line, &lcap, stdin)) != -1) {
            size_t l = (len > 0 && line[len - 1] == '\n') ? (size_t)len - 1 : (size_t)len;
            char *s = (char *)malloc(l + 1); memcpy(s, line, l); s[l] = '\0';
            if (ln == lcapn) { lcapn = lcapn ? lcapn * 2 : 256; lines = (char **)realloc(lines, lcapn * sizeof(char *)); }
            lines[ln++] = s;
            char tmp[4096]; size_t tl = l < sizeof(tmp) ? l : sizeof(tmp) - 1; memcpy(tmp, s, tl); tmp[tl] = '\0';
            char *save = NULL; size_t c = 0;
            for (char *tok = strtok_r(tmp, delim, &save); tok; tok = strtok_r(NULL, delim, &save)) {
                size_t w = strlen(tok);
                if (c < 256 && w > maxw[c]) maxw[c] = w;
                c++;
            }
        }
        free(line);
        for (size_t i = 0; i < ln; i++) {
            char tmp[4096]; size_t tl = strlen(lines[i]); if (tl >= sizeof(tmp)) tl = sizeof(tmp) - 1;
            memcpy(tmp, lines[i], tl); tmp[tl] = '\0';
            char *save = NULL; char *toks[256]; size_t nt = 0;
            for (char *tok = strtok_r(tmp, delim, &save); tok && nt < 256; tok = strtok_r(NULL, delim, &save)) toks[nt++] = tok;
            for (size_t c = 0; c < nt; c++) {
                montauk_sink_append(&g_out, toks[c], strlen(toks[c]));
                if (c + 1 < nt) {  // pad to the column width + 2; last column flush-left
                    size_t pad = maxw[c] - strlen(toks[c]) + 2;
                    for (size_t k = 0; k < pad; k++) montauk_sink_appendc(&g_out, ' ');
                }
            }
            montauk_sink_appendc(&g_out, '\n');
            free(lines[i]);
        }
        free(lines);
        return 0;
    }

    // paste: -s serializes all input lines into ONE tab-joined line. (Side-by-side
    // multi-file paste is the join/set-ops two-stream lane.)
    if (!strcmp(cmd, "paste")) {
        char *line = NULL; size_t lcap = 0; ssize_t len; int first = 1;
        while ((len = getline(&line, &lcap, stdin)) != -1) {
            size_t l = (len > 0 && line[len - 1] == '\n') ? (size_t)len - 1 : (size_t)len;
            if (serial) { if (!first) montauk_sink_appendc(&g_out, '\t'); montauk_sink_append(&g_out, line, l); first = 0; }
            else { montauk_sink_append(&g_out, line, l); montauk_sink_appendc(&g_out, '\n'); }
        }
        if (serial && !first) montauk_sink_appendc(&g_out, '\n');
        free(line);
        return 0;
    }

    // Set ops over two streams -- stdin and a FILE. intersect = lines in both,
    // subtract = stdin lines not in FILE, union = distinct lines from both. Output
    // is stdin's first-seen order, deduped (union appends FILE-only lines after).
    if (!strcmp(cmd, "intersect") || !strcmp(cmd, "subtract") || !strcmp(cmd, "union")) {
        if (!pos) { fprintf(stderr, "sublimation: %s needs a FILE -- e.g. '%s other.txt'\n", cmd, cmd); return 2; }
        StrMap fileset; smap_init(&fileset);
        if (smap_load_file(&fileset, pos, 0) != 0) {
            fprintf(stderr, "sublimation: cannot open '%s'\n", pos); smap_free(&fileset); return 1;
        }
        StrMap emitted; smap_init(&emitted);
        int is_inter = !strcmp(cmd, "intersect"), is_sub = !strcmp(cmd, "subtract");
        char *line = NULL; size_t lcap = 0; ssize_t len;
        while ((len = getline(&line, &lcap, stdin)) != -1) {
            size_t l = (len > 0 && line[len - 1] == '\n') ? (size_t)len - 1 : (size_t)len;
            line[l] = '\0';
            int in_file = smap_has(&fileset, line);
            int keep = is_inter ? in_file : is_sub ? !in_file : 1;  // union keeps all distinct
            if (keep && !smap_has(&emitted, line)) {
                montauk_sink_append(&g_out, line, l); montauk_sink_appendc(&g_out, '\n');
                smap_put(&emitted, line, NULL);
            }
        }
        free(line);
        if (!is_inter && !is_sub)  // union: FILE lines not already emitted
            for (size_t i = 0; i < fileset.cap; i++)
                if (fileset.keys[i] && !smap_has(&emitted, fileset.keys[i])) {
                    montauk_sink_append(&g_out, fileset.keys[i], strlen(fileset.keys[i]));
                    montauk_sink_appendc(&g_out, '\n');
                    smap_put(&emitted, fileset.keys[i], NULL);
                }
        smap_free(&fileset); smap_free(&emitted);
        return 0;
    }

    // join: relational join of stdin and FILE on a 1-based FIELD. For each stdin line,
    // look up its FIELD token in FILE's (token -> line) map; emit the matched pair.
    if (!strcmp(cmd, "join")) {
        if (!pos || nfiles < 1) { fputs("sublimation: join needs FIELD FILE -- e.g. 'join 1 other.txt'\n", stderr); return 2; }
        int jf = atoi(pos); if (jf < 1) { fputs("sublimation: join FIELD is 1-based\n", stderr); return 2; }
        StrMap fm; smap_init(&fm);
        FILE *ff = fopen(files[0], "r");
        if (!ff) { fprintf(stderr, "sublimation: cannot open '%s'\n", files[0]); smap_free(&fm); return 1; }
        char *fl = NULL; size_t flc = 0; ssize_t fll;
        while ((fll = getline(&fl, &flc, ff)) != -1) {
            size_t l = (fll > 0 && fl[fll - 1] == '\n') ? (size_t)fll - 1 : (size_t)fll;
            fl[l] = '\0';
            size_t klen; const char *ks = field_span(fl, l, jf, delim, &klen);
            if (ks) { char *kc = strndup(ks, klen); if (kc) { smap_put(&fm, kc, fl); free(kc); } }
        }
        free(fl); fclose(ff);
        char *line = NULL; size_t lcap = 0; ssize_t len;
        while ((len = getline(&line, &lcap, stdin)) != -1) {
            size_t l = (len > 0 && line[len - 1] == '\n') ? (size_t)len - 1 : (size_t)len;
            line[l] = '\0';
            size_t klen; const char *ks = field_span(line, l, jf, delim, &klen);
            char *kc = ks ? strndup(ks, klen) : NULL;
            const char *match = kc ? smap_get(&fm, kc) : NULL;
            free(kc);
            if (match) {
                montauk_sink_append(&g_out, line, l);
                montauk_sink_appendc(&g_out, ' ');
                montauk_sink_append(&g_out, match, strlen(match));
                montauk_sink_appendc(&g_out, '\n');
            }
            if (g_out.len >= (1u << 16)) montauk_sink_drain(&g_out);
        }
        free(line); smap_free(&fm);
        return 0;
    }

    // replace: regex substitution on a pipe (sed s/pat/repl/g, global per line) on the
    // RE2-lineage Thompson NFA -- linear time, no catastrophic backtracking. REPLACEMENT
    // is literal here; capture-group backreferences (\1) are the deferred NFA extension.
    if (!strcmp(cmd, "replace")) {
        if (!pos || nfiles < 1) { fputs("sublimation: replace needs PATTERN REPLACEMENT -- e.g. 'replace foo bar'\n", stderr); return 2; }
        const char *repl = files[0]; size_t rlen = strlen(repl);
        sublimation_nfa nfa;
        sublimation_nfa_compile_ex(&nfa, pos, strlen(pos), icase);
        if (!sublimation_nfa_valid(&nfa)) { fprintf(stderr, "sublimation: bad regex '%s'\n", pos); return 2; }
        char *line = NULL; size_t lcap = 0; ssize_t len;
        while ((len = getline(&line, &lcap, stdin)) != -1) {
            size_t l = (len > 0 && line[len - 1] == '\n') ? (size_t)len - 1 : (size_t)len;
            size_t off = 0;
            while (off <= l) {
                long end = 0;
                long s = sublimation_nfa_find(&nfa, line + off, l - off, &end);
                if (s < 0) break;
                size_t ms = off + (size_t)s, me = off + (size_t)end;
                montauk_sink_append(&g_out, line + off, ms - off);  // text before the match
                montauk_sink_append(&g_out, repl, rlen);            // the replacement
                if (me > ms) { off = me; }
                else { if (ms < l) montauk_sink_appendc(&g_out, line[ms]); off = ms + 1; }  // zero-width: step on
            }
            if (off <= l) montauk_sink_append(&g_out, line + off, l - off);  // tail after last match
            montauk_sink_appendc(&g_out, '\n');
            if (g_out.len >= (1u << 16)) montauk_sink_drain(&g_out);
        }
        free(line);
        return 0;
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
            const char *tok = line;
            if (field > 0) {
                size_t flen; const char *sp = field_span(line, (size_t)len, field, delim, &flen);
                if (!sp) continue;  // missing column -- skip, like read_values
                char *p = (char *)sp; p[flen] = '\0';  // in place; tally emits keys, not the line
                tok = p;
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

    // sort --keyed: order FULL LINES by a numeric key (the whole line, or the
    // --field N column), keeping every column intact. Plain `sort` and
    // `--field N` both reduce to the bare value -- nothing in the existing
    // surface reorders a row by a derived key while keeping the rest of the
    // row, so a caller who wants that (rank commits by size, keep the hash
    // and subject; rank processes by RSS, keep the full ps line) falls
    // through to coreutils' `sort -t -k`. This closes that gap without the
    // shell round-trip. Lines whose key does not parse as a number are
    // skipped (matching read_values' skip-on-no-number convention).
    if (!strcmp(cmd, "sort") && keyed) {
        KVec kv = {0};
        char *line = NULL; size_t lcap = 0; ssize_t len;
        size_t idx = 0, skipped = 0;
        while ((len = getline(&line, &lcap, stdin)) != -1) {
            if (len > 0 && line[len - 1] == '\n') line[--len] = '\0';
            const char *src = line;
            if (field > 0) {
                size_t flen;
                src = field_span(line, (size_t)len, field, delim, &flen);
                if (!src) { skipped++; continue; }  // missing column -> skip the row
            }
            char *end = NULL;
            double x = strtod(src, &end);
            if (end == src) { skipped++; continue; }
            kvec_push(&kv, x, idx++, strdup(line));
        }
        free(line);
        if (kv.n > 0)
            qsort(kv.v, kv.n, sizeof(KeyedLine), desc ? keyedline_cmp_desc : keyedline_cmp_asc);
        for (size_t i = 0; i < kv.n; i++) {
            montauk_sink_append(&g_out, kv.v[i].line, strlen(kv.v[i].line));
            montauk_sink_appendc(&g_out, '\n');
            free(kv.v[i].line);
            if (g_out.len >= (1u << 16)) montauk_sink_drain(&g_out);
        }
        free(kv.v);
        if (kv.n == 0 && skipped > 0) {
            fprintf(stderr, "sublimation: sort --keyed: no numeric key found (skipped %zu line(s))\n", skipped);
            return 1;
        }
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

    } else if (!strcmp(cmd, "describe")) {  // pandas .describe() / R summary() in one shot
        sublimation_f64(data.v, data.n);    // sort: min/max + the estimator quantiles
        double s = 0.0;
        for (size_t i = 0; i < data.n; i++) s += data.v[i];
        double mean = s / (double)data.n;
        double var = 0.0;
        if (data.n >= 2) {                  // sample (n-1) variance, like the stdev verb
            double ss = 0.0;
            for (size_t i = 0; i < data.n; i++) { double d = data.v[i] - mean; ss += d * d; }
            var = ss / (double)(data.n - 1);
        }
        // Estimator-index quantiles, identical to the default `quantile Q` path.
        size_t i25 = (size_t)(0.25 * (double)data.n); if (i25 >= data.n) i25 = data.n - 1;
        size_t i50 = (size_t)(0.50 * (double)data.n); if (i50 >= data.n) i50 = data.n - 1;
        size_t i75 = (size_t)(0.75 * (double)data.n); if (i75 >= data.n) i75 = data.n - 1;
        montauk_sink_appendf(&g_out, "%-6s %zu\n",   "count", data.n);
        montauk_sink_appendf(&g_out, "%-6s %.12g\n", "mean",  mean);
        montauk_sink_appendf(&g_out, "%-6s %.12g\n", "stdev", sqrt(var));
        montauk_sink_appendf(&g_out, "%-6s %.12g\n", "min",   data.v[0]);
        montauk_sink_appendf(&g_out, "%-6s %.12g\n", "25%",   data.v[i25]);
        montauk_sink_appendf(&g_out, "%-6s %.12g\n", "50%",   data.v[i50]);
        montauk_sink_appendf(&g_out, "%-6s %.12g\n", "75%",   data.v[i75]);
        montauk_sink_appendf(&g_out, "%-6s %.12g\n", "max",   data.v[data.n - 1]);

    } else if (!strcmp(cmd, "outliers")) {  // values outside the Tukey IQR fences
        sublimation_f64(data.v, data.n);
        // Robust fences off the quartiles -- median/IQR-based, so the outliers do
        // not corrupt the threshold the way a mean +/- k*sigma rule lets them.
        size_t i25 = (size_t)(0.25 * (double)data.n); if (i25 >= data.n) i25 = data.n - 1;
        size_t i75 = (size_t)(0.75 * (double)data.n); if (i75 >= data.n) i75 = data.n - 1;
        double q1 = data.v[i25], q3 = data.v[i75], iqr = q3 - q1;
        double lo = q1 - 1.5 * iqr, hi = q3 + 1.5 * iqr;
        for (size_t i = 0; i < data.n; i++)
            if (data.v[i] < lo || data.v[i] > hi)
                montauk_sink_appendf(&g_out, "%.12g\n", data.v[i]);

    } else if (!strcmp(cmd, "histogram")) {  // text histogram (10 bins) -- the shape
        double mn = data.v[0], mx = data.v[0];
        for (size_t i = 1; i < data.n; i++) { if (data.v[i] < mn) mn = data.v[i]; if (data.v[i] > mx) mx = data.v[i]; }
        enum { NB = 10 };
        size_t cnt[NB]; for (int b = 0; b < NB; b++) cnt[b] = 0;
        double range = mx - mn;
        for (size_t i = 0; i < data.n; i++) {
            int b = 0;
            if (range > 0.0) {
                b = (int)((data.v[i] - mn) / range * (double)NB);
                if (b >= NB) b = NB - 1; else if (b < 0) b = 0;
            }
            cnt[b]++;
        }
        size_t maxc = 0; for (int b = 0; b < NB; b++) if (cnt[b] > maxc) maxc = cnt[b];
        int nb = (range > 0.0) ? NB : 1;     // all values equal -> a single bin
        double bw = range / NB;
        for (int b = 0; b < nb; b++) {
            size_t blen = maxc ? cnt[b] * 40 / maxc : 0;
            if (cnt[b] > 0 && blen == 0) blen = 1;  // a non-empty bin always shows one block
            char bar[3 * 40 + 1]; size_t bl = 0;    // '█' FULL BLOCK is the bar glyph
            for (size_t k = 0; k < blen; k++) { bar[bl++] = (char)0xE2; bar[bl++] = (char)0x96; bar[bl++] = (char)0x88; }
            bar[bl] = '\0';
            montauk_sink_appendf(&g_out, "%-12.6g %6zu  %s\n", mn + (double)b * bw, cnt[b], bar);
        }

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
        if (values) {
            // select-by-structure: emit the VALUES any matching window covers, each
            // once in input order -- "the part of the stream that IS this class".
            char *cov = (char *)calloc(data.n, 1);
            for (size_t i = 0; i < k; i++)
                for (size_t j = m[i].start; j < m[i].start + m[i].len && j < data.n; j++) cov[j] = 1;
            for (size_t j = 0; j < data.n; j++)
                if (cov[j]) montauk_sink_appendf(&g_out, "%.12g\n", data.v[j]);
            free(cov);
        } else {
            montauk_sink_appendf(&g_out, "%zu window(s) matching %s:\n", k, sublimation_disorder_name(target));
            for (size_t i = 0; i < k; i++)
                montauk_sink_appendf(&g_out, "  [%zu,%zu)  inv=%.2f  distinct~%zu\n",
                       m[i].start, m[i].start + m[i].len,
                       (double)m[i].inversion_ratio, m[i].distinct_estimate);
        }
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
