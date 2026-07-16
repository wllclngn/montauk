// sublimation -- command-line front door to the adaptive sort and search core.
//
// Reads a numeric stream on stdin, runs one sublimation primitive, writes the
// result to stdout. This is the data-side answer to "stop reaching for awk and
// sort": ordering, percentiles, k-th selection, value lookup, disorder
// classification, structural location, and a max-entropy randomness verdict --
// all through the one library, no shell-stats pipeline.
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
//   sublimation search PATTERN [-F] [-k N] [-i] [-o] [-v] [-c] [-n]  (the tri-face matcher)
//   sublimation field N[,M..] [--delim D]                (column(s) -- awk '{print $N}', '{print $1,$3}')
//   sublimation where 'N OP V' [--delim D]               (numeric column filter -- awk '$N OP V')
//
// CLASS is one of: sorted reversed nearly-sorted few-unique random phased spectral
// --field N pulls the N-th (1-based) delimited column per line, so awk's column
// extraction is folded in -- no `awk '{print $N}' | ...` needed.
//
// The numeric commands read one value per line (or per --field column). search and
// field read whole text lines; search prints matching lines (the order-free search
// side, one engine: literal, regex or fuzzy), field prints a column. One tool for
// sort, awk and grep.

#include "sublimation.h"
#include "sublimation_pack.h"
#include "sublimation_search.h"
#include "sublimation_randomness.h"
#include "sublimation_text.h"

#include "util/sink.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#include <unistd.h>

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
        "  count [--words|--bytes] number of input lines/words/bytes (wc -l/-w/-c)\n"
        "  head N                first N lines (head -N)\n"
        "  tail N                last N lines (tail -N)\n"
        "  distinct              count of distinct tokens (sort | uniq | wc -l)\n"
        "  tally                 per-token frequency, high to low (sort | uniq -c | sort -rn)\n"
        "  classify              disorder class + profile of the stream\n"
        "  locate CLASS [--values]  windows whose disorder class == CLASS (--values: select-by-structure, emit the data in them)\n"
        "  rand                  max-entropy randomness confidence\n"
        "  characterize          structural verdict: class, rand confidence, sort efficiency\n"
        "  search PATTERN [FILE..] matching lines; one engine, three faces (literal -F,\n"
        "                        regex default, fuzzy -k N); stdin or FILE(s)\n"
        "                        search: -A N/-B N/-C N trailing/leading/both context lines\n"
        "  replace PAT REPL      regex substitution, global per line (sed s/pat/repl/g; REPL literal)\n"
        "  field N[,M..] [FILE..] the N-th column, or a comma-list, of each line (awk '{print $N}')\n"
        "  where 'N OP V' [FILE] lines where field N OP V (awk '$N OP V'; OP: < <= > >= == !=)\n"
        "  group KEY OP [VAL]    group by field KEY, aggregate field VAL (datamash -g; OP: sum|mean|count|min|max)\n"
        "  uniq [-d|-u] [-i]     collapse adjacent duplicate lines (-d dups only, -u uniques only, -i case-insensitive)\n"
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
        "  -v / -c / -n          search: invert match / count only (per file) / line number\n"
        "  -i / -o               search: case-insensitive (-i) / print only the match (-o)\n"
        "  -q / -m N             search: quiet (exit status only) / stop after N matches per file\n"
        "  -F / -E               search: fixed string (literal) / extended regex (the default)\n"
        "  -k N                  search: fuzzy, match within N mismatches (approximate)\n"
        "  -A N / -B N / -C N    search: N lines of trailing/leading/both context (-C = both);\n"
        "                        standalone tokens only, not bundleable with other short flags\n"
        "  -w / -x               search: whole words only / whole line must match\n"
        "  -l / -L               search: only names of files with / without a match\n"
        "  -e PAT / -f FILE      search: add PAT / FILE's lines to the pattern set (a line\n"
        "                        matches if ANY pattern does); positionals all become\n"
        "                        input files, like grep\n"
        "  -H / -h               search: force the filename prefix on / off\n"
        "  -s                    search: silence cannot-open messages (exit 2 still reported)\n"
        "  -a / -I               search: binary input as text / as never-matching (default:\n"
        "                        a 'binary file matches' notice, match lines suppressed)\n"
        "  -S                    search: smart case, a ripgrep-ism -- case-insensitive\n"
        "                        unless a pattern contains an uppercase letter\n"
        "  --label NAME          search: NAME stands in for '(standard input)'\n"
        "  --line-buffered       search: flush per output line (automatic at a TTY)\n"
        "  --color WHEN          search: highlight matches, filenames, line numbers\n"
        "                        (auto|always|never; bare --color = auto; also --color=WHEN)\n"
        "  --files-from LIST     search: read input paths from LIST, newline- or NUL-\n"
        "                        delimited, '-' = stdin (find ... | search --files-from -)\n"
        "  --words / --bytes     count: word count / byte count instead of line count (wc -w/-c)\n"
        "  short flags bundle    -iE == -i -E, -vn == -v -n, ...\n"
        "  --nearest             quantile: nearest-rank order statistic (not the estimator)\n"
        "\n"
        "exit: search/field return 0 when something matched, 1 when nothing did;\n"
        "      search returns 2 when an input FILE cannot be read (grep's contract:\n"
        "      -q with a match still returns 0; -s silences the message only).\n",
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

// Grow-on-demand parallel (key, line) buffers for `sort --keyed` -- the
// row-preserving keyed sort. Ordered by sublimation_pack_sort_f64 (stable
// index sort, IEEE754 total-order key transform with the index as a radix
// satellite), so ties keep insertion order in both directions with no
// comparator and no libc qsort. The index is uint32_t, so the verb carries
// the library's documented 2^32-line cap.
typedef struct { double *keys; char **lines; size_t n, cap; } KeyedBuf;
static void keyed_push(KeyedBuf *a, double key, char *line) {
    if (a->n == a->cap) {
        a->cap = a->cap ? a->cap * 2 : 1024;
        a->keys  = (double *)realloc(a->keys,  a->cap * sizeof(double));
        a->lines = (char **)realloc(a->lines, a->cap * sizeof(char *));
        if (!a->keys || !a->lines) { fputs("sublimation: out of memory\n", stderr); exit(1); }
    }
    a->keys[a->n] = key; a->lines[a->n] = line;
    a->n++;
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

// ASCII case-fold byte comparison for uniq -i -- ASCII only, same scope as
// grep/contains' own -i (icase folds ASCII, not full UTF-8 case folding).
static int lines_equal_ci(const char *a, const char *b, size_t l, int icase) {
    if (!icase) return memcmp(a, b, l) == 0;
    for (size_t i = 0; i < l; i++) {
        unsigned char ca = (unsigned char)a[i], cb = (unsigned char)b[i];
        if (ca >= 'A' && ca <= 'Z') ca = (unsigned char)(ca + ('a' - 'A'));
        if (cb >= 'A' && cb <= 'Z') cb = (unsigned char)(cb + ('a' - 'A'));
        if (ca != cb) return 0;
    }
    return 1;
}

// SEARCH HELPERS -- the grep-coverage layer over the tri-face matcher. The
// engine (sublimation_text.h) reports leftmost-longest spans; everything
// grep-shaped that is about LINES and FILES rather than raw matches (word and
// whole-line gating, the multi-pattern OR, prefixes, colors, the path list)
// lives here in the CLI.

// [A-Za-z0-9_], grep -w's word alphabet -- explicit ranges, not isalnum(), so
// the locale can never shift the boundary set.
static int word_byte(unsigned char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '_';
}

// -w boundary test: span [s,e) of line[0..n) counts only when neither
// neighbor is a word byte (a line edge counts as non-word).
static int word_bounded(const char *line, size_t n, long s, long e) {
    if (s > 0 && word_byte((unsigned char)line[s - 1])) return 0;
    if ((size_t)e < n && word_byte((unsigned char)line[e])) return 0;
    return 1;
}

// Next candidate span for ONE pattern at or after `from`, with the -w word
// filter applied. A rejected candidate at start X resumes the scan at X + 1
// (grep's rule -- skipping the rest of the line would drop later words).
// regex_face: find_from reports only the LONGEST end per start, but grep -w
// admits any match length ('a-|a' on "a-b" must still hit the word "a",
// verified against /usr/bin/grep), so on rejection the shorter ends at the
// same start are probed through full_match. ^ is already satisfied (the
// start came from find_from); $-anchored patterns skip the probe since their
// matches may only end at n.
static long search_next_match(const sublimation_search *s, int regex_face,
                              const char *line, size_t n, size_t from,
                              int wword, long *end_out) {
    size_t off = from;
    while (off <= n) {
        long e = -1;
        long st = sublimation_search_find_from(s, line, n, off, &e);
        if (st < 0) return -1;
        if (!wword || word_bounded(line, n, st, e)) { *end_out = e; return st; }
        if (regex_face && !s->g.anchored_end) {
            for (long e2 = e - 1; e2 >= st; e2--) {
                if (!word_bounded(line, n, st, e2)) continue;
                if (sublimation_search_full_match(s, line + st, (size_t)(e2 - st))) {
                    *end_out = e2;
                    return st;
                }
            }
        }
        off = (size_t)st + 1;
    }
    return -1;
}

// Leftmost-longest next span across the WHOLE pattern set: -e/-f is one big
// alternation to grep, so ties at one start go to the longest match across
// all patterns (verified against /usr/bin/grep -o on overlapping patterns).
static long search_next_any(const sublimation_search *set, int nset, int regex_face,
                            const char *line, size_t n, size_t off,
                            int wword, long *end_out) {
    long bs = -1, be = -1;
    for (int p = 0; p < nset; p++) {
        long e = -1;
        long st = search_next_match(&set[p], regex_face, line, n, off, wword, &e);
        if (st < 0) continue;
        if (bs < 0 || st < bs || (st == bs && e > be)) { bs = st; be = e; }
    }
    if (bs >= 0 && end_out) *end_out = be;
    return bs;
}

// Line selection: does ANY pattern accept the line under -x / -w? -x is
// grep's whole-line gate -- full_match covers all three faces (regex end to
// end, fixed/fuzzy length-equal compare, fuzzy within k mismatches).
static int search_selects(const sublimation_search *set, int nset, int regex_face,
                          const char *line, size_t n, int xline, int wword) {
    for (int p = 0; p < nset; p++) {
        if (xline) {
            if (sublimation_search_full_match(&set[p], line, n)) return 1;
        } else {
            long e = -1;
            if (search_next_match(&set[p], regex_face, line, n, 0, wword, &e) >= 0) return 1;
        }
    }
    return 0;
}

// grep's line prefix: "name:12:" for a match, "name-12-" for context. Colors
// are GREP_COLORS' defaults (fn=35 filename, ln=32 line number, se=36
// separator) when on; the reset is \x1b[0m, and the \x1b[K erase grep appends
// per fragment is deliberately dropped -- a terminal redraw nicety, not match
// data.
static void emit_prefix(montauk_sink *out, const char *name, long lineno,
                        int number, char sep, int color) {
    if (name) {
        if (color) montauk_sink_appendf(out, "\x1b[35m%s\x1b[0m\x1b[36m%c\x1b[0m", name, sep);
        else       montauk_sink_appendf(out, "%s%c", name, sep);
    }
    if (number) {
        if (color) montauk_sink_appendf(out, "\x1b[32m%ld\x1b[0m\x1b[36m%c\x1b[0m", lineno, sep);
        else       montauk_sink_appendf(out, "%ld%c", lineno, sep);
    }
}

// The "--" separator between non-adjacent context blocks (se-colored, like grep).
static void emit_ctx_sep(montauk_sink *out, int color) {
    if (color) montauk_sink_append(out, "\x1b[36m--\x1b[0m\n", 12);
    else       montauk_sink_append(out, "--\n", 3);
}

// A bare file name line (-l / -L), fn-colored like grep's.
static void emit_name(montauk_sink *out, const char *name, int color) {
    if (color) montauk_sink_appendf(out, "\x1b[35m%s\x1b[0m\n", name);
    else       montauk_sink_appendf(out, "%s\n", name);
}

// Selected-line content with every match span in grep's match color (ms=01;31).
// Spans are re-derived through the same candidate walk selection used, so the
// highlight can never disagree with the selection. rawlen keeps the original
// trailing-newline byte (or its absence) intact.
static void emit_colored_line(montauk_sink *out, const sublimation_search *set, int nset,
                              int regex_face, const char *line, size_t mlen,
                              size_t rawlen, int xline, int wword) {
    size_t off = 0, cur = 0;
    while (off <= mlen) {
        long s, e = -1;
        if (xline) { s = 0; e = (long)mlen; }   // -x: the whole line is the match
        else s = search_next_any(set, nset, regex_face, line, mlen, off, wword, &e);
        if (s < 0) break;
        if (e > s) {
            montauk_sink_append(out, line + cur, (size_t)s - cur);
            montauk_sink_append(out, "\x1b[01;31m", 8);
            montauk_sink_append(out, line + s, (size_t)(e - s));
            montauk_sink_append(out, "\x1b[0m", 4);
            cur = (size_t)e;
            off = (size_t)e;
        } else {
            off = (size_t)s + 1;   // zero-width: no highlight, step on
        }
        if (xline) break;
    }
    montauk_sink_append(out, line + cur, rawlen - cur);
}

// Grow-on-demand strdup'd string list (search's pattern set and file list).
static void strlist_push(char ***v, int *n, int *cap, const char *s) {
    if (*n == *cap) {
        *cap = *cap ? *cap * 2 : 16;
        *v = (char **)realloc(*v, (size_t)*cap * sizeof(char *));
        if (!*v) { fputs("sublimation: out of memory\n", stderr); exit(1); }
    }
    (*v)[(*n)++] = strdup(s);
}

// --files-from LIST: input file paths, newline- or NUL-delimited ('-' =
// stdin); NUL-delimited is auto-detected (any NUL byte in the list = find
// -print0 form). This is search's traversal affordance: `find ... |
// sublimation search PAT --files-from -` covers grep -r while directory
// walking stays find's job, by target. Blank entries are skipped. Returns -1
// when LIST cannot be opened.
static int load_files_from(const char *list, char ***v, int *n, int *cap) {
    FILE *f = strcmp(list, "-") ? fopen(list, "r") : stdin;
    if (!f) return -1;
    char *buf = NULL;
    size_t blen = 0, bcap = 0;
    char chunk[4096];
    size_t got;
    while ((got = fread(chunk, 1, sizeof chunk, f)) > 0) {
        if (blen + got + 1 > bcap) {
            bcap = bcap ? bcap * 2 : 8192;
            while (bcap < blen + got + 1) bcap *= 2;
            buf = (char *)realloc(buf, bcap);
            if (!buf) { fputs("sublimation: out of memory\n", stderr); exit(1); }
        }
        memcpy(buf + blen, chunk, got);
        blen += got;
    }
    if (f != stdin) fclose(f);
    char dch = (buf && memchr(buf, 0, blen)) ? '\0' : '\n';
    for (size_t i = 0; i < blen; ) {
        size_t start = i;
        while (i < blen && buf[i] != dch) i++;
        buf[i] = '\0';   // safe: bcap always holds one spare byte past blen
        if (i > start) strlist_push(v, n, cap, buf + start);
        i++;
    }
    free(buf);
    return 0;
}

// Rebuild `line` with its `field`-th (1-based) token removed, remaining
// tokens rejoined with `sep` -- used by `join` so the join-key field appears
// exactly once in the output instead of once per side. `sep` matches real
// join -t: a plain space by default, but the same single character as
// --delim when one was explicitly given (join -tCHAR uses CHAR for both
// parsing and output; a bare space regardless of --delim would silently
// diverge from real join's byte output on any non-default delimiter). Caller
// frees the result.
static char *fields_excluding(const char *line, size_t len, int field, const char *delim, char sep) {
    char *copy = (char *)malloc(len + 1);
    memcpy(copy, line, len); copy[len] = '\0';
    char *out = (char *)malloc(len + 1); out[0] = '\0';
    char *save = NULL; int col = 0; int first = 1;
    char sepbuf[2] = {sep, '\0'};
    for (char *tok = strtok_r(copy, delim, &save); tok; tok = strtok_r(NULL, delim, &save)) {
        col++;
        if (col == field) continue;
        if (!first) strcat(out, sepbuf);
        strcat(out, tok);
        first = 0;
    }
    free(copy);
    return out;
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
    int delim_set = 0;  // true once --delim is explicitly given (join's output separator cares)
    int desc = 0;
    int keyed = 0;                                // sort --keyed: preserve full lines, order by key
    size_t window = 512, stride = 0;
    int invert = 0, count_only = 0, number = 0;  // search line-filter flags
    int icase = 0, only_match = 0, fixed = 0;     // search -i (case-fold), -o (matches only), -F (fixed string)
    int quiet = 0;                                // search -q: exit status only, no output
    long max_count = 0;                           // search -m N: stop after N matches per file (0 = unlimited)
    long kval = 0;                                // search -k N: fuzzy, up to N mismatches (0 = exact/regex)
    int word_match = 0, line_match = 0;           // search -w (whole words) / -x (whole line)
    int names_only = 0, names_without = 0;        // search -l / -L (file names with / without a match)
    int suppress = 0;                             // search -s: silence cannot-open messages (exit 2 stands)
    int bin_text = 0, bin_skip = 0;               // search -a (binary as text) / -I (binary never matches)
    int fname_on = 0, fname_off = 0;              // search -H / -h: force the filename prefix on / off
    int smartcase = 0;                            // search -S: smart case (a ripgrep-ism)
    int line_buffered = 0;                        // search --line-buffered: drain per output line
    int color_mode = 0;                           // search --color: 0 never, 1 auto (TTY), 2 always
    const char *label = NULL;                     // search --label: stdin's display name
    const char *files_from = NULL;                // search --files-from: input path list ('-' = stdin)
    const char *epats[256]; int nepat = 0;        // search -e PAT (repeatable)
    const char *pfiles[64]; int npfile = 0;       // search -f FILE (newline-separated patterns)
    int nearest = 0;                              // quantile --nearest: nearest-rank, not estimator
    int uniq_d = 0, uniq_u = 0;                   // uniq -d (dups only) / -u (uniques only)
    int serial = 0;                               // paste -s: serialize lines into one
    int endopts = 0;                              // after `--`, everything is positional
    int values = 0;                               // locate --values: select-by-structure (emit the data)
    int count_words = 0, count_bytes = 0;         // count --words / --bytes (default: lines, wc -l)
    long ctx_after = 0, ctx_before = 0;            // grep/contains -A N / -B N (0 = no context)
    const char *pos = NULL;  // positional arg (Q / K / V / CLASS / N)
    const char *files[256];  // grep/contains/field: input files after the pattern
    int nfiles = 0;          // 0 -> read stdin (the pipe case)
    int is_search = !strcmp(cmd, "search");  // several short flags are verb-scoped (see the bundle switch)

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
        else if (!strcmp(a, "--delim") && i + 1 < argc) { delim = argv[++i]; delim_set = 1; }
        else if (!strcmp(a, "--desc")) desc = 1;
        else if (!strcmp(a, "--keyed")) keyed = 1;  // sort: keep the whole line, order by the key
        else if (!strcmp(a, "--window") && i + 1 < argc) window = strtoull(argv[++i], NULL, 10);
        else if (!strcmp(a, "--stride") && i + 1 < argc) stride = strtoull(argv[++i], NULL, 10);
        else if (!strcmp(a, "--nearest")) nearest = 1;  // quantile: nearest-rank order statistic
        else if (!strcmp(a, "--values")) values = 1;    // locate: emit data, not window ranges
        else if (!strcmp(a, "--words")) count_words = 1;  // count: word count -- wc -w
        else if (!strcmp(a, "--bytes")) count_bytes = 1;  // count: byte count -- wc -c
        else if (!strcmp(a, "-m") && i + 1 < argc) max_count = strtol(argv[++i], NULL, 10);  // search -m N
        else if (!strcmp(a, "-k") && i + 1 < argc) kval = strtol(argv[++i], NULL, 10);       // search -k N (fuzzy)
        else if (!strcmp(a, "-A") && i + 1 < argc) ctx_after = strtol(argv[++i], NULL, 10);   // grep -A N
        else if (!strcmp(a, "-B") && i + 1 < argc) ctx_before = strtol(argv[++i], NULL, 10);  // grep -B N
        else if (!strcmp(a, "-C") && i + 1 < argc) ctx_after = ctx_before = strtol(argv[++i], NULL, 10);  // grep -C N
        else if (is_search && !strcmp(a, "-e") && i + 1 < argc) {                             // grep -e PAT (repeatable)
            if (nepat >= 256) { fprintf(stderr, "sublimation: too many -e patterns\n"); return 2; }
            epats[nepat++] = argv[++i];
        }
        else if (is_search && !strcmp(a, "-f") && i + 1 < argc) {                             // grep -f FILE (pattern file)
            if (npfile >= 64) { fprintf(stderr, "sublimation: too many -f files\n"); return 2; }
            pfiles[npfile++] = argv[++i];
        }
        else if (is_search && !strcmp(a, "--label") && i + 1 < argc) label = argv[++i];
        else if (is_search && !strncmp(a, "--label=", 8)) label = a + 8;
        else if (is_search && !strcmp(a, "--line-buffered")) line_buffered = 1;
        else if (is_search && !strcmp(a, "--color")) color_mode = 1;      // bare --color = auto, like grep
        else if (is_search && !strncmp(a, "--color=", 8)) {
            const char *w = a + 8;
            if      (!strcmp(w, "always")) color_mode = 2;
            else if (!strcmp(w, "auto"))   color_mode = 1;
            else if (!strcmp(w, "never"))  color_mode = 0;
            else { fprintf(stderr, "sublimation: --color takes auto|always|never\n"); return 2; }
        }
        else if (is_search && !strcmp(a, "--files-from") && i + 1 < argc) files_from = argv[++i];
        else if (a[0] == '-' && a[1] && a[1] != '-') {
            // Bundled short flags, getopt-style: -iE == -i -E, -vn == -v -n. Each
            // char is one boolean grep flag. -E (extended regex) is a no-op:
            // sublimation's NFA is already RE2-lineage ERE, so it is accepted for
            // grep compatibility rather than switching dialects.
            // The letter set is verb-scoped: search owns grep's letters (-s is
            // "silence open errors" there, -d/-u are unknown), everyone else
            // keeps uniq's -d/-u and paste's -s. Same byte, different verb,
            // different meaning -- scoping is what keeps both correct.
            for (const char *f = a + 1; *f; f++) {
                int known = 1;
                if (is_search) {
                    switch (*f) {
                        case 'v': invert = 1; break;       // grep -v: print non-matching
                        case 'c': count_only = 1; break;   // grep -c: count, not lines
                        case 'n': number = 1; break;       // grep -n: 1-based line number
                        case 'i': icase = 1; break;        // grep -i: ASCII case-insensitive
                        case 'o': only_match = 1; break;   // grep -o: print only the match
                        case 'q': quiet = 1; break;        // grep -q: exit status only, no output
                        case 'F': fixed = 1; break;        // grep -F: fixed string (literal), the anchor face
                        case 'E': break;                   // grep -E: already extended; accept, no-op
                        case 'w': word_match = 1; break;   // grep -w: whole words only
                        case 'x': line_match = 1; break;   // grep -x: the whole line must match
                        case 'l': names_only = 1; break;   // grep -l: names of matching files
                        case 'L': names_without = 1; break;// grep -L: names of files without a match
                        case 's': suppress = 1; break;     // grep -s: silence cannot-open messages
                        case 'a': bin_text = 1; break;     // grep -a: binary input as text
                        case 'I': bin_skip = 1; break;     // grep -I: binary input never matches
                        case 'H': fname_on = 1; break;     // grep -H: always prefix the filename
                        case 'h': fname_off = 1; break;    // grep -h: never prefix the filename
                        case 'S': smartcase = 1; break;    // smart case (ripgrep-ism): -i unless a pattern has an uppercase letter
                        default: known = 0; break;
                    }
                } else {
                    switch (*f) {
                        case 'v': invert = 1; break;
                        case 'c': count_only = 1; break;
                        case 'n': number = 1; break;
                        case 'i': icase = 1; break;
                        case 'o': only_match = 1; break;
                        case 'q': quiet = 1; break;
                        case 'F': fixed = 1; break;
                        case 'E': break;
                        case 'd': uniq_d = 1; break;       // uniq -d: only duplicated lines
                        case 'u': uniq_u = 1; break;       // uniq -u: only unique lines
                        case 's': serial = 1; break;       // paste -s: serialize lines into one
                        default: known = 0; break;
                    }
                }
                if (!known) {
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
    if (!strcmp(cmd, "search")) {
        int regex_face = (!fixed && kval == 0);   // the face decides -w's shorter-end probe
        // Pattern set. grep's rule: the bare first argument is the pattern only
        // until -e/-f names one -- after that EVERY positional is an input FILE.
        char **pats = NULL; int npat = 0, patcap = 0;
        if (nepat > 0 || npfile > 0) {
            for (int p = 0; p < nepat; p++) strlist_push(&pats, &npat, &patcap, epats[p]);
            for (int p = 0; p < npfile; p++) {
                FILE *pf = strcmp(pfiles[p], "-") ? fopen(pfiles[p], "r") : stdin;
                if (!pf) { fprintf(stderr, "sublimation: cannot open '%s'\n", pfiles[p]); return 2; }
                char *pl = NULL; size_t plc = 0; ssize_t pll;
                while ((pll = getline(&pl, &plc, pf)) != -1) {
                    if (pll > 0 && pl[pll - 1] == '\n') pl[--pll] = '\0';
                    strlist_push(&pats, &npat, &patcap, pl);   // an empty line = match-all, like grep -f
                }
                free(pl);
                if (pf != stdin) fclose(pf);
            }
            // -f named only empty files: nothing can ever match (grep -f /dev/null).
            if (npat == 0) return 1;
        } else {
            if (!pos) {
                fprintf(stderr, "sublimation: search needs a PATTERN\n");
                return 2;
            }
            strlist_push(&pats, &npat, &patcap, pos);
            pos = NULL;   // consumed as the pattern, not an input file
        }
        // -S smart case (a ripgrep-ism, not in grep, and documented as such in
        // the help): fold ASCII case unless some pattern carries an explicit
        // uppercase letter.
        if (smartcase && !icase) {
            int has_upper = 0;
            for (int p = 0; p < npat && !has_upper; p++)
                for (const char *c2 = pats[p]; *c2; c2++)
                    if (*c2 >= 'A' && *c2 <= 'Z') { has_upper = 1; break; }
            if (!has_upper) icase = 1;
        }
        // One engine, three faces: -F literal (anchor), default regex (field),
        // -k N fuzzy (pigeonhole). -i folds ASCII case across all of them. One
        // compiled program per pattern; a line matches if ANY pattern does.
        unsigned sflags = (fixed ? SUBLIMATION_SEARCH_FIXED : 0u)
                        | (icase ? SUBLIMATION_SEARCH_ICASE : 0u);
        sublimation_search *srchs =
            (sublimation_search *)malloc((size_t)npat * sizeof(sublimation_search));
        if (!srchs) { fputs("sublimation: out of memory\n", stderr); return 1; }
        for (int p = 0; p < npat; p++) {
            // The empty pattern matches every line in every face (grep -F ''
            // included), but the fixed/fuzzy compilers reject len == 0 -- route
            // it through the regex face, whose "" is the legal zero-width
            // match-all.
            unsigned pflags = pats[p][0] ? sflags : (sflags & SUBLIMATION_SEARCH_ICASE);
            int pk = pats[p][0] ? (int)kval : 0;
            sublimation_search_compile(&srchs[p], pats[p], strlen(pats[p]), pflags, pk);
            if (!sublimation_search_valid(&srchs[p])) {
                fprintf(stderr, "sublimation: bad pattern '%s'\n", pats[p]);
                return 2;
            }
        }
        // Input set: the positionals plus --files-from's list, in that order.
        // An empty --files-from list means "no inputs" (exit 1), never a
        // silent fallback to stdin.
        char **sfiles = NULL; int nsf = 0, sfcap = 0;
        if (pos) strlist_push(&sfiles, &nsf, &sfcap, pos);   // only when -e/-f made it a FILE
        for (int fi = 0; fi < nfiles; fi++) strlist_push(&sfiles, &nsf, &sfcap, files[fi]);
        if (files_from && load_files_from(files_from, &sfiles, &nsf, &sfcap) != 0) {
            fprintf(stderr, "sublimation: cannot open '%s'\n", files_from);
            return 2;
        }
        int use_stdin = (nsf == 0 && !files_from);
        // Filename prefix: grep's default (several inputs) overridden by
        // -H / -h. --files-from entries count exactly like positionals here.
        int prefix = fname_off ? 0 : (fname_on || nsf > 1);
        int color = (color_mode == 2) || (color_mode == 1 && isatty(1));
        // --line-buffered, and implicitly at a TTY: drain the sink per output
        // line so hits land as they happen, not at buffer-fill boundaries.
        int line_drain = line_buffered || isatty(1);
        char *line = NULL;
        size_t cap = 0;
        ssize_t len;
        long matches = 0;                 // total selected lines/spans: the exit-code source
        int q_done = 0;                   // -q: stop everything at the first hit
        int had_error = 0;                // an unreadable FILE -> exit 2, grep's contract
        // -A/-B/-C context lines. Confirmed directly against real grep before
        // writing this: -o disables context entirely (real grep does too);
        // -n marks a matched/shown line with ':' but a context line with '-'
        // (both the line number and, for multi-file, the filename prefix);
        // non-adjacent context blocks get a bare "--" separator, but never
        // before the very first printed block. want_ctx guards all of it so
        // the zero-context case (the overwhelming common one) runs the exact
        // same code path as before this feature existed.
        // Active whenever -A/-B/-C was given at all. -o still uses this --
        // real GNU grep keeps the "--" block separator between distant
        // matches even in -o mode, it just never prints actual context
        // *text* there (there is no non-matching line content to show
        // alongside a bare match span). Confirmed directly against
        // /usr/bin/grep, not this shell's own grep function (which shells
        // out to ugrep for anything not matching a narrow passthrough list
        // -- ugrep disables the separator entirely with -o, a real,
        // confirmed difference from GNU grep, not a mistake in this check).
        int want_ctx = (ctx_after > 0 || ctx_before > 0);
        typedef struct { char *data; size_t len; long lineno; } CtxLine;
        size_t ring_cap = (size_t)(ctx_before > 0 ? ctx_before : 0);
        CtxLine *ring = ring_cap ? (CtxLine *)calloc(ring_cap, sizeof(CtxLine)) : NULL;
        size_t ring_n = 0, ring_next = 0;
        long last_printed_line = 0;   // 0 == nothing printed yet THIS FILE
        long after_remaining = 0;
        // Persists ACROSS files, unlike last_printed_line above: real grep
        // still opens a "--" separator between file1's last shown content
        // and file2's first, even though line numbers restart at 1 for the
        // new file (so last_printed_line's own per-file contiguity check
        // can never fire there on its own -- confirmed directly against
        // /usr/bin/grep with two files).
        int printed_any = 0;
        // Read each named file, or stdin when none were given. A single named file
        // is the common `grep PATTERN file` idiom -- sublimation serves it directly
        // now instead of treating the path as an unexpected argument. Native
        // traversal (-r, globs) is still find's job, by target; --files-from
        // above is the bridge.
        for (int fi = 0; fi < (use_stdin ? 1 : nsf) && !q_done; fi++) {
            FILE *in = stdin;
            const char *fname = NULL;
            if (!use_stdin) {
                fname = sfiles[fi];
                in = fopen(fname, "r");
                if (!in) {
                    // -s silences the message only; the exit-2 verdict stands
                    // (grep: -q with a match is the one thing that outranks it).
                    had_error = 1;
                    if (!suppress) fprintf(stderr, "sublimation: cannot open '%s'\n", fname);
                    continue;
                }
            }
            const char *disp = fname ? fname : (label ? label : "(standard input)");
            // Binary sniff, grep-shaped: a NUL in the first 32 KiB names the
            // file binary BEFORE any line is matched (then rewind for the line
            // loop). Only seekable inputs sniff; stdin and fifos fall back to
            // the per-line check below, so a NUL there flips the verdict from
            // that line on. (grep can classify later than 32 KiB when its read
            // buffer grew first -- a match printed before a NUL that deep is
            // the one place this can diverge.)
            int binary = 0, bin_announced = 0;
            if (!bin_text && in != stdin && lseek(fileno(in), 0, SEEK_CUR) != -1) {
                char sniff[4096];
                size_t seen = 0;
                while (seen < (1u << 15)) {
                    size_t got = fread(sniff, 1, sizeof sniff, in);
                    if (got == 0) break;
                    if (memchr(sniff, 0, got)) { binary = 1; break; }
                    seen += got;
                }
                fseek(in, 0, SEEK_SET);
            }
            if (binary && bin_skip) {   // -I: binary simply has no matching data
                fclose(in);
                if (names_without && !quiet) {   // ... which is exactly what -L lists
                    emit_name(&g_out, disp, color);
                    if (line_drain) montauk_sink_drain(&g_out);
                }
                continue;
            }
            long lineno = 0, fmatches = 0;
            int fdone = 0;   // per-file stop: -l hit, -m N reached, binary announced
            // Context state resets per file, same as real grep -- except
            // printed_any (declared outside the file loop, see above).
            ring_n = 0; ring_next = 0; last_printed_line = 0; after_remaining = 0;
            for (size_t z = 0; z < ring_cap; z++) { free(ring[z].data); ring[z].data = NULL; }
            while (!fdone && !q_done && (len = getline(&line, &cap, in)) != -1) {
                lineno++;
                size_t mlen = (size_t)len;
                if (mlen && line[mlen - 1] == '\n') mlen--;  // match without the trailing newline
                if (!bin_text && !binary && memchr(line, 0, mlen)) binary = 1;
                if (binary && bin_skip) { fmatches = 0; break; }  // NUL past the sniff window: same -I verdict

                if (only_match && !names_only && !names_without) {
                    if (invert) {
                        // grep -v -o prints nothing, but the line still
                        // selects: the exit code follows the lines.
                        if (!search_selects(srchs, npat, regex_face, line, mlen, line_match, word_match)) {
                            fmatches++;
                            if (quiet) q_done = 1;
                            else if (max_count && fmatches >= max_count) fdone = 1;
                        }
                        continue;
                    }
                    // grep -o: every non-overlapping span of every pattern,
                    // leftmost-longest across the whole set. -x collapses to
                    // one whole-line span.
                    size_t off = 0;
                    int line_has_match = 0;
                    while (off <= mlen && !fdone && !q_done) {
                        long end = -1, s;
                        if (line_match) {
                            if (!search_selects(srchs, npat, regex_face, line, mlen, 1, word_match)) break;
                            s = 0; end = (long)mlen;
                        } else {
                            // find_from (inside search_next_*) keeps ^/$ anchored
                            // to the real line ends across restarts; a shifted
                            // `line + off` buffer would let ^ match again at
                            // every continuation offset.
                            s = search_next_any(srchs, npat, regex_face, line, mlen, off, word_match, &end);
                            if (s < 0) break;
                        }
                        size_t mstart = (size_t)s;
                        size_t mend = (size_t)end;
                        if (mend > mstart) {
                            fmatches++;
                            if (!quiet && !count_only) {
                                if (binary) {
                                    if (!bin_announced) {
                                        fprintf(stderr, "sublimation: %s: binary file matches\n", disp);
                                        bin_announced = 1;
                                    }
                                    fdone = 1;   // the verdict is in; nothing more may print
                                    break;
                                }
                                if (want_ctx && !line_has_match) {
                                    // No context text to print here (see want_ctx's
                                    // comment above) -- just whether this match's
                                    // line is farther from the last one than the
                                    // combined -A/-B reach, real grep's own rule.
                                    // printed_any (not last_printed_line, which is
                                    // per-file) gates whether a separator can appear
                                    // at all -- a fresh file's first match must not
                                    // get one, but it does need one if a PRIOR file
                                    // already printed something (real grep still
                                    // separates across a file boundary).
                                    if (printed_any && (last_printed_line == 0 ||
                                        lineno - ctx_before > last_printed_line + ctx_after + 1))
                                        emit_ctx_sep(&g_out, color);
                                    last_printed_line = lineno;
                                }
                                line_has_match = 1;
                                printed_any = 1;
                                emit_prefix(&g_out, prefix ? disp : NULL, lineno, number, ':', color);
                                if (color) {
                                    montauk_sink_append(&g_out, "\x1b[01;31m", 8);
                                    montauk_sink_append(&g_out, line + mstart, mend - mstart);
                                    montauk_sink_append(&g_out, "\x1b[0m", 4);
                                } else {
                                    montauk_sink_append(&g_out, line + mstart, mend - mstart);
                                }
                                montauk_sink_appendc(&g_out, '\n');
                                if (line_drain) montauk_sink_drain(&g_out);
                                else if (g_out.len >= (1u << 16)) montauk_sink_drain(&g_out);
                            }
                            off = mend;            // continue after the match (non-overlapping)
                            if (quiet) q_done = 1;                                   // grep -q
                            else if (max_count && fmatches >= max_count) fdone = 1;  // grep -m, per FILE
                        } else {
                            off = mstart + 1;      // zero-width match: step past to make progress
                        }
                        if (line_match) break;     // at most one whole-line span
                    }
                    continue;
                }

                int show = search_selects(srchs, npat, regex_face, line, mlen, line_match, word_match);
                if (invert) show = !show;     // grep -v
                if (show) {
                    fmatches++;
                    if (quiet) { q_done = 1; continue; }         // grep -q
                    if (names_only) {                            // grep -l: the name once, then the next file
                        emit_name(&g_out, disp, color);
                        if (line_drain) montauk_sink_drain(&g_out);
                        fdone = 1;
                        continue;
                    }
                    if (names_without) { fdone = 1; continue; }  // grep -L: one hit disqualifies; stop reading
                    if (!count_only) {
                        if (binary) {
                            // grep's binary contract, verified against 3.12: one
                            // stderr notice ("grep: FILE: binary file matches"),
                            // no line output, exit still says "matched".
                            // Mirrored with our own prefix.
                            if (!bin_announced) {
                                fprintf(stderr, "sublimation: %s: binary file matches\n", disp);
                                bin_announced = 1;
                            }
                            fdone = 1;
                        } else {
                            if (want_ctx) {
                                long first_ctx_line = (ring_n > 0)
                                    ? ring[(ring_next + ring_cap - ring_n) % ring_cap].lineno
                                    : lineno;
                                if (printed_any && (last_printed_line == 0 || first_ctx_line != last_printed_line + 1))
                                    emit_ctx_sep(&g_out, color);
                                for (size_t k = 0; k < ring_n; k++) {
                                    size_t idx = (ring_next + ring_cap - ring_n + k) % ring_cap;
                                    emit_prefix(&g_out, prefix ? disp : NULL, ring[idx].lineno, number, '-', color);
                                    montauk_sink_append(&g_out, ring[idx].data, ring[idx].len);
                                    if (ring[idx].len == 0 || ring[idx].data[ring[idx].len - 1] != '\n')
                                        montauk_sink_appendc(&g_out, '\n');
                                }
                                ring_n = 0;
                                last_printed_line = lineno;
                            }
                            printed_any = 1;
                            emit_prefix(&g_out, prefix ? disp : NULL, lineno, number, ':', color);   // grep -n / file:
                            if (color) emit_colored_line(&g_out, srchs, npat, regex_face,
                                                         line, mlen, (size_t)len, line_match, word_match);
                            else montauk_sink_append(&g_out, line, (size_t)len);
                            if (line_drain) montauk_sink_drain(&g_out);
                            else if (g_out.len >= (1u << 16)) montauk_sink_drain(&g_out);  // bound memory
                            if (want_ctx) after_remaining = ctx_after;
                        }
                    }
                    if (max_count && fmatches >= max_count) fdone = 1;  // grep -m is per FILE
                } else if (want_ctx && !quiet && !count_only &&
                           !names_only && !names_without && !binary) {
                    if (after_remaining > 0) {
                        printed_any = 1;
                        emit_prefix(&g_out, prefix ? disp : NULL, lineno, number, '-', color);
                        montauk_sink_append(&g_out, line, (size_t)len);
                        if (line_drain) montauk_sink_drain(&g_out);
                        else if (g_out.len >= (1u << 16)) montauk_sink_drain(&g_out);
                        after_remaining--;
                        last_printed_line = lineno;
                    } else if (ring_cap > 0) {
                        size_t idx = ring_next;
                        free(ring[idx].data);
                        ring[idx].data = (char *)malloc((size_t)len);
                        memcpy(ring[idx].data, line, (size_t)len);
                        ring[idx].len = (size_t)len;
                        ring[idx].lineno = lineno;
                        ring_next = (ring_next + 1) % ring_cap;
                        if (ring_n < ring_cap) ring_n++;
                    }
                }
            }
            if (in != stdin) fclose(in);
            // grep -L: a fully read file with no hit gets its name listed. The
            // exit code still follows the MATCHES (grep 3.2 reverted 3.1's
            // listed-means-success experiment; 3.12 confirms: all listed and
            // nothing matched is still exit 1).
            if (names_without && !quiet && fmatches == 0) {
                emit_name(&g_out, disp, color);
                if (line_drain) montauk_sink_drain(&g_out);
            }
            // grep -c is PER FILE: "name:count" under the same prefix rule as
            // match lines (a zero still prints), a bare count otherwise.
            if (count_only && !quiet && !names_only && !names_without) {
                emit_prefix(&g_out, prefix ? disp : NULL, 0, 0, ':', color);
                montauk_sink_appendf(&g_out, "%ld\n", fmatches);
                if (line_drain) montauk_sink_drain(&g_out);
            }
            matches += fmatches;
        }
        free(line);
        if (ring) { for (size_t z = 0; z < ring_cap; z++) free(ring[z].data); free(ring); }
        for (int p = 0; p < npat; p++) free(pats[p]);
        free(pats);
        free(srchs);
        for (int fi = 0; fi < nsf; fi++) free(sfiles[fi]);
        free(sfiles);
        // grep's exit contract, verified against /usr/bin/grep 3.12: -q with a
        // match outranks everything (0); otherwise ANY read error is 2, even
        // when other files matched (-s silences the message, never the
        // status); else 0 when something was selected, 1 when nothing was --
        // so `if ... | sublimation search` and `&&` chains stay correct.
        if (quiet && matches) return 0;
        if (had_error) return 2;
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
            // -i (shared with grep/contains' icase flag): fold ASCII case for the
            // adjacent-duplicate comparison only -- the emitted line keeps its
            // original case, matching real uniq -i (first-of-run wins verbatim).
            if (have_prev && l == plen && lines_equal_ci(line, prev, l, icase)) { run++; continue; }
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

    // head/tail: first-N / last-N lines, exact byte passthrough (no added or
    // stripped newlines) -- the aged pipeline's most commonly reached-for
    // primitive, absent from sublimation until now. head stops after N lines,
    // bounded work; tail keeps only the last N in a fixed-size ring buffer,
    // bounded memory regardless of input size.
    if (!strcmp(cmd, "head") || !strcmp(cmd, "tail")) {
        if (!pos) { fprintf(stderr, "sublimation: %s needs a count -- e.g. '%s 10'\n", cmd, cmd); return 2; }
        long n = strtol(pos, NULL, 10);
        if (n <= 0) { fputs("sublimation: count must be a positive integer\n", stderr); return 2; }
        char *line = NULL; size_t lcap = 0; ssize_t len;
        if (!strcmp(cmd, "head")) {
            long shown = 0;
            while (shown < n && (len = getline(&line, &lcap, stdin)) != -1) {
                montauk_sink_append(&g_out, line, (size_t)len);
                shown++;
                if (g_out.len >= (1u << 16)) montauk_sink_drain(&g_out);
            }
        } else {
            typedef struct { char *data; size_t len; } RingLine;
            RingLine *ring = (RingLine *)calloc((size_t)n, sizeof(RingLine));
            size_t count = 0, next = 0;  // next = slot to write, wraps once full (oldest overwritten)
            while ((len = getline(&line, &lcap, stdin)) != -1) {
                free(ring[next].data);
                ring[next].data = (char *)malloc((size_t)len);
                memcpy(ring[next].data, line, (size_t)len);
                ring[next].len = (size_t)len;
                next = (next + 1) % (size_t)n;
                if (count < (size_t)n) count++;
            }
            size_t start = (count < (size_t)n) ? 0 : next;
            for (size_t i = 0; i < count; i++) {
                size_t idx = (start + i) % (size_t)n;
                montauk_sink_append(&g_out, ring[idx].data, ring[idx].len);
                free(ring[idx].data);
            }
            free(ring);
        }
        free(line);
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
        size_t *maxw = NULL; size_t maxw_cap = 0;
        while ((len = getline(&line, &lcap, stdin)) != -1) {
            size_t l = (len > 0 && line[len - 1] == '\n') ? (size_t)len - 1 : (size_t)len;
            char *s = (char *)malloc(l + 1); memcpy(s, line, l); s[l] = '\0';
            if (ln == lcapn) { lcapn = lcapn ? lcapn * 2 : 256; lines = (char **)realloc(lines, lcapn * sizeof(char *)); }
            lines[ln++] = s;
            // Scratch copy for strtok_r (it writes NULs into the buffer); s
            // itself is kept intact for the render pass below.
            char *tmp = (char *)malloc(l + 1); memcpy(tmp, s, l); tmp[l] = '\0';
            char *save = NULL; size_t c = 0;
            for (char *tok = strtok_r(tmp, delim, &save); tok; tok = strtok_r(NULL, delim, &save)) {
                size_t w = strlen(tok);
                if (c >= maxw_cap) {
                    size_t new_cap = maxw_cap ? maxw_cap * 2 : 64;
                    while (new_cap <= c) new_cap *= 2;
                    maxw = (size_t *)realloc(maxw, new_cap * sizeof(size_t));
                    for (size_t k = maxw_cap; k < new_cap; k++) maxw[k] = 0;
                    maxw_cap = new_cap;
                }
                if (w > maxw[c]) maxw[c] = w;
                c++;
            }
            free(tmp);
        }
        free(line);
        for (size_t i = 0; i < ln; i++) {
            size_t tl = strlen(lines[i]);
            char *tmp = (char *)malloc(tl + 1); memcpy(tmp, lines[i], tl); tmp[tl] = '\0';
            char *save = NULL; char **toks = NULL; size_t toks_cap = 0, nt = 0;
            for (char *tok = strtok_r(tmp, delim, &save); tok; tok = strtok_r(NULL, delim, &save)) {
                if (nt == toks_cap) { toks_cap = toks_cap ? toks_cap * 2 : 64; toks = (char **)realloc(toks, toks_cap * sizeof(char *)); }
                toks[nt++] = tok;
            }
            for (size_t c = 0; c < nt; c++) {
                montauk_sink_append(&g_out, toks[c], strlen(toks[c]));
                if (c + 1 < nt) {  // pad to the column width + 2; last column flush-left
                    size_t pad = maxw[c] - strlen(toks[c]) + 2;
                    for (size_t k = 0; k < pad; k++) montauk_sink_appendc(&g_out, ' ');
                }
            }
            montauk_sink_appendc(&g_out, '\n');
            free(toks);
            free(tmp);
            free(lines[i]);
        }
        free(lines);
        free(maxw);
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
        // Real join -tCHAR uses CHAR for both input parsing and output joining;
        // with no -t, parsing is any blank run but output is always a plain
        // space. Mirrored here: sep is delim's first char only when --delim was
        // explicitly given, else a space regardless of the default " \t".
        char sep = delim_set ? delim[0] : ' ';
        StrMap fm; smap_init(&fm);
        FILE *ff = fopen(files[0], "r");
        if (!ff) { fprintf(stderr, "sublimation: cannot open '%s'\n", files[0]); smap_free(&fm); return 1; }
        char *fl = NULL; size_t flc = 0; ssize_t fll;
        while ((fll = getline(&fl, &flc, ff)) != -1) {
            size_t l = (fll > 0 && fl[fll - 1] == '\n') ? (size_t)fll - 1 : (size_t)fll;
            fl[l] = '\0';
            size_t klen; const char *ks = field_span(fl, l, jf, delim, &klen);
            if (ks) {
                char *kc = strndup(ks, klen);
                char *rest = fields_excluding(fl, l, jf, delim, sep);
                if (kc) smap_put(&fm, kc, rest);
                free(kc); free(rest);
            }
        }
        free(fl); fclose(ff);
        char *line = NULL; size_t lcap = 0; ssize_t len;
        while ((len = getline(&line, &lcap, stdin)) != -1) {
            size_t l = (len > 0 && line[len - 1] == '\n') ? (size_t)len - 1 : (size_t)len;
            line[l] = '\0';
            size_t klen; const char *ks = field_span(line, l, jf, delim, &klen);
            char *kc = ks ? strndup(ks, klen) : NULL;
            const char *match = kc ? smap_get(&fm, kc) : NULL;
            // Join key printed once, then each side's remaining fields (key
            // field excluded) -- real join dedupes the key; the prior
            // implementation printed the whole matched line, key included a
            // second time (confirmed via byte-diff against real join, and
            // tracked in ROADMAP.md as the reason join wasn't hook/bashrc-
            // routable this session; this is that fix).
            if (match) {
                char *rest = fields_excluding(line, l, jf, delim, sep);
                montauk_sink_append(&g_out, kc, klen);
                if (rest[0]) { montauk_sink_appendc(&g_out, sep); montauk_sink_append(&g_out, rest, strlen(rest)); }
                if (match[0]) { montauk_sink_appendc(&g_out, sep); montauk_sink_append(&g_out, match, strlen(match)); }
                montauk_sink_appendc(&g_out, '\n');
                free(rest);
            }
            free(kc);
            if (g_out.len >= (1u << 16)) montauk_sink_drain(&g_out);
        }
        free(line); smap_free(&fm);
        return 0;
    }

    // replace: regex substitution on a pipe (sed s/pat/repl/g, global per line) on the
    // Glushkov bit-parallel field -- linear time, no catastrophic backtracking. REPLACEMENT
    // is literal here; capture-group backreferences (\1) are the deferred extension.
    if (!strcmp(cmd, "replace")) {
        if (!pos || nfiles < 1) { fputs("sublimation: replace needs PATTERN REPLACEMENT -- e.g. 'replace foo bar'\n", stderr); return 2; }
        const char *repl = files[0]; size_t rlen = strlen(repl);
        sublimation_search srch;
        sublimation_search_compile(&srch, pos, strlen(pos), icase ? SUBLIMATION_SEARCH_ICASE : 0u, 0);
        if (!sublimation_search_valid(&srch)) { fprintf(stderr, "sublimation: bad regex '%s'\n", pos); return 2; }
        char *line = NULL; size_t lcap = 0; ssize_t len;
        while ((len = getline(&line, &lcap, stdin)) != -1) {
            size_t l = (len > 0 && line[len - 1] == '\n') ? (size_t)len - 1 : (size_t)len;
            size_t off = 0;
            while (off <= l) {
                long end = 0;
                // Continuation-safe: ^ fires once at the true line start, $ once at
                // the true end, however many replacements precede them.
                long s = sublimation_search_find_from(&srch, line, l, off, &end);
                if (s < 0) break;
                size_t ms = (size_t)s, me = (size_t)end;
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
        KeyedBuf kb = {0};
        char *line = NULL; size_t lcap = 0; ssize_t len;
        size_t skipped = 0;
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
            keyed_push(&kb, x, strdup(line));
        }
        free(line);
        if (kb.n > UINT32_MAX) {
            fprintf(stderr, "sublimation: sort --keyed caps at 2^32 lines (got %zu)\n", kb.n);
            return 1;
        }
        uint32_t *order = NULL;
        if (kb.n > 0) {
            order = (uint32_t *)malloc(kb.n * sizeof(uint32_t));
            if (!order) { fputs("sublimation: out of memory\n", stderr); return 1; }
            for (size_t i = 0; i < kb.n; i++) order[i] = (uint32_t)i;
            sublimation_pack_sort_f64(kb.keys, order, kb.n, desc != 0);
        }
        for (size_t i = 0; i < kb.n; i++) {
            char *row = kb.lines[order[i]];
            montauk_sink_append(&g_out, row, strlen(row));
            montauk_sink_appendc(&g_out, '\n');
            free(row);
            if (g_out.len >= (1u << 16)) montauk_sink_drain(&g_out);
        }
        free(order); free(kb.keys); free(kb.lines);
        if (kb.n == 0 && skipped > 0) {
            fprintf(stderr, "sublimation: sort --keyed: no numeric key found (skipped %zu line(s))\n", skipped);
            return 1;
        }
        return 0;
    }

    // count: line/word/byte count -- wc -l (default), wc -w (--words), wc -c
    // (--bytes). A real single-pass read of its own text, not derived from
    // the numeric parse below (which discards line content once parsed),
    // so it works on all-text input and --words/--bytes see real bytes.
    if (!strcmp(cmd, "count")) {
        char *line = NULL; size_t lcap = 0; ssize_t len;
        size_t lines = 0, words = 0, bytes = 0;
        while ((len = getline(&line, &lcap, stdin)) != -1) {
            lines++;
            bytes += (size_t)len;
            int in_word = 0;
            for (ssize_t i = 0; i < len; i++) {
                if (isspace((unsigned char)line[i])) { in_word = 0; }
                else { if (!in_word) words++; in_word = 1; }
            }
        }
        free(line);
        size_t result = count_bytes ? bytes : (count_words ? words : lines);
        montauk_sink_appendf(&g_out, "%zu\n", result);
        return 0;
    }

    Vec data = {0};
    size_t skipped = read_values(&data, field, delim);

    if (data.n == 0) {
        fputs("sublimation: no numeric values on stdin\n", stderr);
        return 1;
    }
    // A statistic over a silently reduced stream is the worst kind of wrong
    // answer: a confident number over an unstated subset. Warn on stderr
    // (stdout byte-parity with the real tools is untouched), the same
    // precedent sort --keyed already sets for its skipped lines.
    if (skipped > 0)
        fprintf(stderr,
                "sublimation: %s: skipped %zu non-numeric line(s); result "
                "covers %zu value(s)\n",
                cmd, skipped, data.n);

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
            {"hook", "lis", "inv", "distinct", "hvg", "bandt-pompe", "rqa", "spectral"};
        // Verdict names the k-of-N agreement class; confidence carries the
        // meet veto, so a periodic input can read verdict=mixed with
        // confidence 0.000 -- both true, two different statements.
        static const char *verdict[] = {"structured", "mixed", "consistent", "max-entropy"};
        montauk_sink_appendf(&g_out, "confidence=%.3f  verdict=%s  (k=%u/%u bases at max entropy)\n",
               (double)r.confidence, verdict[r.verdict], r.agree_count, r.lens_count);
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
