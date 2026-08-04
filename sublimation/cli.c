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
// CLASS is one of: sorted reversed nearly-sorted few-unique random phased
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
#include "sublimation_stats.h"
#include "sublimation_text.h"

#include "util/sink.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdatomic.h>

// Data output (stdout) drains through one buffered sink instead of a syscall
// per printf; stderr diagnostics stay on stderr unchanged.
static montauk_sink g_out;
static void drain_out(void) { montauk_sink_drain(&g_out); }

// Checked allocation for the line-buffering verbs. A NULL from the allocator is
// an out-of-memory the CLI cannot proceed past, so report it and exit rather
// than dereference NULL. cli.c is the top-level program, so exiting here is
// correct; the library itself never exits.
static void oom(void) { fputs("sublimation: out of memory\n", stderr); exit(2); }
static void *xmalloc(size_t n) { void *p = malloc(n); if (!p && n) oom(); return p; }
static void *xcalloc(size_t nm, size_t sz) { void *p = calloc(nm, sz); if (!p && nm && sz) oom(); return p; }
static void *xrealloc(void *q, size_t n) { void *p = realloc(q, n); if (!p && n) oom(); return p; }

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
        "  head N [FILE]         first N lines (head -N)\n"
        "  tail N [FILE]         last N lines (tail -N)\n"
        "  distinct              count of distinct tokens (sort | uniq | wc -l)\n"
        "  tally                 per-token frequency, high to low (sort | uniq -c | sort -rn)\n"
        "  classify              disorder class + profile of the stream\n"
        "  locate CLASS [--values]  windows whose disorder class == CLASS (--values: select-by-structure, emit the data in them)\n"
        "  rand                  max-entropy randomness confidence\n"
        "  characterize          structural verdict: class, rand confidence, sort efficiency\n"
        "  search PATTERN [FILE..] matching lines; one engine, three faces (literal -F,\n"
        "                        regex default, fuzzy -k N); stdin or FILE(s)\n"
        "                        search: -A N/-B N/-C N trailing/leading/both context lines\n"
        "                        search: --dispersion reports the SHAPE of where the\n"
        "                        pattern falls instead of the lines -- density, stride\n"
        "                        spread, Goh-Barabasi burstiness, gap disorder class,\n"
        "                        spectral saliency, matrix-profile discord/motif -- over\n"
        "                        the match POSITIONS, never re-reading the haystack\n"
        "                        search: a bare PATTERN with embedded newlines is one\n"
        "                        pattern PER LINE, OR'd (any face) -- like grep, no -e needed\n"
        "  replace PAT REPL      regex substitution, global per line (sed s/pat/repl/g; REPL literal)\n"
        "  field N[,M..] [FILE..] the N-th column, or a comma-list, of each line (awk '{print $N}')\n"
        "  where 'N OP V' [FILE] lines where field N OP V (awk '$N OP V'; OP: < <= > >= == !=)\n"
        "  group KEY OP [VAL]    group by field KEY, aggregate field VAL (datamash -g; OP:\n"
        "                        sum|mean|count|min|max|sstdev|pstdev|first|last|\n"
        "                        median|mode|antimode|unique|collapse|countunique)\n"
        "  uniq [-d|-u] [-i] [FILE] collapse adjacent duplicate lines (-d dups only, -u uniques only, -i case-insensitive)\n"
        "  cut LO-HI [FILE]      character columns, 1-based inclusive (cut -c): N, lo-hi, lo-, -hi\n"
        "  column [FILE]         align delimited input into columns (column -t)\n"
        "  tac [FILE]            reverse line order\n"
        "  paste [FILE..]        one line per input, tab-joined side by side (zip-style);\n"
        "                        ragged files pad with an empty field once exhausted\n"
        "  paste -s [FILE]       serialize one file's lines into one tab-joined line\n"
        "  tr SET1 SET2          translate SET1's characters to SET2's, positionally\n"
        "                        (SET2 shorter: its last char repeats); X-Y ranges, \\n\\t\\r\\\\ escapes\n"
        "  tr -d SET1            delete SET1's characters instead of translating\n"
        "  comm FILE             sorted 3-column compare vs stdin (both pre-sorted): col 1\n"
        "                        stdin-only, col 2 (1 tab) FILE-only, col 3 (2 tabs) common\n"
        "  intersect FILE        lines in both stdin and FILE (set intersection)\n"
        "  subtract FILE         lines in stdin but not in FILE (set difference)\n"
        "  union FILE            distinct lines from stdin and FILE (set union)\n"
        "  join FIELD FILE       join stdin and FILE on field FIELD (relational join)\n"
        "  version               print the library version and ABI (also --version)\n"
        "\n"
        "  CLASS: sorted reversed nearly-sorted few-unique random phased\n"
        "\n"
        "options:\n"
        "  --field N             pull the N-th (1-based) delimited column per line;\n"
        "                        negative counts from the end (-1 = last column)\n"
        "  --delim D (-d D)      column delimiter chars (default: whitespace);\n"
        "                        -d is the alias everywhere except uniq (which owns -d)\n"
        "  --desc                sort descending\n"
        "  --human               sort --keyed: scale K/M/G/T/P suffixed keys\n"
        "                        (1024-based) so `du -sh | sort --keyed --human`\n"
        "                        orders by real size -- coreutils' `sort -h`\n"
        "  --keyed               sort: keep the whole line, order by --field N (or\n"
        "                        the whole line) as the key -- a row-preserving\n"
        "                        keyed sort, not just the extracted value; --field N,M,...\n"
        "                        adds NUMERIC secondary keys, tie-breaking down the list\n"
        "                        (one shared --desc direction; a non-numeric secondary\n"
        "                        field is a defined 0, not a skip)\n"
        "  --window W            window size for locate (default 512)\n"
        "  --stride S            window stride for locate (default = window)\n"
        "  -v / -c / -n          search: invert match / count only (per file) / line number\n"
        "  -i / -o               search: case-insensitive (-i) / print only the match (-o)\n"
        "  -q / -m N             search: quiet (exit status only) / stop after N matches per file\n"
        "  -F / -E               search: fixed string (literal) / extended regex (the default)\n"
        "                        regex is a bitset engine capped at 64 positions (one per\n"
        "                        literal/class/metachar); an alternation past the cap is split\n"
        "                        on its top-level | automatically, exactly as repeated -e would,\n"
        "                        so only a single over-long branch is a 'bad pattern' -- use -F\n"
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
        "  -i                    case-insensitive. Folds ASCII, plus the non-ASCII\n"
        "                        characters whose upper/lower forms keep the same UTF-8\n"
        "                        byte length AND lead byte (1791 pairs: Latin-1 98%,\n"
        "                        Latin Extended-A 96%, Greek 56%, Cyrillic 33%). A block\n"
        "                        stops folding where it crosses a UTF-8 second-byte\n"
        "                        boundary, so 'moskva' in Cyrillic matches its\n"
        "                        capitalised form but not its ALL-CAPS form. Characters\n"
        "                        that cannot fold match EXACTLY -- the search narrows,\n"
        "                        never widens -- and a one-line stderr notice says so\n"
        "                        rather than letting it pass unremarked\n"
        "  -S                    search: smart case, a ripgrep-ism -- case-insensitive\n"
        "                        unless a pattern contains an uppercase letter\n"
        "  --label NAME          search: NAME stands in for '(standard input)'\n"
        "  --line-buffered       search: flush per output line (automatic at a TTY)\n"
        "  --color WHEN          search: highlight matches, filenames, line numbers\n"
        "                        (auto|always|never; bare --color = auto; also --color=WHEN)\n"
        "  --tally               search: count each extracted match instead of\n"
        "                        printing it, highest first (implies -o) -- the\n"
        "                        `search -o ... | tally` pipeline in one verb\n"
        "  --files-from LIST     search: read input paths from LIST, newline- or NUL-\n"
        "                        delimited, '-' = stdin (find ... | search --files-from -)\n"
        "  --words / --bytes     count: word count / byte count instead of line count (wc -w/-c)\n"
        "  short flags bundle    -iE == -i -E, -vn == -v -n, ... (verb-scoped:\n"
        "                        search owns grep's letters; uniq keeps -d/-u/-i,\n"
        "                        paste -s, replace -i; any other verb+flag pair\n"
        "                        is an error, never silently ignored)\n"
        "  --nearest             quantile: nearest-rank order statistic (not the estimator)\n"
        "\n"
        "exit: 0 when output or a match was produced; 1 when nothing matched or\n"
        "      nothing was produced (search, field, where); 2 on a usage, pattern\n"
        "      or IO error, including an unreadable FILE (grep's contract: -q with\n"
        "      a match still returns 0; -s silences the message, never the status).\n",
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
// `du -h`/`sort -h` style magnitude suffix trailing a numeric key: K M G T P E,
// 1024-based, tolerating the 'i'/'B' spellings (4.0K, 16MiB, 1.2G). Returns the
// multiplier for whatever follows the number, 1.0 when there is no suffix.
static double human_scale(const char *s) {
    // The suffix must abut the number, exactly as du -h emits it ("4.0K\tpath").
    // Skipping whitespace first would read the next column's first letter as a
    // magnitude -- "512\ttiny" became 512 TiB.
    switch (*s) {
        case 'k': case 'K': return 1024.0;
        case 'm': case 'M': return 1024.0 * 1024.0;
        case 'g': case 'G': return 1024.0 * 1024.0 * 1024.0;
        case 't': case 'T': return 1024.0 * 1024.0 * 1024.0 * 1024.0;
        case 'p': case 'P': return 1024.0 * 1024.0 * 1024.0 * 1024.0 * 1024.0;
        case 'e': case 'E': return 1024.0 * 1024.0 * 1024.0 * 1024.0 * 1024.0 * 1024.0;
        default: return 1.0;
    }
}

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

// sort --keyed multi-key: stably refine a row-index permutation `order[]` (n
// entries) by one more field, from least to most significant. Built entirely
// from the existing single-key stable sort (sublimation_pack_sort_f64) -- no
// new sort algorithm. Technique: gather each row's key in the CURRENT order,
// sort with an identity payload (0..n-1, so ties fall back to the current
// position, i.e. the order established by earlier, less-significant passes),
// then scatter the row indices back through the resulting permutation. Applied
// once per key, primary key last, composes into a full lexicographic sort.
// Best-effort: leaves `order` unchanged on allocation failure.
static void refine_order_by_key(uint32_t *order, const double *key_by_row, size_t n, int desc) {
    double *gathered = (double *)malloc(n * sizeof(double));
    uint32_t *idx = (uint32_t *)malloc(n * sizeof(uint32_t));
    if (!gathered || !idx) { free(gathered); free(idx); return; }
    for (size_t j = 0; j < n; j++) { gathered[j] = key_by_row[order[j]]; idx[j] = (uint32_t)j; }
    sublimation_pack_sort_f64(gathered, idx, n, desc != 0);
    uint32_t *scattered = (uint32_t *)malloc(n * sizeof(uint32_t));
    if (scattered) {
        for (size_t j = 0; j < n; j++) scattered[j] = order[idx[j]];
        memcpy(order, scattered, n * sizeof(uint32_t));
        free(scattered);
    }
    free(gathered); free(idx);
}

// Open-addressing string hash map, for the two-stream set ops, join, group
// and tally (vals NULL entries = plain set; nums carries group ids / counts).
// FNV-1a; grows at 50% load. This is the ONE probe/grow implementation --
// group and tally used to carry their own verbatim copies of the same hash.
typedef struct { char **keys; char **vals; size_t *nums; size_t cap, used; } StrMap;
static uint64_t str_fnv(const char *s) {
    uint64_t h = 1469598103934665603ULL;
    for (; *s; s++) { h ^= (unsigned char)*s; h *= 1099511628211ULL; }
    return h;
}
static void smap_init(StrMap *m) {
    m->cap = 1024; m->used = 0;
    m->keys = (char **)calloc(m->cap, sizeof(char *));
    m->vals = (char **)calloc(m->cap, sizeof(char *));
    m->nums = (size_t *)calloc(m->cap, sizeof(size_t));
    if (!m->keys || !m->vals || !m->nums) { fputs("sublimation: out of memory\n", stderr); exit(1); }
}
static size_t smap_slot(StrMap *m, const char *k) {
    size_t i = str_fnv(k) & (m->cap - 1);
    while (m->keys[i] && strcmp(m->keys[i], k)) i = (i + 1) & (m->cap - 1);
    return i;
}
static int smap_has(StrMap *m, const char *k) { return m->keys[smap_slot(m, k)] != NULL; }
static const char *smap_get(StrMap *m, const char *k) { size_t i = smap_slot(m, k); return m->keys[i] ? m->vals[i] : NULL; }
static void smap_grow(StrMap *m) {
    size_t nc = m->cap * 2;
    char  **nk = (char **)calloc(nc, sizeof(char *));
    char  **nv = (char **)calloc(nc, sizeof(char *));
    size_t *nn = (size_t *)calloc(nc, sizeof(size_t));
    if (!nk || !nv || !nn) { fputs("sublimation: out of memory\n", stderr); exit(1); }
    for (size_t j = 0; j < m->cap; j++) if (m->keys[j]) {
        size_t p = str_fnv(m->keys[j]) & (nc - 1);
        while (nk[p]) p = (p + 1) & (nc - 1);
        nk[p] = m->keys[j]; nv[p] = m->vals[j]; nn[p] = m->nums[j];
    }
    free(m->keys); free(m->vals); free(m->nums);
    m->keys = nk; m->vals = nv; m->nums = nn; m->cap = nc;
}
static void smap_put(StrMap *m, const char *k, const char *v) {
    if ((m->used + 1) * 2 >= m->cap) smap_grow(m);
    size_t i = smap_slot(m, k);
    if (m->keys[i]) return;  // first value per key wins
    m->keys[i] = strdup(k); m->vals[i] = v ? strdup(v) : NULL; m->used++;
}
// Find-or-insert for the nums-payload users (group's key -> group id, tally's
// key -> count): returns k's slot, strdup-inserting on first sight (nums[slot]
// zeroed, *created = 1 when non-NULL). The SLOT is valid only until the next
// insertion (grow relocates entries); the key STRING is stable for the map's
// lifetime, so callers may share m->keys[slot] pointers long-term.
static size_t smap_intern(StrMap *m, const char *k, int *created) {
    if ((m->used + 1) * 2 >= m->cap) smap_grow(m);
    size_t i = smap_slot(m, k);
    if (m->keys[i]) { if (created) *created = 0; return i; }
    m->keys[i] = strdup(k); m->nums[i] = 0; m->used++;
    if (created) *created = 1;
    return i;
}
static void smap_free(StrMap *m) {
    for (size_t i = 0; i < m->cap; i++) { free(m->keys[i]); free(m->vals[i]); }
    free(m->keys); free(m->vals); free(m->nums);
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
// ANSI wrapping ONLY. The span enumeration this used to inline is the
// occurrence field's job and now lives in the library -- the CLI asks where the
// matches are and decorates them, rather than knowing how to walk them. A
// stack buffer covers the overwhelmingly common case; the heap path exists
// because a pathological line (thousands of matches) must still render, not
// because it is expected.
#define COLOR_SPANS_STACK 64
static void emit_colored_line(montauk_sink *out, const sublimation_search *set, int nset,
                              int regex_face, const char *line, size_t mlen,
                              size_t rawlen, int xline, int wword) {
    sublimation_match_span stackbuf[COLOR_SPANS_STACK];
    sublimation_match_span *spans = stackbuf;
    size_t n = sublimation_search_spans(set, nset, regex_face, line, mlen,
                                        wword, xline, stackbuf, COLOR_SPANS_STACK);
    size_t have = n < COLOR_SPANS_STACK ? n : COLOR_SPANS_STACK;
    if (n > COLOR_SPANS_STACK) {
        sublimation_match_span *heap =
            (sublimation_match_span *)malloc(n * sizeof(*heap));
        if (heap) {
            // Re-enumerate rather than resume: the walk is deterministic over an
            // immutable program, so the second call yields the same spans.
            (void)sublimation_search_spans(set, nset, regex_face, line, mlen,
                                           wword, xline, heap, n);
            spans = heap;
            have = n;
        }
        // On allocation failure `have` stays at the stack cap: the line renders
        // with the first 64 matches highlighted and the rest plain, which is a
        // degraded render rather than a dropped line.
    }
    size_t cur = 0;
    for (size_t i = 0; i < have; i++) {
        montauk_sink_append(out, line + cur, spans[i].start - cur);
        montauk_sink_append(out, "\x1b[01;31m", 8);
        montauk_sink_append(out, line + spans[i].start, spans[i].end - spans[i].start);
        montauk_sink_append(out, "\x1b[0m", 4);
        cur = spans[i].end;
    }
    montauk_sink_append(out, line + cur, rawlen - cur);
    if (spans != stackbuf) free(spans);
}

// Parallel multi-file search: file fan-out on the shared work-stealing deque.
// Engaged only for the naturally per-file-independent output modes -- plain
// match printing, -c, -l/-L -- gated OFF whenever -q, --tally or -A/-B/-C
// context are in play, since those carry state across files that a private
// per-file sink cannot capture.
//
// The gate is total BYTES, not file count: measured on this box (a worker
// pool spawn+join costs roughly a millisecond, one-time, regardless of file
// count), file count alone is a poor predictor -- a corpus of many tiny files
// (~4KB each) does not pay for that cost until ~500KB-1MB of total input,
// while a handful of large files (~1MB each) pays for it by ~2MB. The
// threshold below is set past BOTH observed crossovers, so it is a safe,
// conservative floor rather than a razor's-edge value tuned to one corpus
// shape; sharpening it into a real two-factor (per-file + per-byte) cost
// model is standing optimization-track work, not a blocker here. A lone file
// (nsf == 1) never engages regardless of size -- fan-out needs more than one
// frame to fan out; single-large-file line-chunking is a separate, deferred
// item.
//
// The compiled search program is immutable during a scan (every scratch
// allocation -- the regex reach memo, the fuzzy dedup set -- is malloc'd and
// freed inside the call), so one const sublimation_search array is shared
// read-only across workers with no lock: unlike ripgrep, nothing here needs
// per-thread cloning.
#define SEARCH_PAR_MIN_BYTES (2 * 1024 * 1024)

// Cheap stat() pass (no opens, no reads) to size the corpus before deciding.
static long long search_total_bytes(char **files, int n) {
    long long total = 0;
    struct stat st;
    for (int i = 0; i < n; i++)
        if (stat(files[i], &st) == 0 && S_ISREG(st.st_mode)) total += (long long)st.st_size;
    return total;
}

// THE FAN-OUT UNIT IS A CHUNK, not a file. A whole file is one chunk with the
// range left open, so the multi-file path is the same code with nothing to
// offset -- that is what keeps its output identical by construction rather than
// by testing.
//
// line_no in the records is RELATIVE to the chunk's first line, because a chunk
// cannot know how many lines precede it without reading them. `lines` is what
// makes the absolute number recoverable: the merge walks chunks in order and
// accumulates it into line_base, which is the only place absolute numbering
// exists.
typedef struct {
    sublimation_occ_buf buf;   // the library's occurrence records + line arena
    long       fmatches;
    long       lines;        // lines scanned in this chunk (feeds the next base)
    long       line_base;    // absolute number of the line BEFORE this chunk
    int        file;         // index into ParSearchCtx.files
    long long  start, end;   // byte range, line-aligned; end <= 0 => to EOF
    int        had_error;    // fopen failed
    int        binary_hit;   // matched, but content suppressed as binary
    int        overflowed;   // buffer bound hit: render re-scans this chunk
} ParFileResult;

// IN-FLIGHT BOUND. Every worker buffers its whole file's matching lines and
// nothing is rendered until every scan has finished, so peak memory was the
// SUM OF ALL MATCHES ACROSS THE CORPUS -- no ceiling at all. A corpus that
// matches heavily (a pattern hitting most lines of a many-GB tree) could take
// the machine down, and the failure mode is the worst kind: it scales with the
// input, so it works in testing and dies in production.
//
// The bound is a shared byte counter rather than a per-file cap, because
// per-file bounds still sum. On exceeding it a worker STOPS buffering, frees
// what it holds and marks the file for re-scan; the render pass reads that file
// serially and streams it straight out, which is O(1) in memory.
//
// WHY NOT "block the worker until the main thread drains": the main thread is
// inside sublimation_parallel_for waiting for every task, so a blocked worker and
// a waiting main thread deadlock. Re-scan trades a second read of a
// pathological file for a guarantee that cannot deadlock, and the OUTPUT IS
// IDENTICAL either way -- the same lines, in the same order, from the same
// matcher.
// OPERATOR-PARAMETERIZED, not a baked-in threshold: a memory ceiling is exactly
// the kind of knob whose right value is a property of the box, not of the tool.
// SUBLIMATION_SEARCH_MAX_INFLIGHT overrides it (bytes); 0 disables the bound for
// anyone who would rather have the old unbounded behaviour deliberately.
#define SEARCH_PAR_MAX_INFLIGHT_DEFAULT (256u * 1024u * 1024u)
static size_t search_max_inflight(void) {
    const char *e = getenv("SUBLIMATION_SEARCH_MAX_INFLIGHT");
    if (!e || !*e) return SEARCH_PAR_MAX_INFLIGHT_DEFAULT;
    char *end = NULL;
    unsigned long long v = strtoull(e, &end, 10);
    if (end == e || (end && *end)) return SEARCH_PAR_MAX_INFLIGHT_DEFAULT;
    return v ? (size_t)v : (size_t)-1;   // 0 = unbounded, by asking for it
}

typedef struct {
    char                     **files;
    const sublimation_search  *srchs;
    int   npat, regex_face, invert, count_only, number, names_only,
          names_without, word_match, line_match, bin_text, bin_skip,
          prefix, color;
    long  max_count;
    ParFileResult *results;   // one per CHUNK, in output order
    int            nchunks;
    atomic_size_t  inflight;  // bytes buffered across ALL workers, see the bound above
    size_t         max_inflight;
    atomic_int     overflow_announced;  // NO SILENT CAPS: say it once, on stderr
} ParSearchCtx;

// Scans one file into its own record array. Renders nothing: the scan decides
// WHICH lines are selected and where they are, search_render_one_file_par turns
// that into bytes afterwards, in file order, with the same primitives the serial
// loop uses (emit_prefix / emit_name / emit_colored_line).
static void search_scan_one_file_par(const char *fname, ParSearchCtx *pc, ParFileResult *r) {
    r->fmatches = 0;
    r->lines = 0;
    r->had_error = 0;
    r->binary_hit = 0;
    FILE *in = fopen(fname, "r");
    if (!in) { r->had_error = 1; return; }

    int binary = 0;
    // Only the chunk that owns the head sniffs. A mid-file chunk cannot see the
    // file's first bytes and must not guess; the per-line NUL check below still
    // catches binary content wherever it appears.
    if (r->start == 0 && !pc->bin_text && lseek(fileno(in), 0, SEEK_CUR) != -1) {
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
    if (binary && pc->bin_skip) { fclose(in); return; }
    if (r->start > 0 && fseeko(in, (off_t)r->start, SEEK_SET) != 0) {
        fclose(in); r->had_error = 1; return;
    }

    char *line = NULL; size_t cap = 0; ssize_t len;
    long fmatches = 0, lineno = 0;
    long long pos = r->start;
    int fdone = 0;
    while (!fdone && (r->end <= 0 || pos < r->end)
           && (len = getline(&line, &cap, in)) != -1) {
        pos += len;
        lineno++;
        size_t mlen = (size_t)len;
        if (mlen && line[mlen - 1] == '\n') mlen--;
        if (!pc->bin_text && !binary && memchr(line, 0, mlen)) binary = 1;
        if (binary && pc->bin_skip) { fmatches = 0; lineno = 0; r->buf.n = 0; break; }

        int show = sublimation_search_selects(pc->srchs, pc->npat, pc->regex_face, line, mlen,
                                  pc->line_match, pc->word_match);
        if (pc->invert) show = !show;
        if (show) {
            fmatches++;
            if (pc->names_only || pc->names_without) { fdone = 1; continue; }
            if (!pc->count_only) {
                if (binary) { r->binary_hit = 1; fdone = 1; }
                else if (r->overflowed) {
                    // Already handed to the serial renderer: count, never buffer.
                    // Without this an easing budget would refill a buffer the
                    // render is going to ignore.
                }
                else {
                    size_t prev = atomic_fetch_add(&pc->inflight, (size_t)len);
                    if (prev + (size_t)len > pc->max_inflight) {
                        // Give back what this chunk holds and hand it to the
                        // serial renderer. Counting the bytes back matters:
                        // otherwise one overflowing chunk poisons the budget for
                        // every chunk still scanning.
                        atomic_fetch_sub(&pc->inflight,
                                         r->buf.raw_n + (size_t)len);
                        sublimation_occ_buf_free(&r->buf);
                        sublimation_occ_buf_init(&r->buf);
                        r->overflowed = 1;
                        // A bound that engages invisibly reads as "nothing
                        // happened" when the real story is "this run re-read a
                        // file". Output is unaffected; the cost is not, so say
                        // so -- once, on stderr, never on the data path.
                        if (!atomic_exchange(&pc->overflow_announced, 1))
                            fprintf(stderr,
                                    "sublimation: in-flight buffer bound (%zu bytes) "
                                    "reached; re-reading heavily-matching files "
                                    "instead of buffering them "
                                    "(SUBLIMATION_SEARCH_MAX_INFLIGHT overrides; 0 disables)\n",
                                    pc->max_inflight);
                        // Keep COUNTING to the end: fmatches and lines are still
                        // owed to the merge, and a chunk that stopped early
                        // would corrupt every later chunk's line numbers.
                    }
                    else sublimation_occ_buf_push(&r->buf, (uint32_t)lineno, line,
                                                  mlen, (size_t)len);
                }
            }
            if (pc->max_count && fmatches >= pc->max_count) fdone = 1;
        }
    }
    free(line);
    fclose(in);
    r->fmatches = fmatches;
    r->lines = lineno;
}

// The rendering half: one pass over one file's records, in file order, on the
// main thread. Byte-identical to the serial loop's output for the modes the
// fan-out covers -- the same emit_* primitives, the same order, just driven by
// positions the scan recorded instead of by the scan itself. The binary-file
// notice is emitted here rather than in the worker so its stderr ordering is
// deterministic instead of racing between threads.
static void search_render_one_file_par(const char *fname, const ParSearchCtx *pc,
                                       const ParFileResult *r, montauk_sink *out) {
    // names_only / names_without / count_only / the binary notice are per-FILE
    // answers, and a file may now be several chunks. The merge aggregates them
    // and emits once; this function only ever renders LINES.
    if (pc->names_only || pc->names_without || pc->count_only) return;
    if (r->binary_hit) return;
    // OVERFLOWED: the scan gave this file's buffer back to stay under the
    // in-flight bound, so read it again here and stream it. Same matcher, same
    // emit primitives, same order -- the bound changes when bytes are read, not
    // what is printed.
    if (r->overflowed) {
        FILE *in = fopen(fname, "r");
        if (!in) return;
        if (r->start > 0 && fseeko(in, (off_t)r->start, SEEK_SET) != 0) { fclose(in); return; }
        char *line = NULL; size_t cap = 0; ssize_t len;
        long lineno = 0, fmatches = 0;
        long long pos = r->start;
        while ((r->end <= 0 || pos < r->end) && (len = getline(&line, &cap, in)) != -1) {
            pos += len;
            lineno++;
            size_t mlen = (size_t)len;
            if (mlen && line[mlen - 1] == '\n') mlen--;
            int show = sublimation_search_selects(pc->srchs, pc->npat, pc->regex_face,
                                                  line, mlen, pc->line_match,
                                                  pc->word_match);
            if (pc->invert) show = !show;
            if (!show) continue;
            fmatches++;
            emit_prefix(out, pc->prefix ? fname : NULL, r->line_base + lineno,
                        pc->number, ':', pc->color);
            if (pc->color)
                emit_colored_line(out, pc->srchs, pc->npat, pc->regex_face,
                                  line, mlen, (size_t)len, pc->line_match, pc->word_match);
            else
                montauk_sink_append(out, line, (size_t)len);
            if (pc->max_count && fmatches >= pc->max_count) break;
            if (out->len >= (1u << 16)) montauk_sink_drain(out);
        }
        free(line);
        fclose(in);
        return;
    }
    for (size_t i = 0; i < r->buf.n; i++) {
        const sublimation_search_occ *o = &r->buf.occ[i];
        const char *line = r->buf.raw + o->off;
        emit_prefix(out, pc->prefix ? fname : NULL,
                    r->line_base + (long)o->line_no, pc->number, ':', pc->color);
        if (pc->color)
            emit_colored_line(out, pc->srchs, pc->npat, pc->regex_face,
                              line, o->len, o->raw_len, pc->line_match, pc->word_match);
        else
            montauk_sink_append(out, line, o->raw_len);
    }
}

// One chunk, by index. The deque plumbing that used to live here -- frames,
// depths, a hand-written distributor -- moved into the library behind
// sublimation_parallel_for, which is what let cli.c stop including
// sublimation's internal headers.
static void search_par_chunk(size_t idx, void *user) {
    ParSearchCtx *pc = (ParSearchCtx *)user;
    search_scan_one_file_par(pc->files[pc->results[idx].file], pc, &pc->results[idx]);
}

// LINE-ALIGNED SPLIT of one file into at most `want` chunks. A lone file never
// engaged the fan-out no matter its size, so `search PATTERN one-huge.log` was
// fully serial while a directory of small files was not -- the opposite of what
// the sizes suggest.
//
// Boundaries are snapped FORWARD to just past the next newline, so every chunk
// holds whole lines and no line is scanned twice or missed. A boundary that
// runs to EOF collapses the chunk, which is why the count is a maximum and not
// a promise. Returns the number of chunks written.
//
// No engine change is needed for this and that is the point: gnfa_range is
// range-scoped, per-call scratch is local, and the compiled program is
// immutable, so a chunk is just another independent scan.
static int search_split_file(const char *fname, long long size, int want,
                             ParFileResult *out, int file_idx) {
    FILE *fp = fopen(fname, "r");
    if (!fp) return 0;
    long long prev = 0;
    int n = 0;
    for (int i = 1; i < want && prev < size; i++) {
        long long target = (long long)((double)size * i / want);
        if (target <= prev) continue;
        if (fseeko(fp, (off_t)target, SEEK_SET) != 0) break;
        int c;
        long long b = target;
        while ((c = fgetc(fp)) != EOF) { b++; if (c == '\n') break; }
        if (c == EOF || b >= size) break;      // no boundary left: one chunk covers the tail
        out[n].file = file_idx; out[n].start = prev; out[n].end = b;
        prev = b; n++;
    }
    out[n].file = file_idx; out[n].start = prev; out[n].end = 0;   // 0 => to EOF
    n++;
    fclose(fp);
    return n;
}

// tr's SET syntax: literal bytes, X-Y ranges and backslash escapes (n t r a
// b f v, or the escaped char itself) -- byte-domain only, no POSIX [:class:]
// names, no multi-byte UTF-8 range expansion. Expands into out[] (caller-sized,
// >=256 for a full-range SET); returns the expanded length.
static size_t tr_expand_set(const char *set, unsigned char *out, size_t outcap) {
    size_t n = 0;
    for (const char *p = set; *p && n < outcap; ) {
        unsigned char c;
        if (*p == '\\' && p[1]) {
            switch (p[1]) {
                case 'n': c = '\n'; break;
                case 't': c = '\t'; break;
                case 'r': c = '\r'; break;
                case 'a': c = '\a'; break;
                case 'b': c = '\b'; break;
                case 'f': c = '\f'; break;
                case 'v': c = '\v'; break;
                default:  c = (unsigned char)p[1]; break;   // \\ or any other char: itself, literally
            }
            p += 2;
        } else {
            c = (unsigned char)*p++;
        }
        if (*p == '-' && p[1] && p[1] != '\0') {   // X-Y range; Y taken literally (no escape at the range end)
            unsigned char hi = (unsigned char)p[1];
            p += 2;
            if (hi >= c) { for (unsigned v = c; v <= hi && n < outcap; v++) out[n++] = (unsigned char)v; }
            else out[n++] = c;   // reversed range: just the one char, not a POSIX-strict error
        } else {
            out[n++] = c;
        }
    }
    return n;
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
    // Built with a write pointer, single pass -- strcat-in-loop rescans the
    // whole prefix per token, O(tokens^2) per line. Tokens plus separators
    // never exceed the source length, so len + 1 bounds the output.
    char *out = (char *)malloc(len + 1);
    char *w = out;
    char *save = NULL; int col = 0;
    for (char *tok = strtok_r(copy, delim, &save); tok; tok = strtok_r(NULL, delim, &save)) {
        col++;
        if (col == field) continue;
        if (w != out) *w++ = sep;
        size_t tl = strlen(tok);
        memcpy(w, tok, tl); w += tl;
    }
    *w = '\0';
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

// stdin-or-files input walker shared by field and where (search keeps its own
// richer loop): yields stdin once when no FILE was named, otherwise each named
// file in turn. An unopenable file reports cannot-open and flags had_error,
// which the callers turn into exit 2 -- the IO half of the exit contract.
typedef struct { const char **files; int nfiles, next, had_error; FILE *in; const char *fname; } InputIter;
static int input_next(InputIter *it) {
    if (it->in && it->in != stdin) { fclose(it->in); it->in = NULL; }
    if (it->nfiles == 0) {
        if (it->next++) return 0;
        it->in = stdin; it->fname = NULL;
        return 1;
    }
    while (it->next < it->nfiles) {
        it->fname = it->files[it->next++];
        it->in = fopen(it->fname, "r");
        if (it->in) return 1;
        fprintf(stderr, "sublimation: cannot open '%s'\n", it->fname);
        it->had_error = 1;
    }
    return 0;
}

// Single optional FILE input for the coreutils-shaped text verbs (uniq, tac,
// head, tail, cut, column, paste -- each of whose real counterpart reads a
// named FILE): stdin by default, the one named FILE otherwise. A second
// positional is a usage error and an unopenable FILE an IO error, both exit 2
// per the contract in usage(). exit() is safe here: the atexit sink drain
// covers it and nothing has been emitted yet when inputs are being opened.
static FILE *open_single_input(const char *cmd, const char *path, const char *extra) {
    if (extra) {
        fprintf(stderr, "sublimation: %s takes at most one FILE; '%s' is an "
                "unexpected argument\n", cmd, extra);
        exit(2);
    }
    if (!path) return stdin;
    FILE *f = fopen(path, "r");
    if (!f) { fprintf(stderr, "sublimation: cannot open '%s'\n", path); exit(2); }
    return f;
}

// Read stdin into `out`, parsing one double per line (or per --field column).
// Lines whose field does not parse as a number are skipped (and counted).
static size_t read_values(Vec *out, int field, const char *delim) {
    char *line = NULL;
    size_t cap = 0;
    ssize_t len;
    size_t skipped = 0;
    while ((len = getline(&line, &cap, stdin)) != -1) {
        char numbuf[64];
        const char *src = line;
        if (field > 0) {
            size_t flen;
            const char *f = field_span(line, (size_t)len, field, delim, &flen);
            if (!f) { skipped++; continue; }
            // Bound strtod to the field: a delimiter that is itself a strtod byte
            // ('.', 'e', 'x', sign, digit) would otherwise pull the next field
            // into the number. Copy out, NUL-terminated, and parse that.
            if (flen >= sizeof(numbuf)) flen = sizeof(numbuf) - 1;
            memcpy(numbuf, f, flen);
            numbuf[flen] = '\0';
            src = numbuf;
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
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2 || !strcmp(argv[1], "-h") || !strcmp(argv[1], "--help") ||
        !strcmp(argv[1], "help")) {
        usage(stdout);
        return 0;
    }
    // `VERB --help` reaches the usage text too, so asking a verb how it works
    // never costs an error exit. Only the long form is scanned past argv[1]:
    // search owns -h for its filename-prefix toggle.
    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "--help")) {
            usage(stdout);
            return 0;
        }
    }
    const char *cmd = argv[1];

    // One stdout sink for all data output; atexit covers every return/exit path,
    // streaming loops drain periodically (below) to bound memory.
    montauk_sink_init(&g_out, 1);
    atexit(drain_out);

    // version: sourced ONLY from the header macros -- the one version story.
    // The CLI has no version of its own; it reports the library it fronts.
    if (!strcmp(cmd, "version") || !strcmp(cmd, "--version")) {
        montauk_sink_appendf(&g_out, "sublimation %s (abi %d)\n",
                             SUBLIMATION_VERSION_STRING, SUBLIMATION_API_VERSION);
        return 0;
    }

    // Verb existence is diagnosed BEFORE any stdin read: `sublimation typo`
    // must say "unknown command", not drain the pipe and then complain about
    // its contents (the old order reached the check only after read_values,
    // so `sublimation --version </dev/null` died with "no numeric values").
    static const char *verbs[] = {
        "sort", "quantile", "select", "searchsorted", "sum", "mean", "stdev",
        "variance", "min", "max", "describe", "outliers", "histogram", "count",
        "head", "tail", "distinct", "tally", "classify", "locate", "rand",
        "characterize", "search", "replace", "field", "where", "group", "uniq",
        "cut", "column", "tac", "paste", "intersect", "subtract", "union",
        "join", "tr", "comm",
    };
    int known_cmd = 0;
    for (size_t vi = 0; vi < sizeof verbs / sizeof verbs[0]; vi++)
        if (!strcmp(cmd, verbs[vi])) { known_cmd = 1; break; }
    if (!known_cmd) {
        fprintf(stderr, "sublimation: unknown command '%s'\n\n", cmd);
        usage(stderr);
        return 2;
    }

    int field = 0;
    const char *field_arg = NULL;  // --field's raw text; sort --keyed splits a comma-list from
                                    // this for multi-key (secondary tie-break) sort. Every other
                                    // verb keeps using the already-parsed single int unchanged.
    const char *delim = " \t";
    int delim_set = 0;  // true once --delim is explicitly given (join's output separator cares)
    int desc = 0;
    int tr_delete = 0;  // tr -d: delete SET1's characters instead of translating to SET2
    int keyed = 0;                                // sort --keyed: preserve full lines, order by key
    int human = 0;                                // sort --keyed --human: K/M/G suffixed keys
    size_t window = 512, stride = 0;
    int invert = 0, count_only = 0, number = 0;  // search line-filter flags
    int icase = 0, only_match = 0, fixed = 0;     // search -i (case-fold), -o (matches only), -F (fixed string)
    int tally_mode = 0;                           // search --tally: count spans instead of printing them
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
    // Short flags are verb-scoped (see the bundle switch): search owns grep's
    // letters, uniq/paste/replace keep exactly their documented ones, every
    // other verb+short-flag pair is an error rather than a silent no-op
    // (`field 1 -v -q -F` used to exit 0 having ignored all three).
    int is_search  = !strcmp(cmd, "search");
    int is_uniq    = !strcmp(cmd, "uniq");
    int is_paste   = !strcmp(cmd, "paste");
    int is_replace = !strcmp(cmd, "replace");
    // --dispersion: report the SHAPE of where a pattern falls instead of the
    // lines it fell on. Reads the occurrence field, never the haystack twice.
    int dispersion_mode = 0;
    int is_tr      = !strcmp(cmd, "tr");

    for (int i = 2; i < argc; i++) {
        const char *a = argv[i];
        if (endopts) {  // after `--`, everything is a positional (lets REPL/PATTERN start with '-')
            if (!pos) pos = a;
            else if (nfiles < 256) files[nfiles++] = a;
            else { fprintf(stderr, "sublimation: too many arguments\n"); return 2; }
            continue;
        }
        if (!strcmp(a, "--")) { endopts = 1; continue; }
        if (!strcmp(a, "--field") && i + 1 < argc) { field_arg = argv[i + 1]; field = atoi(argv[++i]); }
        else if (!strcmp(a, "--delim") && i + 1 < argc) { delim = argv[++i]; delim_set = 1; }
        // -d is the --delim alias everywhere except uniq, which owns -d for its
        // dups-only toggle (same byte, different verb, the rule the short-flag
        // families already follow below).
        else if (!is_uniq && !is_tr && !strcmp(a, "-d") && i + 1 < argc) { delim = argv[++i]; delim_set = 1; }
        // A bare negative integer is a positional, not a bundled short flag --
        // this is what lets `field -1` mean the last column.
        else if (!pos && a[0] == '-' && isdigit((unsigned char)a[1])) pos = a;
        else if (!strcmp(a, "--desc")) desc = 1;
        else if (!strcmp(a, "--keyed")) keyed = 1;  // sort: keep the whole line, order by the key
        else if (!strcmp(a, "--human")) human = 1;  // sort --keyed: scale K/M/G/T keys
        else if (!strcmp(a, "--window") && i + 1 < argc) window = strtoull(argv[++i], NULL, 10);
        else if (!strcmp(a, "--stride") && i + 1 < argc) stride = strtoull(argv[++i], NULL, 10);
        else if (!strcmp(a, "--nearest")) nearest = 1;  // quantile: nearest-rank order statistic
        else if (!strcmp(a, "--values")) values = 1;    // locate: emit data, not window ranges
        else if (!strcmp(a, "--words")) count_words = 1;  // count: word count -- wc -w
        else if (!strcmp(a, "--bytes")) count_bytes = 1;  // count: byte count -- wc -c
        else if (is_search && !strcmp(a, "-m") && i + 1 < argc) max_count = strtol(argv[++i], NULL, 10);  // search -m N
        else if (is_search && !strcmp(a, "-k") && i + 1 < argc) kval = strtol(argv[++i], NULL, 10);       // search -k N (fuzzy)
        else if (is_search && !strcmp(a, "-A") && i + 1 < argc) ctx_after = strtol(argv[++i], NULL, 10);   // grep -A N
        else if (is_search && !strcmp(a, "-B") && i + 1 < argc) ctx_before = strtol(argv[++i], NULL, 10);  // grep -B N
        else if (is_search && !strcmp(a, "-C") && i + 1 < argc) ctx_after = ctx_before = strtol(argv[++i], NULL, 10);  // grep -C N
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
        // --tally implies -o: it counts the spans, so it must extract them.
        else if (is_search && !strcmp(a, "--tally")) { tally_mode = 1; only_match = 1; }
        else if (is_search && !strcmp(a, "--dispersion")) dispersion_mode = 1;
        else if (a[0] == '-' && a[1] && a[1] != '-') {
            // Bundled short flags, getopt-style: -iE == -i -E, -vn == -v -n. Each
            // char is one boolean flag. -E (extended regex) is a no-op:
            // sublimation's NFA is already RE2-lineage ERE, so it is accepted for
            // grep compatibility rather than switching dialects.
            // The letter set is verb-scoped BY FAMILY: search owns grep's letters
            // (-s is "silence open errors" there, -d/-u are unknown), uniq keeps
            // -d/-u/-i, paste keeps -s, replace keeps -i, and no other verb owns
            // any short boolean flag. Same byte, different verb, different
            // meaning -- and a flag outside its family is an ERROR, because a
            // silently accepted-and-ignored flag (`field 1 -v -q -F` exiting 0)
            // is the silent-misfire shape the wrappers must never route through.
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
                } else if (is_uniq) {
                    switch (*f) {
                        case 'd': uniq_d = 1; break;       // uniq -d: only duplicated lines
                        case 'u': uniq_u = 1; break;       // uniq -u: only unique lines
                        case 'i': icase = 1; break;        // uniq -i: case-fold the compare
                        default: known = 0; break;
                    }
                } else if (is_paste) {
                    switch (*f) {
                        case 's': serial = 1; break;       // paste -s: serialize lines into one
                        default: known = 0; break;
                    }
                } else if (is_replace) {
                    switch (*f) {
                        case 'i': icase = 1; break;        // replace -i: case-insensitive pattern
                        default: known = 0; break;
                    }
                } else if (is_tr) {
                    switch (*f) {
                        case 'd': tr_delete = 1; break;    // tr -d: delete SET1's characters
                        default: known = 0; break;
                    }
                } else {
                    known = 0;   // no other verb owns any short boolean flag
                }
                if (!known) {
                    fprintf(stderr, "sublimation: unknown option '-%c' for %s\n", *f, cmd);
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
            // Bare PATTERNS (no -e/-f): real grep's own documented rule --
            // "one or more patterns separated by newline characters" -- so
            // `search $'apple\ncherry'` ORs apple and cherry exactly like
            // `-e apple -e cherry`, in EITHER face (-F or regex), with no -e
            // repetition needed. An empty segment matches every line, same as
            // an empty line in a -f pattern file, above.
            const char *start = pos;
            for (const char *p = pos; ; p++) {
                if (*p == '\n' || *p == '\0') {
                    char *seg = strndup(start, (size_t)(p - start));
                    strlist_push(&pats, &npat, &patcap, seg);
                    free(seg);
                    if (*p == '\0') break;
                    start = p + 1;
                }
            }
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
        // An over-long ALTERNATION is the one "bad pattern" that is not a typo:
        // the regex face is a 64-position bitset summed across | branches, so
        // `a|b|c|...` can blow the cap even though every branch fits it easily.
        // grep treats `A|B` and `-e A -e B` as the same pattern set, so when a
        // whole pattern will not compile, expand it into its top-level branches
        // and carry on -- the caller never has to re-type it as repeated -e.
        // Only the regex face has the cap (-F and -k take patterns literally),
        // and only a pattern that ALREADY failed is touched, so nothing that
        // compiles today changes shape.
        if (!fixed && kval == 0) {
            char **np = NULL; int nn = 0, ncap = 0, changed = 0;
            for (int p = 0; p < npat; p++) {
                char **br = NULL; int nbr = 0;
                if (strchr(pats[p], '|')) {
                    sublimation_search probe;
                    sublimation_search_compile(&probe, pats[p], strlen(pats[p]), sflags, 0);
                    if (!sublimation_search_valid(&probe))
                        sublimation_search_split_alternation(pats[p], &br, &nbr);
                }
                if (nbr >= 2) {
                    for (int b = 0; b < nbr; b++) { strlist_push(&np, &nn, &ncap, br[b]); free(br[b]); }
                    free(br);
                    changed = 1;
                } else {
                    strlist_push(&np, &nn, &ncap, pats[p]);
                }
            }
            if (changed) {
                for (int p = 0; p < npat; p++) free(pats[p]);
                free(pats);
                pats = np; npat = nn; patcap = ncap;
            } else {
                for (int p = 0; p < nn; p++) free(np[p]);
                free(np);
            }
        }
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
                // The regex face is a bitset NFA capped at 64 positions (one per
                // literal char / class / metachar, summed across | branches), so
                // an over-long pattern is rejected here just like bad syntax --
                // name both causes so a too-long pattern is not read as a typo.
                if (pk == 0 && !fixed)
                    fprintf(stderr, "sublimation: bad pattern '%s' -- invalid regex, or a single "
                            "branch over the 64-position limit (use -F for a literal)\n", pats[p]);
                else
                    fprintf(stderr, "sublimation: bad pattern '%s' (empty or too long)\n", pats[p]);
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
        // search --tally: intern every -o span instead of printing it, then emit
        // per-span counts once every file is walked. `-o | tally` was the
        // workhorse pipeline; this collapses it to one verb and one hash pass.
        StrMap tmap;
        if (tally_mode) smap_init(&tmap);
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
        // File fan-out on the shared work-stealing deque: more than one file,
        // none of the cross-file-state modes in play, past the measured
        // byte-total floor (see search_total_bytes above).
        // --dispersion: one serial pass collecting SPANS (not lines), then the
        // field over them. Serial on purpose -- the whole point is the ORDER of
        // arrivals, and a chunked scan would have to stitch positions back into
        // sequence before any of it means anything.
        if (dispersion_mode) {
            // --dispersion replaces the output entirely, so a flag that shapes
            // line output cannot apply. Rejected rather than ignored: silently
            // accepting -c here would print a dispersion field to someone who
            // asked for a count.
            const char *clash = count_only ? "-c" : names_only ? "-l"
                              : names_without ? "-L" : only_match ? "-o"
                              : tally_mode ? "--tally" : quiet ? "-q"
                              : want_ctx ? "-A/-B/-C" : invert ? "-v"
                              : max_count ? "-m" : NULL;
            if (clash) {
                fprintf(stderr, "sublimation: --dispersion reports the SHAPE of "
                                "where a pattern falls, not the lines; %s does "
                                "not apply to it\n", clash);
                return 2;
            }
            sublimation_match_span *all = NULL; size_t nall = 0, capall = 0;
            long long base = 0;   // byte offset of the current line
            int rc_any = 0;
            for (int fi = 0; fi < (use_stdin ? 1 : nsf); fi++) {
                FILE *in = stdin;
                if (!use_stdin) {
                    in = fopen(sfiles[fi], "r");
                    if (!in) { had_error = 1;
                               if (!suppress) fprintf(stderr, "sublimation: cannot open '%s'\n", sfiles[fi]);
                               continue; }
                }
                char *ln = NULL; size_t lc = 0; ssize_t l;
                while ((l = getline(&ln, &lc, in)) != -1) {
                    size_t ml = (size_t)l;
                    if (ml && ln[ml - 1] == '\n') ml--;
                    size_t got = sublimation_search_spans(srchs, npat, regex_face, ln, ml,
                                                          word_match, line_match, NULL, 0);
                    if (got) {
                        if (nall + got > capall) {
                            size_t nc = capall ? capall * 2 : 1024;
                            while (nc < nall + got) nc *= 2;
                            sublimation_match_span *na =
                                (sublimation_match_span *)realloc(all, nc * sizeof *na);
                            if (!na) { free(ln); if (!use_stdin) fclose(in); goto disp_done; }
                            all = na; capall = nc;
                        }
                        sublimation_search_spans(srchs, npat, regex_face, ln, ml,
                                                 word_match, line_match, all + nall, got);
                        // Lift each span into WHOLE-STREAM coordinates; a field
                        // computed on per-line offsets would describe the lines,
                        // not the stream.
                        for (size_t k = 0; k < got; k++) {
                            all[nall + k].start += (uint32_t)base;
                            all[nall + k].end   += (uint32_t)base;
                        }
                        nall += got;
                        rc_any = 1;
                    }
                    base += l;
                }
                free(ln);
                if (!use_stdin) fclose(in);
            }
        disp_done:;
            sublimation_dispersion d;
            if (nall >= 2 && sublimation_dispersion_field(all, nall, (size_t)base, &d)) {
                static const char *kCls[] = {"sorted","reversed","nearly-sorted",
                                             "few-unique","random","phased"};
                const char *cn = (d.gap_class >= 0 && d.gap_class < 6) ? kCls[d.gap_class] : "?";
                montauk_sink_appendf(&g_out, "matches            %zu\n", d.matches);
                montauk_sink_appendf(&g_out, "span_bytes         %zu\n", d.span_bytes);
                montauk_sink_appendf(&g_out, "density_per_kb     %.6g\n", d.density_per_kb);
                montauk_sink_appendf(&g_out, "stride_mean        %.6g\n", d.stride_mean);
                montauk_sink_appendf(&g_out, "stride_stdev       %.6g\n", d.stride_stdev);
                montauk_sink_appendf(&g_out, "stride_p50         %.6g\n", d.stride_p50);
                montauk_sink_appendf(&g_out, "stride_p90         %.6g\n", d.stride_p90);
                montauk_sink_appendf(&g_out, "stride_p99         %.6g\n", d.stride_p99);
                montauk_sink_appendf(&g_out, "stride_max         %.6g\n", d.stride_max);
                montauk_sink_appendf(&g_out, "burstiness         %.6g\n", d.burstiness);
                montauk_sink_appendf(&g_out, "gap_class          %s\n", cn);
                montauk_sink_appendf(&g_out, "saliency_max       %.6g\n", d.saliency_max);
                montauk_sink_appendf(&g_out, "saliency_at        %zu\n", d.saliency_at);
                montauk_sink_appendf(&g_out, "saliency_window    %zu\n", d.saliency_window);
                montauk_sink_appendf(&g_out, "discord            %.6g\n", d.discord);
                montauk_sink_appendf(&g_out, "discord_at         %zu\n", d.discord_at);
                montauk_sink_appendf(&g_out, "motif              %.6g\n", d.motif);
                montauk_sink_appendf(&g_out, "motif_at           %zu\n", d.motif_at);
            } else if (nall < 2) {
                fprintf(stderr, "sublimation: %zu match(es) -- a dispersion field "
                                "needs at least 2 (one match has no stride)\n", nall);
            }
            free(all);
            for (int pi = 0; pi < npat; pi++) free(pats[pi]);
            free(pats);
            free(srchs);
            for (int fi2 = 0; fi2 < nsf; fi2++) free(sfiles[fi2]);
            free(sfiles);
            montauk_sink_drain(&g_out);
            return had_error ? 2 : (rc_any ? 0 : 1);
        }

        // NO SILENT NARROWING. -i folds ASCII and the non-ASCII characters whose
        // UTF-8 counterpart keeps the same byte length AND lead byte; anything
        // else matches exactly, so the search quietly returns LESS than asked
        // for. Cyrillic past U+0440 is the common case (`москва` matches
        // `Москва` but not `МОСКВА`). Said once, on stderr, never on the data
        // path -- the results are still correct, just narrower than -i implies.
        if (icase) {
            size_t fold_gaps = 0;
            for (int pi = 0; pi < npat; pi++)
                fold_gaps += sublimation_search_fold_gaps(pats[pi], strlen(pats[pi]));
            if (fold_gaps)
                fprintf(stderr, "sublimation: -i cannot case-fold %zu character(s) "
                        "in this pattern (their upper/lower forms differ in UTF-8 "
                        "length or lead byte); those match exactly, so this search "
                        "is NARROWER than -i implies\n", fold_gaps);
        }

        long long par_bytes = use_stdin ? 0 : search_total_bytes(sfiles, nsf);
        // A LONE FILE NOW CHUNKS. -m is the one exclusion: it means "the first N
        // matches in this file", and chunks scan concurrently with no way to
        // know which N came first without serialising the very thing being
        // parallelised. Everything else composes -- counts sum, names OR, and
        // line numbers are recovered by the merge.
        int want_chunk = !use_stdin && nsf == 1 && !quiet && !tally_mode
                       && !want_ctx && !only_match && !max_count
                       && par_bytes >= SEARCH_PAR_MIN_BYTES;
        int want_parallel = (!use_stdin && nsf >= 2 && !quiet
                          && !tally_mode && !want_ctx && !only_match
                          && par_bytes >= SEARCH_PAR_MIN_BYTES) || want_chunk;
        if (want_parallel) {
            int workers = (int)sublimation_default_workers();
            int maxch = want_chunk ? workers : nsf;
            ParFileResult *results =
                (ParFileResult *)calloc((size_t)(maxch > 0 ? maxch : 1), sizeof(ParFileResult));
            if (!results) { fputs("sublimation: out of memory\n", stderr); return 1; }
            int nchunks;
            if (want_chunk) {
                nchunks = search_split_file(sfiles[0], par_bytes, workers, results, 0);
                if (nchunks <= 0) { nchunks = 1; results[0].file = 0;
                                    results[0].start = 0; results[0].end = 0; }
            } else {
                nchunks = nsf;
                for (int fi = 0; fi < nsf; fi++) {
                    results[fi].file = fi; results[fi].start = 0; results[fi].end = 0;
                }
            }
            ParSearchCtx pc = {
                .files = sfiles, .srchs = srchs, .npat = npat, .regex_face = regex_face,
                .invert = invert, .count_only = count_only, .number = number,
                .names_only = names_only, .names_without = names_without,
                .word_match = word_match, .line_match = line_match,
                .bin_text = bin_text, .bin_skip = bin_skip, .prefix = prefix,
                .color = color, .max_count = max_count, .results = results,
                .nchunks = nchunks,
            };
            atomic_init(&pc.inflight, (size_t)0);
            pc.max_inflight = search_max_inflight();
            atomic_init(&pc.overflow_announced, 0);
            if (!sublimation_parallel_for((size_t)nchunks, (size_t)workers,
                                          search_par_chunk, &pc))
                for (int ci = 0; ci < nchunks; ci++)      // engine OOM: same worker fn, serial
                    search_par_chunk((size_t)ci, &pc);
            // Merge in chunk order, grouping by file. line_base is accumulated
            // HERE and nowhere else: a chunk records line numbers relative to
            // its own start because it cannot know what precedes it, and this
            // is the one pass that does.
            for (int ci = 0; ci < pc.nchunks; ) {
                int f = results[ci].file;
                int cj = ci;
                long base = 0, fmatches = 0;
                int ferr = 0, fbinary = 0;
                while (cj < pc.nchunks && results[cj].file == f) {
                    results[cj].line_base = base;
                    base += results[cj].lines;
                    fmatches += results[cj].fmatches;
                    ferr |= results[cj].had_error;
                    fbinary |= results[cj].binary_hit;
                    cj++;
                }
                if (ferr) {
                    had_error = 1;
                    if (!suppress) fprintf(stderr, "sublimation: cannot open '%s'\n", sfiles[f]);
                } else if (names_only) {
                    if (fmatches > 0) emit_name(&g_out, sfiles[f], color);
                } else if (names_without) {
                    if (fmatches == 0) emit_name(&g_out, sfiles[f], color);
                } else if (count_only) {
                    emit_prefix(&g_out, prefix ? sfiles[f] : NULL, 0, 0, ':', color);
                    montauk_sink_appendf(&g_out, "%ld\n", fmatches);
                } else if (fbinary) {
                    fprintf(stderr, "sublimation: %s: binary file matches\n", sfiles[f]);
                } else {
                    for (int k = ci; k < cj; k++)
                        search_render_one_file_par(sfiles[f], &pc, &results[k], &g_out);
                }
                for (int k = ci; k < cj; k++) {
                    atomic_fetch_sub(&pc.inflight, results[k].buf.raw_n);
                    sublimation_occ_buf_free(&results[k].buf);
                }
                matches += fmatches;
                if (g_out.len >= (1u << 16)) montauk_sink_drain(&g_out);
                ci = cj;
            }
            free(results);
        } else {
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
                        if (!sublimation_search_selects(srchs, npat, regex_face, line, mlen, line_match, word_match)) {
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
                            if (!sublimation_search_selects(srchs, npat, regex_face, line, mlen, 1, word_match)) break;
                            s = 0; end = (long)mlen;
                        } else {
                            // find_from (inside search_next_*) keeps ^/$ anchored
                            // to the real line ends across restarts; a shifted
                            // `line + off` buffer would let ^ match again at
                            // every continuation offset.
                            s = sublimation_search_next_any(srchs, npat, regex_face, line, mlen, off, word_match, &end);
                            if (s < 0) break;
                        }
                        size_t mstart = (size_t)s;
                        size_t mend = (size_t)end;
                        if (mend > mstart) {
                            fmatches++;
                            // grep -c counts matching LINES, not -o spans: one hit
                            // on this line is enough, move on.
                            if (count_only) break;
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
                                if (tally_mode) {
                                    // Count the span, print nothing; the match
                                    // is a slice of a live line, so copy it out
                                    // NUL-terminated for the intern table.
                                    size_t klen = mend - mstart;
                                    char stackk[256];
                                    char *key = (klen < sizeof stackk) ? stackk
                                                                       : (char *)malloc(klen + 1);
                                    if (key) {
                                        memcpy(key, line + mstart, klen);
                                        key[klen] = '\0';
                                        tmap.nums[smap_intern(&tmap, key, NULL)]++;
                                        if (key != stackk) free(key);
                                    }
                                    off = mend;
                                    if (quiet) q_done = 1;
                                    else if (max_count && fmatches >= max_count) fdone = 1;
                                    continue;
                                }
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

                int show = sublimation_search_selects(srchs, npat, regex_face, line, mlen, line_match, word_match);
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
        }
        // --tally emit: highest count first, the same pack-and-sort the tally
        // verb uses (count << 32 | dense index, ordered by the u64 sort).
        if (tally_mode) {
            if (tmap.used > 0 && !quiet) {
                char    **dk     = (char **)malloc(tmap.used * sizeof(char *));
                uint64_t *packed = (uint64_t *)malloc(tmap.used * sizeof(uint64_t));
                if (dk && packed) {
                    size_t d = 0;
                    for (size_t z = 0; z < tmap.cap; z++)
                        if (tmap.keys[z]) {
                            dk[d] = tmap.keys[z];
                            packed[d] = ((uint64_t)tmap.nums[z] << 32) | (uint64_t)d;
                            d++;
                        }
                    sublimation_u64(packed, tmap.used);
                    for (size_t z = tmap.used; z-- > 0;) {
                        unsigned long long c = (unsigned long long)(packed[z] >> 32);
                        size_t idx = (size_t)(packed[z] & 0xFFFFFFFFULL);
                        montauk_sink_appendf(&g_out, "%llu %s\n", c, dk[idx]);
                    }
                }
                free(dk); free(packed);
            }
            smap_free(&tmap);
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
            // 1-based forward, or negative from the end (-1 = last column).
            // Zero is the one index that names nothing either way.
            if (e == p || c == 0 || c < -64 || c > 64 || ncol >= 64) {
                fputs("sublimation: field needs N or a comma-list N,M,... "
                      "(1-based, or negative from the end: -1 is the last)\n", stderr);
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
        long printed = 0;   // lines whose projection was non-empty (the exit-code source)
        InputIter it = { files, nfiles, 0, 0, NULL, NULL };
        while (input_next(&it)) {
            while ((len = getline(&line, &cap, it.in)) != -1) {
                size_t mlen = (size_t)len;
                if (mlen && line[mlen - 1] == '\n') mlen--;
                // awk-exact: capture the requested column(s), print them joined by a
                // single space (awk's default OFS), empty for a missing column, one
                // line per record -- so `field N` matches `{print $N}` even when a
                // line is blank or short.
                const char *got[64];
                size_t gotlen[64];
                for (int k = 0; k < ncol; k++) { got[k] = NULL; gotlen[k] = 0; }
                // A negative column counts from the end, and the end is only
                // known once the line is walked. Keep a ring of the last
                // `maxneg` spans so one pass still answers both directions.
                int maxneg = 0;
                for (int k = 0; k < ncol; k++)
                    if (cols[k] < 0 && -cols[k] > maxneg) maxneg = -cols[k];
                const char *ringp[64];
                size_t ringl[64];
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
                    if (maxneg) {
                        int slot = (f - 1) % maxneg;
                        ringp[slot] = line + start;
                        ringl[slot] = i - start;
                    }
                }
                for (int k = 0; k < ncol; k++) {
                    if (cols[k] >= 0) continue;
                    int m = -cols[k];
                    if (m <= f && m <= maxneg) {
                        int slot = (f - m) % maxneg;
                        got[k] = ringp[slot];
                        gotlen[k] = ringl[slot];
                    }
                }
                int nonempty = 0;
                for (int k = 0; k < ncol; k++) {
                    if (k) montauk_sink_appendc(&g_out, ' ');
                    if (got[k]) { montauk_sink_append(&g_out, got[k], gotlen[k]); nonempty = 1; }
                }
                montauk_sink_appendc(&g_out, '\n');
                if (g_out.len >= (1u << 16)) montauk_sink_drain(&g_out);  // bound memory
                // Only a line that actually yielded a column counts toward exit
                // 0 -- counting every input line made usage()'s "1 when nothing
                // matched" unreachable (`field 9` on 2-column input exited 0).
                if (nonempty) printed++;
            }
        }
        free(line);
        if (it.had_error) return 2;   // unreadable FILE: IO error, like search
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
        InputIter it = { files, nfiles, 0, 0, NULL, NULL };
        while (input_next(&it)) {
            while ((len = getline(&line, &cap, it.in)) != -1) {
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
                    if (multi) montauk_sink_appendf(&g_out, "%s:", it.fname);
                    montauk_sink_append(&g_out, line, (size_t)len);
                }
            }
        }
        free(line);
        if (it.had_error) return 2;   // unreadable FILE: IO error, like search
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
        // The vocabulary datamash defines. Split by what each op NEEDS rather
        // than alphabetically: streaming ops keep O(groups) memory, buffering
        // ops keep every value and cannot avoid it (a median is not a running
        // statistic). sum/mean/min/max/count keep exactly the memory profile
        // they had before this grew.
        enum { G_SUM, G_MEAN, G_COUNT, G_MIN, G_MAX, G_SSTDEV, G_PSTDEV,
               G_FIRST, G_LAST, G_MEDIAN, G_MODE, G_ANTIMODE, G_UNIQUE,
               G_COLLAPSE, G_COUNTUNIQUE, G_BAD };
        static const struct { const char *name; int id; } kOps[] = {
            {"sum",G_SUM},{"mean",G_MEAN},{"count",G_COUNT},{"min",G_MIN},{"max",G_MAX},
            {"sstdev",G_SSTDEV},{"pstdev",G_PSTDEV},{"first",G_FIRST},{"last",G_LAST},
            {"median",G_MEDIAN},{"mode",G_MODE},{"antimode",G_ANTIMODE},
            {"unique",G_UNIQUE},{"collapse",G_COLLAPSE},{"countunique",G_COUNTUNIQUE},
        };
        int opid = G_BAD;
        for (size_t i = 0; i < sizeof kOps / sizeof *kOps; i++)
            if (!strcmp(op, kOps[i].name)) { opid = kOps[i].id; break; }
        if (opid == G_BAD) {
            fprintf(stderr, "sublimation: group OP must be sum|mean|count|min|max|"
                    "sstdev|pstdev|first|last|median|mode|antimode|unique|collapse|"
                    "countunique (got '%s')\n", op);
            return 2;
        }
        int is_count = (opid == G_COUNT);
        // Numeric ops parse the value and skip a row that has none; text ops take
        // the field verbatim, which is what makes `unique` usable on labels.
        int needs_num = (opid == G_SUM || opid == G_MEAN || opid == G_MIN ||
                         opid == G_MAX || opid == G_SSTDEV || opid == G_PSTDEV ||
                         opid == G_MEDIAN);
        int buffers   = (opid == G_MEDIAN || opid == G_MODE || opid == G_ANTIMODE ||
                         opid == G_UNIQUE || opid == G_COLLAPSE || opid == G_COUNTUNIQUE);
        if (!is_count && nfiles < 2) {
            fprintf(stderr, "sublimation: group %s needs a VAL field -- e.g. 'group 1 %s 2'\n", op, op);
            return 2;
        }
        int valf = (nfiles >= 2) ? atoi(files[1]) : 0;
        if (keyf < 1 || (!is_count && valf < 1)) {
            fputs("sublimation: group KEY/VAL fields are 1-based\n", stderr);
            return 2;
        }
        if (nfiles > 2) {  // KEY OP [VAL] consumed; anything further is a mistake
            fprintf(stderr, "sublimation: group reads stdin; '%s' is an "
                    "unexpected argument\n", files[2]);
            return 2;
        }

        StrMap km; smap_init(&km);                              // key -> dense group id (nums)
        size_t gcap = 256, gn = 0;                              // dense per-group state
        char   **gkey = (char **)malloc(gcap * sizeof(char *)); // shares km's key strings
        size_t *grows = (size_t *)malloc(gcap * sizeof(size_t));
        size_t *gnval = (size_t *)malloc(gcap * sizeof(size_t));
        double *gsum  = (double *)malloc(gcap * sizeof(double));
        double *gmin  = (double *)malloc(gcap * sizeof(double));
        double *gmax  = (double *)malloc(gcap * sizeof(double));
        // Welford, so sstdev/pstdev stay STREAMING and numerically stable; a
        // sum-of-squares would lose precision on large means for no saving.
        double *gm    = (double *)calloc(gcap, sizeof(double));   // running mean
        double *gm2   = (double *)calloc(gcap, sizeof(double));   // sum of squared deviations
        char  **gfirst = (char **)calloc(gcap, sizeof(char *));
        char  **glast  = (char **)calloc(gcap, sizeof(char *));
        char ***gvals = (char ***)calloc(gcap, sizeof(char **));  // buffering ops only
        size_t *gvn = (size_t *)calloc(gcap, sizeof(size_t));
        size_t *gvc = (size_t *)calloc(gcap, sizeof(size_t));
        if (!gkey || !grows || !gnval || !gsum || !gmin || !gmax || !gm || !gm2 ||
            !gfirst || !glast || !gvals || !gvn || !gvc) {
            fputs("sublimation: out of memory\n", stderr); return 1;
        }

        char *line = NULL; size_t lcap = 0; ssize_t len;
        while ((len = getline(&line, &lcap, stdin)) != -1) {
            if (len > 0 && line[len - 1] == '\n') line[--len] = '\0';
            size_t klen; const char *kspan = field_span(line, (size_t)len, keyf, delim, &klen);
            if (!kspan) continue;  // no key column -> skip the row
            double val = 0.0; int have_val = 0;
            const char *vspan = NULL; size_t vlen = 0;
            if (!is_count) {
                vspan = field_span(line, (size_t)len, valf, delim, &vlen);
                if (vspan) { char *end = NULL; val = strtod(vspan, &end); have_val = (end != vspan); }
                if (needs_num && !have_val) continue;   // numeric ops need a number
                if (!vspan) continue;                   // text ops still need the column
            }
            char *ktok = (char *)kspan; ktok[klen] = '\0';
            int created = 0;
            size_t slot = smap_intern(&km, ktok, &created);  // the one hash implementation
            size_t gid;
            if (!created) {
                gid = km.nums[slot];
            } else {
                if (gn == gcap) {  // grow dense arrays (the strings they point to do not move)
                    size_t ncap = gcap * 2;
                    gkey = (char **)realloc(gkey, ncap * sizeof(char *));
                    grows = (size_t *)realloc(grows, ncap * sizeof(size_t));
                    gnval = (size_t *)realloc(gnval, ncap * sizeof(size_t));
                    gsum = (double *)realloc(gsum, ncap * sizeof(double));
                    gmin = (double *)realloc(gmin, ncap * sizeof(double));
                    gmax = (double *)realloc(gmax, ncap * sizeof(double));
                    gm = (double *)realloc(gm, ncap * sizeof(double));
                    gm2 = (double *)realloc(gm2, ncap * sizeof(double));
                    gfirst = (char **)realloc(gfirst, ncap * sizeof(char *));
                    glast = (char **)realloc(glast, ncap * sizeof(char *));
                    gvals = (char ***)realloc(gvals, ncap * sizeof(char **));
                    gvn = (size_t *)realloc(gvn, ncap * sizeof(size_t));
                    gvc = (size_t *)realloc(gvc, ncap * sizeof(size_t));
                    if (!gkey || !grows || !gnval || !gsum || !gmin || !gmax || !gm ||
                        !gm2 || !gfirst || !glast || !gvals || !gvn || !gvc) {
                        fputs("sublimation: out of memory\n", stderr); return 1;
                    }
                    for (size_t z = gcap; z < ncap; z++) {
                        gm[z] = gm2[z] = 0.0; gfirst[z] = glast[z] = NULL;
                        gvals[z] = NULL; gvn[z] = gvc[z] = 0;
                    }
                    gcap = ncap;
                }
                gid = gn++;
                gkey[gid] = km.keys[slot];   // the map's strdup'd key, stable across grows
                grows[gid] = 0; gnval[gid] = 0; gsum[gid] = 0.0; gmin[gid] = 0.0; gmax[gid] = 0.0;
                gm[gid] = gm2[gid] = 0.0; gfirst[gid] = glast[gid] = NULL;
                gvals[gid] = NULL; gvn[gid] = gvc[gid] = 0;
                km.nums[slot] = gid;
            }
            grows[gid]++;
            if (vspan) {
                char *vtok = (char *)malloc(vlen + 1);
                if (!vtok) { fputs("sublimation: out of memory\n", stderr); return 1; }
                memcpy(vtok, vspan, vlen); vtok[vlen] = '\0';
                if (!gfirst[gid]) gfirst[gid] = vtok;
                else if (opid == G_FIRST) { free(vtok); vtok = NULL; }
                if (vtok) {
                    if (opid == G_LAST) { if (glast[gid] && glast[gid] != gfirst[gid]) free(glast[gid]);
                                          glast[gid] = vtok; }
                    else if (buffers) {
                        if (gvn[gid] == gvc[gid]) {
                            size_t nc = gvc[gid] ? gvc[gid] * 2 : 8;
                            char **nv = (char **)realloc(gvals[gid], nc * sizeof(char *));
                            if (!nv) { fputs("sublimation: out of memory\n", stderr); return 1; }
                            gvals[gid] = nv; gvc[gid] = nc;
                        }
                        gvals[gid][gvn[gid]++] = vtok;
                    } else if (vtok != gfirst[gid]) free(vtok);
                }
            }
            if (have_val) {
                if (gnval[gid] == 0) { gmin[gid] = val; gmax[gid] = val; }
                else { if (val < gmin[gid]) gmin[gid] = val; if (val > gmax[gid]) gmax[gid] = val; }
                gsum[gid] += val; gnval[gid]++;
                double d = val - gm[gid];
                gm[gid] += d / (double)gnval[gid];
                gm2[gid] += d * (val - gm[gid]);
            }
        }
        free(line);

        for (size_t g = 0; g < gn; g++) {
            size_t nv = gvn[g];
            switch (opid) {
            case G_COUNT:  montauk_sink_appendf(&g_out, "%s %zu\n", gkey[g], grows[g]); break;
            case G_SUM:    montauk_sink_appendf(&g_out, "%s %.14g\n", gkey[g], gsum[g]); break;
            case G_MEAN:   montauk_sink_appendf(&g_out, "%s %.14g\n", gkey[g],
                                gnval[g] ? gsum[g] / (double)gnval[g] : 0.0); break;
            case G_MIN:    montauk_sink_appendf(&g_out, "%s %.14g\n", gkey[g], gmin[g]); break;
            case G_MAX:    montauk_sink_appendf(&g_out, "%s %.14g\n", gkey[g], gmax[g]); break;
            // SAMPLE stdev of ONE observation is UNDEFINED, not zero: the
            // estimator divides by n-1. Reporting 0 there is a convenient lie
            // that reads as "no spread" when the truth is "not estimable", and
            // datamash says nan for the same reason. POPULATION stdev of one
            // point IS 0 and stays 0 -- the two differ here on purpose.
            case G_SSTDEV: montauk_sink_appendf(&g_out, "%s %.14g\n", gkey[g],
                                gnval[g] > 1 ? sqrt(gm2[g] / (double)(gnval[g] - 1))
                                             : (double)NAN); break;
            case G_PSTDEV: montauk_sink_appendf(&g_out, "%s %.14g\n", gkey[g],
                                gnval[g] ? sqrt(gm2[g] / (double)gnval[g]) : 0.0); break;
            case G_FIRST:  montauk_sink_appendf(&g_out, "%s %s\n", gkey[g],
                                gfirst[g] ? gfirst[g] : ""); break;
            case G_LAST:   montauk_sink_appendf(&g_out, "%s %s\n", gkey[g],
                                glast[g] ? glast[g] : (gfirst[g] ? gfirst[g] : "")); break;
            case G_MEDIAN: {
                double *v = (double *)malloc((nv ? nv : 1) * sizeof *v);
                if (!v) break;
                for (size_t i = 0; i < nv; i++) v[i] = strtod(gvals[g][i], NULL);
                // The library's own sort, not qsort: shipped code has one
                // ordering implementation and this is it.
                sublimation_f64(v, nv);
                double med = nv ? (nv % 2 ? v[nv / 2]
                                          : (v[nv / 2 - 1] + v[nv / 2]) / 2.0) : 0.0;
                montauk_sink_appendf(&g_out, "%s %.14g\n", gkey[g], med);
                free(v);
                break;
            }
            case G_MODE: case G_ANTIMODE: {
                // Ties go to the value that appears EARLIEST in sorted order, so
                // the answer is deterministic instead of depending on input order.
                const char **v = (const char **)malloc((nv ? nv : 1) * sizeof *v);
                if (!v) break;
                for (size_t i = 0; i < nv; i++) v[i] = gvals[g][i];
                sublimation_strings(v, nv);
                size_t best = 0, run = 0, bestrun = 0; const char *bestv = nv ? v[0] : "";
                for (size_t i = 0; i < nv; i++) {
                    run = (i && !strcmp(v[i], v[i - 1])) ? run + 1 : 1;
                    int better = (opid == G_MODE) ? (run > bestrun)
                                                  : (bestrun == 0 || run < bestrun);
                    // antimode wants the SMALLEST run, but a run is only final at
                    // its end -- compare on the last element of each run.
                    int at_end = (i + 1 == nv) || strcmp(v[i], v[i + 1]);
                    if (at_end && (bestrun == 0 || better)) { bestrun = run; bestv = v[i]; best = i; }
                }
                (void)best;
                montauk_sink_appendf(&g_out, "%s %s\n", gkey[g], nv ? bestv : "");
                free(v);
                break;
            }
            case G_UNIQUE: {
                const char **v = (const char **)malloc((nv ? nv : 1) * sizeof *v);
                if (!v) break;
                for (size_t i = 0; i < nv; i++) v[i] = gvals[g][i];
                sublimation_strings(v, nv);
                montauk_sink_appendf(&g_out, "%s ", gkey[g]);
                int first_out = 1;
                for (size_t i = 0; i < nv; i++) {
                    if (i && !strcmp(v[i], v[i - 1])) continue;
                    if (!first_out) montauk_sink_appendc(&g_out, ',');
                    montauk_sink_append(&g_out, v[i], strlen(v[i]));
                    first_out = 0;
                }
                montauk_sink_appendc(&g_out, '\n');
                free(v);
                break;
            }
            case G_COLLAPSE: {
                montauk_sink_appendf(&g_out, "%s ", gkey[g]);
                for (size_t i = 0; i < nv; i++) {
                    if (i) montauk_sink_appendc(&g_out, ',');
                    montauk_sink_append(&g_out, gvals[g][i], strlen(gvals[g][i]));
                }
                montauk_sink_appendc(&g_out, '\n');
                break;
            }
            case G_COUNTUNIQUE: {
                const char **v = (const char **)malloc((nv ? nv : 1) * sizeof *v);
                if (!v) break;
                for (size_t i = 0; i < nv; i++) v[i] = gvals[g][i];
                sublimation_strings(v, nv);
                size_t u = 0;
                for (size_t i = 0; i < nv; i++)
                    if (!i || strcmp(v[i], v[i - 1])) u++;
                montauk_sink_appendf(&g_out, "%s %zu\n", gkey[g], u);
                free(v);
                break;
            }
            default: break;
            }
            if (g_out.len >= (1u << 16)) montauk_sink_drain(&g_out);
        }
        for (size_t g = 0; g < gn; g++) {
            for (size_t i = 0; i < gvn[g]; i++)
                if (gvals[g][i] != gfirst[g]) free(gvals[g][i]);
            free(gvals[g]);
            if (glast[g] && glast[g] != gfirst[g]) free(glast[g]);
            free(gfirst[g]);
        }
        smap_free(&km);   // owns (and frees) the key strings gkey shares
        free(gkey); free(grows); free(gnval); free(gsum); free(gmin); free(gmax);
        free(gm); free(gm2); free(gfirst); free(glast); free(gvals); free(gvn); free(gvc);
        return 0;
    }

    // uniq: collapse ADJACENT equal lines (sort first for a global dedup). -d emits
    // only lines that repeated, -u only lines that did not. stdin or one FILE,
    // like real uniq's INPUT argument.
    if (!strcmp(cmd, "uniq")) {
        FILE *in = open_single_input(cmd, pos, nfiles ? files[0] : NULL);
        char *line = NULL, *prev = NULL; size_t lcap = 0, pcap = 0, plen = 0; ssize_t len;
        int have_prev = 0; long run = 0;
        while ((len = getline(&line, &lcap, in)) != -1) {
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
        if (in != stdin) fclose(in);
        free(line); free(prev);
        return 0;
    }

    // tac: reverse line (arrival) order -- distinct from sort --desc (sorted order).
    // stdin or one FILE, like real tac's FILE argument.
    if (!strcmp(cmd, "tac")) {
        FILE *in = open_single_input(cmd, pos, nfiles ? files[0] : NULL);
        char **buf = NULL; size_t bn = 0, bcap = 0;
        char *line = NULL; size_t lcap = 0; ssize_t len;
        while ((len = getline(&line, &lcap, in)) != -1) {
            if (bn == bcap) { bcap = bcap ? bcap * 2 : 1024; buf = (char **)xrealloc(buf, bcap * sizeof(char *)); }
            buf[bn] = (char *)xmalloc((size_t)len + 1);
            memcpy(buf[bn], line, (size_t)len); buf[bn][len] = '\0'; bn++;
        }
        if (in != stdin) fclose(in);
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
        // stdin or one FILE after the count, like real head/tail's -N FILE.
        FILE *in = open_single_input(cmd, nfiles ? files[0] : NULL, nfiles > 1 ? files[1] : NULL);
        char *line = NULL; size_t lcap = 0; ssize_t len;
        if (!strcmp(cmd, "head")) {
            long shown = 0;
            while (shown < n && (len = getline(&line, &lcap, in)) != -1) {
                montauk_sink_append(&g_out, line, (size_t)len);
                shown++;
                if (g_out.len >= (1u << 16)) montauk_sink_drain(&g_out);
            }
        } else {
            typedef struct { char *data; size_t len; } RingLine;
            RingLine *ring = (RingLine *)xcalloc((size_t)n, sizeof(RingLine));
            size_t count = 0, next = 0;  // next = slot to write, wraps once full (oldest overwritten)
            while ((len = getline(&line, &lcap, in)) != -1) {
                free(ring[next].data);
                ring[next].data = (char *)xmalloc((size_t)len);
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
        if (in != stdin) fclose(in);
        free(line);
        return 0;
    }

    // cut: character columns (cut -c). RANGE is 1-based inclusive: "N", "lo-hi",
    // "lo-", "-hi". field/where own delimiter columns; this is the char-range gap.
    // stdin or one FILE after the range, like real cut -c RANGE FILE.
    if (!strcmp(cmd, "cut")) {
        if (!pos) { fputs("sublimation: cut needs a char range -- e.g. 'cut 1-5'\n", stderr); return 2; }
        long clo = 1, chi = -1;  // chi = -1 means "to end of line"
        const char *dash = strchr(pos, '-');
        if (!dash) { clo = chi = atol(pos); }
        else { clo = (dash == pos) ? 1 : atol(pos); chi = *(dash + 1) ? atol(dash + 1) : -1; }
        if (clo < 1) clo = 1;
        FILE *in = open_single_input(cmd, nfiles ? files[0] : NULL, nfiles > 1 ? files[1] : NULL);
        char *line = NULL; size_t lcap = 0; ssize_t len;
        while ((len = getline(&line, &lcap, in)) != -1) {
            size_t l = (len > 0 && line[len - 1] == '\n') ? (size_t)len - 1 : (size_t)len;
            size_t a = (size_t)clo - 1;
            size_t b = (chi < 0) ? l : (size_t)chi;
            if (b > l) b = l;
            if (a < b) montauk_sink_append(&g_out, line + a, b - a);
            montauk_sink_appendc(&g_out, '\n');
            if (g_out.len >= (1u << 16)) montauk_sink_drain(&g_out);
        }
        if (in != stdin) fclose(in);
        free(line);
        return 0;
    }

    // column: align delim/whitespace-separated input into columns (column -t).
    // Buffers the input to compute per-column widths. stdin or one FILE, like
    // real column -t FILE.
    if (!strcmp(cmd, "column")) {
        FILE *in = open_single_input(cmd, pos, nfiles ? files[0] : NULL);
        char **lines = NULL; size_t ln = 0, lcapn = 0;
        char *line = NULL; size_t lcap = 0; ssize_t len;
        size_t *maxw = NULL; size_t maxw_cap = 0;
        while ((len = getline(&line, &lcap, in)) != -1) {
            size_t l = (len > 0 && line[len - 1] == '\n') ? (size_t)len - 1 : (size_t)len;
            char *s = (char *)xmalloc(l + 1); memcpy(s, line, l); s[l] = '\0';
            if (ln == lcapn) { lcapn = lcapn ? lcapn * 2 : 256; lines = (char **)xrealloc(lines, lcapn * sizeof(char *)); }
            lines[ln++] = s;
            // Scratch copy for strtok_r (it writes NULs into the buffer); s
            // itself is kept intact for the render pass below.
            char *tmp = (char *)xmalloc(l + 1); memcpy(tmp, s, l); tmp[l] = '\0';
            char *save = NULL; size_t c = 0;
            for (char *tok = strtok_r(tmp, delim, &save); tok; tok = strtok_r(NULL, delim, &save)) {
                size_t w = strlen(tok);
                if (c >= maxw_cap) {
                    size_t new_cap = maxw_cap ? maxw_cap * 2 : 64;
                    while (new_cap <= c) new_cap *= 2;
                    maxw = (size_t *)xrealloc(maxw, new_cap * sizeof(size_t));
                    for (size_t k = maxw_cap; k < new_cap; k++) maxw[k] = 0;
                    maxw_cap = new_cap;
                }
                if (w > maxw[c]) maxw[c] = w;
                c++;
            }
            free(tmp);
        }
        if (in != stdin) fclose(in);
        free(line);
        for (size_t i = 0; i < ln; i++) {
            size_t tl = strlen(lines[i]);
            char *tmp = (char *)xmalloc(tl + 1); memcpy(tmp, lines[i], tl); tmp[tl] = '\0';
            char *save = NULL; char **toks = NULL; size_t toks_cap = 0, nt = 0;
            for (char *tok = strtok_r(tmp, delim, &save); tok; tok = strtok_r(NULL, delim, &save)) {
                if (nt == toks_cap) { toks_cap = toks_cap ? toks_cap * 2 : 64; toks = (char **)xrealloc(toks, toks_cap * sizeof(char *)); }
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
    // multi-file paste is the join/set-ops two-stream lane.) stdin or one FILE,
    // like real paste -s FILE.
    if (!strcmp(cmd, "paste") && serial) {
        FILE *in = open_single_input(cmd, pos, nfiles ? files[0] : NULL);
        char *line = NULL; size_t lcap = 0; ssize_t len; int first = 1;
        while ((len = getline(&line, &lcap, in)) != -1) {
            size_t l = (len > 0 && line[len - 1] == '\n') ? (size_t)len - 1 : (size_t)len;
            if (!first) montauk_sink_appendc(&g_out, '\t');
            montauk_sink_append(&g_out, line, l); first = 0;
        }
        if (!first) montauk_sink_appendc(&g_out, '\n');
        if (in != stdin) fclose(in);
        free(line);
        return 0;
    }

    // paste, positional (zip) mode: one line from EACH input per output line,
    // tab-joined; a single file (or stdin alone) just passes through unchanged,
    // matching the prior single-stream behavior. Ragged files pad with an empty
    // field once exhausted, continuing until every stream is done -- real
    // paste's multi-file semantics, which sublimation's paste never had before.
    if (!strcmp(cmd, "paste")) {
        enum { MAXIN = 257 };
        FILE *ins[MAXIN]; int nin = 0;
        if (!pos && nfiles == 0) { ins[nin++] = stdin; }
        else {
            const char *p0 = pos ? pos : files[0];
            int start = pos ? 0 : 1;
            ins[nin] = strcmp(p0, "-") ? fopen(p0, "r") : stdin;
            if (!ins[nin]) { fprintf(stderr, "sublimation: cannot open '%s'\n", p0); return 2; }
            nin++;
            for (int i = start; i < nfiles && nin < MAXIN; i++) {
                ins[nin] = strcmp(files[i], "-") ? fopen(files[i], "r") : stdin;
                if (!ins[nin]) { fprintf(stderr, "sublimation: cannot open '%s'\n", files[i]); return 2; }
                nin++;
            }
        }
        char **bufs = (char **)calloc((size_t)nin, sizeof(char *));
        size_t *caps = (size_t *)calloc((size_t)nin, sizeof(size_t));
        int *done = (int *)calloc((size_t)nin, sizeof(int));
        if (!bufs || !caps || !done) { fputs("sublimation: out of memory\n", stderr); return 1; }
        for (;;) {
            size_t row_start = g_out.len;
            int any = 0;
            for (int i = 0; i < nin; i++) {
                if (i) montauk_sink_appendc(&g_out, '\t');
                if (done[i]) continue;
                ssize_t len = getline(&bufs[i], &caps[i], ins[i]);
                if (len == -1) { done[i] = 1; continue; }
                any = 1;
                size_t l = (len > 0 && bufs[i][len - 1] == '\n') ? (size_t)len - 1 : (size_t)len;
                montauk_sink_append(&g_out, bufs[i], l);
            }
            if (!any) { g_out.len = row_start; break; }   // every stream exhausted: no trailing empty row
            montauk_sink_appendc(&g_out, '\n');
            if (g_out.len >= (1u << 16)) montauk_sink_drain(&g_out);
        }
        for (int i = 0; i < nin; i++) { free(bufs[i]); if (ins[i] != stdin) fclose(ins[i]); }
        free(bufs); free(caps); free(done);
        return 0;
    }

    // Set ops over two streams -- stdin and a FILE. intersect = lines in both,
    // subtract = stdin lines not in FILE, union = distinct lines from both. Output
    // is stdin's first-seen order, deduped (union appends FILE-only lines after).
    if (!strcmp(cmd, "intersect") || !strcmp(cmd, "subtract") || !strcmp(cmd, "union")) {
        if (!pos) { fprintf(stderr, "sublimation: %s needs a FILE -- e.g. '%s other.txt'\n", cmd, cmd); return 2; }
        if (nfiles > 0) {  // one FILE only: the other stream is stdin by design
            fprintf(stderr, "sublimation: %s takes one FILE; '%s' is an "
                    "unexpected argument\n", cmd, files[0]);
            return 2;
        }
        StrMap fileset; smap_init(&fileset);
        if (smap_load_file(&fileset, pos, 0) != 0) {
            // IO error is exit 2 (the contract in usage()), not 1 -- 1 is
            // reserved for "ran fine, nothing matched/produced".
            fprintf(stderr, "sublimation: cannot open '%s'\n", pos); smap_free(&fileset); return 2;
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
        if (nfiles > 1) {  // FIELD FILE consumed; anything further is a mistake
            fprintf(stderr, "sublimation: join takes FIELD FILE; '%s' is an "
                    "unexpected argument\n", files[1]);
            return 2;
        }
        int jf = atoi(pos); if (jf < 1) { fputs("sublimation: join FIELD is 1-based\n", stderr); return 2; }
        // Real join -tCHAR uses CHAR for both input parsing and output joining;
        // with no -t, parsing is any blank run but output is always a plain
        // space. Mirrored here: sep is delim's first char only when --delim was
        // explicitly given, else a space regardless of the default " \t".
        char sep = delim_set ? delim[0] : ' ';
        StrMap fm; smap_init(&fm);
        FILE *ff = fopen(files[0], "r");
        if (!ff) { fprintf(stderr, "sublimation: cannot open '%s'\n", files[0]); smap_free(&fm); return 2; }  // IO error, per the contract
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
        if (nfiles > 1) {  // PATTERN REPLACEMENT consumed; replace reads stdin
            fprintf(stderr, "sublimation: replace reads stdin; '%s' is an "
                    "unexpected argument\n", files[1]);
            return 2;
        }
        const char *repl = files[0]; size_t rlen = strlen(repl);
        // Backreferences are opt-in BY THE REPLACEMENT: no \1..\9 means the
        // literal fast path, unchanged, and no submatch pass ever runs.
        int has_backref = 0;
        for (size_t ri = 0; ri + 1 < rlen; ri++)
            if (repl[ri] == '\\' && ((repl[ri+1] >= '0' && repl[ri+1] <= '9'))) { has_backref = 1; break; }
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
                if (has_backref && me > ms) {
                    // Captures are extracted from the MATCH SPAN alone, and only
                    // because this replacement asked. A pattern with no groups,
                    // or one the submatch subset cannot parse, substitutes the
                    // backreference as EMPTY rather than guessing -- the same
                    // thing sed does for a group that did not participate.
                    sublimation_match_span gr[9];
                    size_t ng = 0;
                    int have = sublimation_search_captures(pos, line + ms, me - ms,
                                                           icase, gr, 9, &ng);
                    for (size_t ri = 0; ri < rlen; ri++) {
                        if (repl[ri] == '\\' && ri + 1 < rlen) {
                            char d = repl[ri + 1];
                            if (d >= '1' && d <= '9') {
                                size_t gi = (size_t)(d - '1');
                                if (have && gi < ng && gr[gi].pat >= 0)
                                    montauk_sink_append(&g_out, line + ms + gr[gi].start,
                                                        gr[gi].end - gr[gi].start);
                                ri++; continue;
                            }
                            if (d == '0') {   // \0: the whole match, as sed's & does
                                montauk_sink_append(&g_out, line + ms, me - ms);
                                ri++; continue;
                            }
                            if (d == '\\') { montauk_sink_appendc(&g_out, '\\'); ri++; continue; }
                        }
                        montauk_sink_appendc(&g_out, repl[ri]);
                    }
                } else {
                    montauk_sink_append(&g_out, repl, rlen);        // the replacement
                }
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

    // tr SET1 [SET2] / tr -d SET1: byte-domain translate or delete over stdin,
    // reading and writing raw bytes (not line-oriented -- real tr has no
    // notion of lines). No POSIX [:class:] names, no squeeze (-s); those are
    // out of this scope, only translate/delete.
    if (!strcmp(cmd, "tr")) {
        if (!pos) { fputs("sublimation: tr needs SET1 [SET2] -- e.g. 'tr a-z A-Z' or 'tr -d 0-9'\n", stderr); return 2; }
        if (!tr_delete && nfiles < 1) { fputs("sublimation: tr needs SET2 (or -d to delete SET1) -- e.g. 'tr a-z A-Z'\n", stderr); return 2; }
        if (nfiles > 1) { fprintf(stderr, "sublimation: tr reads stdin; '%s' is an unexpected argument\n", files[1]); return 2; }
        unsigned char set1[256];
        size_t n1 = tr_expand_set(pos, set1, sizeof set1);
        int ch;
        if (tr_delete) {
            unsigned char del[256] = {0};
            for (size_t i = 0; i < n1; i++) del[set1[i]] = 1;
            while ((ch = getchar()) != EOF) {
                if (!del[(unsigned char)ch]) montauk_sink_appendc(&g_out, (char)ch);
                if (g_out.len >= (1u << 16)) montauk_sink_drain(&g_out);
            }
        } else {
            unsigned char set2[256];
            size_t n2 = tr_expand_set(files[0], set2, sizeof set2);
            unsigned char map[256];
            for (int i = 0; i < 256; i++) map[i] = (unsigned char)i;
            for (size_t i = 0; i < n1; i++)
                map[set1[i]] = (n2 == 0) ? set1[i] : set2[(i < n2) ? i : n2 - 1];  // SET2 shorter: its last char repeats
            while ((ch = getchar()) != EOF) {
                montauk_sink_appendc(&g_out, (char)map[(unsigned char)ch]);
                if (g_out.len >= (1u << 16)) montauk_sink_drain(&g_out);
            }
        }
        return 0;
    }

    // comm FILE: sorted 3-column compare, stdin vs FILE (both assumed already
    // sorted -- unsorted input gives comm's usual undefined-ish output, same
    // as real comm). Column 1 = stdin-only, column 2 (1 tab) = FILE-only,
    // column 3 (2 tabs) = common to both. No -1/-2/-3 column suppression yet.
    if (!strcmp(cmd, "comm")) {
        if (!pos) { fputs("sublimation: comm needs FILE -- e.g. 'comm sorted.txt' (stdin is the other stream, both pre-sorted)\n", stderr); return 2; }
        if (nfiles > 0) { fprintf(stderr, "sublimation: comm takes one FILE; '%s' is an unexpected argument\n", files[0]); return 2; }
        FILE *f2 = strcmp(pos, "-") ? fopen(pos, "r") : stdin;
        if (!f2) { fprintf(stderr, "sublimation: cannot open '%s'\n", pos); return 2; }
        char *l1 = NULL, *l2 = NULL; size_t c1 = 0, c2 = 0; ssize_t n1, n2;
        n1 = getline(&l1, &c1, stdin); if (n1 > 0 && l1[n1 - 1] == '\n') l1[--n1] = '\0';
        n2 = getline(&l2, &c2, f2);    if (n2 > 0 && l2[n2 - 1] == '\n') l2[--n2] = '\0';
        while (n1 >= 0 || n2 >= 0) {
            int cmp = (n1 < 0) ? 1 : (n2 < 0) ? -1 : strcmp(l1, l2);
            if (cmp < 0) {
                montauk_sink_append(&g_out, l1, (size_t)n1); montauk_sink_appendc(&g_out, '\n');
                n1 = getline(&l1, &c1, stdin); if (n1 > 0 && l1[n1 - 1] == '\n') l1[--n1] = '\0';
            } else if (cmp > 0) {
                montauk_sink_appendc(&g_out, '\t');
                montauk_sink_append(&g_out, l2, (size_t)n2); montauk_sink_appendc(&g_out, '\n');
                n2 = getline(&l2, &c2, f2); if (n2 > 0 && l2[n2 - 1] == '\n') l2[--n2] = '\0';
            } else {
                montauk_sink_append(&g_out, "\t\t", 2);
                montauk_sink_append(&g_out, l1, (size_t)n1); montauk_sink_appendc(&g_out, '\n');
                n1 = getline(&l1, &c1, stdin); if (n1 > 0 && l1[n1 - 1] == '\n') l1[--n1] = '\0';
                n2 = getline(&l2, &c2, f2);    if (n2 > 0 && l2[n2 - 1] == '\n') l2[--n2] = '\0';
            }
            if (g_out.len >= (1u << 16)) montauk_sink_drain(&g_out);
        }
        free(l1); free(l2);
        if (f2 != stdin) fclose(f2);
        return 0;
    }

    // Numeric/structural commands read stdin only; a leftover positional here
    // is a mistake (the text verbs consumed theirs above). Error rather than
    // silently reading stdin and ignoring the path: `sublimation sum data.txt`
    // reporting a confident number about the PIPE is the silent-wrong-answer
    // shape. Of the verbs that reach this point, only quantile / select /
    // searchsorted / locate consume a positional (Q / K / V / CLASS).
    if (pos && strcmp(cmd, "quantile") && strcmp(cmd, "select") &&
        strcmp(cmd, "searchsorted") && strcmp(cmd, "locate")) {
        fprintf(stderr, "sublimation: %s reads stdin; '%s' is an unexpected "
                "argument\n", cmd, pos);
        return 2;
    }
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
        StrMap tm; smap_init(&tm);   // token -> count (nums payload)
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
            tm.nums[smap_intern(&tm, tok, NULL)]++;   // the one hash implementation
        }
        free(line);

        if (!strcmp(cmd, "distinct")) {
            montauk_sink_appendf(&g_out, "%zu\n", tm.used);
        } else if (tm.used > 0) {
            // Compact to dense (key,count); order by count desc through the u64
            // sort. pack = (count << 32) | dense_index -- both fit a line stream.
            char    **dk     = (char **)malloc(tm.used * sizeof(char *));
            uint64_t *packed = (uint64_t *)malloc(tm.used * sizeof(uint64_t));
            if (!dk || !packed) { fputs("sublimation: out of memory\n", stderr); return 1; }
            size_t d = 0;
            for (size_t i = 0; i < tm.cap; i++)
                if (tm.keys[i]) { dk[d] = tm.keys[i]; packed[d] = ((uint64_t)tm.nums[i] << 32) | (uint64_t)d; d++; }
            sublimation_u64(packed, tm.used);          // ascending
            for (size_t i = tm.used; i-- > 0;) {       // descending = highest count first
                unsigned long long count = (unsigned long long)(packed[i] >> 32);
                size_t idx = (size_t)(packed[i] & 0xFFFFFFFFULL);
                montauk_sink_appendf(&g_out, "%llu %s\n", count, dk[idx]);
            }
            free(dk); free(packed);
        }
        smap_free(&tm);
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
            // A NaN key ("nan"/"NaN") parses but is no more a valid sort key than
            // "abc" is -- skip it the same way, not letting it slip into the sort.
            if (end == src || isnan(x)) { skipped++; continue; }
            if (human) x *= human_scale(end);   // 4.0K sorts under 16M, not over it
            keyed_push(&kb, x, strdup(line));
        }
        free(line);
        if (kb.n > UINT32_MAX) {
            fprintf(stderr, "sublimation: sort --keyed caps at 2^32 lines (got %zu)\n", kb.n);
            return 1;
        }
        // Multi-key: --field takes a comma list, e.g. --field 1,2 -- secondary
        // keys tie-break the primary, down the list. The primary (first token)
        // is already `field`/kb.keys above; only the rest need parsing here.
        // No comma: every other verb's single-int --field is untouched.
        int keyfields[16], nkeyfields = 0;
        if (field_arg && strchr(field_arg, ',')) {
            char *fa = strdup(field_arg);
            char *save = NULL; int first = 1;
            for (char *tok = strtok_r(fa, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
                if (first) { first = 0; continue; }   // first token is the primary, already parsed
                if (nkeyfields < 16) keyfields[nkeyfields++] = atoi(tok);
            }
            free(fa);
        }

        uint32_t *order = NULL;
        if (kb.n > 0) {
            order = (uint32_t *)malloc(kb.n * sizeof(uint32_t));
            if (!order) { fputs("sublimation: out of memory\n", stderr); return 1; }
            for (size_t i = 0; i < kb.n; i++) order[i] = (uint32_t)i;
            if (nkeyfields > 0) {
                double *fieldvals = (double *)malloc(kb.n * sizeof(double));
                if (!fieldvals) { fputs("sublimation: out of memory\n", stderr); free(order); return 1; }
                for (int kx = nkeyfields - 1; kx >= 0; kx--) {   // least to most significant secondary
                    int fld = keyfields[kx];
                    for (size_t i = 0; i < kb.n; i++) {
                        size_t rl = strlen(kb.lines[i]);
                        size_t flen; const char *sp = field_span(kb.lines[i], rl, fld, delim, &flen);
                        double v = 0.0;   // missing/non-numeric secondary field: a defined 0, not a skip
                        if (sp) { char *end = NULL; double x = strtod(sp, &end); if (end != sp && !isnan(x)) v = x; }
                        fieldvals[i] = v;
                    }
                    refine_order_by_key(order, fieldvals, kb.n, desc);
                }
                free(fieldvals);
                refine_order_by_key(order, kb.keys, kb.n, desc);   // primary key: most significant, applied last
            } else {
                sublimation_pack_sort_f64(kb.keys, order, kb.n, desc != 0);
            }
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
        montauk_sink_appendf(&g_out, "%.12g\n", sublimation_sum_f64(data.v, data.n));

    } else if (!strcmp(cmd, "mean")) {    // awk '{s+=$N} END{print s/NR}' (over the parsed values)
        montauk_sink_appendf(&g_out, "%.12g\n", sublimation_mean_f64(data.v, data.n));

    } else if (!strcmp(cmd, "variance") || !strcmp(cmd, "stdev")) {
        // SAMPLE variance / stdev (n-1 denominator), matching the convention the
        // PANDEMONIUM suite's mean_stdev() uses so it is an exact drop-in. n<2 has
        // no spread -> 0.0 (same as mean_stdev).
        if (data.n < 2) { montauk_sink_appendf(&g_out, "0\n"); }
        else {
            montauk_sink_appendf(&g_out, "%.12g\n",
                !strcmp(cmd, "stdev") ? sublimation_stdev_f64(data.v, data.n)
                                      : sublimation_variance_f64(data.v, data.n));
        }

    } else if (!strcmp(cmd, "min")) {     // running minimum
        montauk_sink_appendf(&g_out, "%.12g\n", sublimation_min_f64(data.v, data.n));

    } else if (!strcmp(cmd, "max")) {     // running maximum
        montauk_sink_appendf(&g_out, "%.12g\n", sublimation_max_f64(data.v, data.n));

    } else if (!strcmp(cmd, "describe")) {  // pandas .describe() / R summary() in one shot
        sub_describe_t d = sublimation_describe_f64(data.v, data.n);
        montauk_sink_appendf(&g_out, "%-6s %zu\n",   "count", d.n);
        montauk_sink_appendf(&g_out, "%-6s %.12g\n", "mean",  d.mean);
        montauk_sink_appendf(&g_out, "%-6s %.12g\n", "stdev", d.stdev);
        montauk_sink_appendf(&g_out, "%-6s %.12g\n", "min",   d.min);
        montauk_sink_appendf(&g_out, "%-6s %.12g\n", "25%",   d.q25);
        montauk_sink_appendf(&g_out, "%-6s %.12g\n", "50%",   d.q50);
        montauk_sink_appendf(&g_out, "%-6s %.12g\n", "75%",   d.q75);
        montauk_sink_appendf(&g_out, "%-6s %.12g\n", "max",   d.max);

    } else if (!strcmp(cmd, "outliers")) {  // values outside the Tukey IQR fences
        double lo, hi;
        sublimation_tukey_fences_f64(data.v, data.n, &lo, &hi);  // sorts in place
        for (size_t i = 0; i < data.n; i++)
            if (data.v[i] < lo || data.v[i] > hi)
                montauk_sink_appendf(&g_out, "%.12g\n", data.v[i]);

    } else if (!strcmp(cmd, "histogram")) {  // text histogram (10 bins) -- the shape
        enum { NB = 10 };
        size_t cnt[NB];
        double mn = 0.0, bw = 0.0;
        sublimation_histogram_f64(data.v, data.n, NB, cnt, &mn, &bw);
        size_t maxc = 0; for (int b = 0; b < NB; b++) if (cnt[b] > maxc) maxc = cnt[b];
        int nb = (bw > 0.0) ? NB : 1;        // all values equal -> a single bin
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
        // --nearest is nearest-rank (k = ceil(q*n)-1), the exact convention the
        // PANDEMONIUM suite's percentile() uses, so it is a bit-exact drop-in;
        // the default estimator path is unchanged for existing callers.
        montauk_sink_appendf(&g_out, "%.12g\n",
            sublimation_quantile_f64(data.v, data.n, q, nearest));

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
                  "few-unique random phased)\n", stderr);
            return 2;
        }
        if (window > data.n) {
            fprintf(stderr, "sublimation: --window %zu exceeds input length %zu\n", window, data.n);
            return 2;
        }
        size_t cap = data.n / stride + 2;
        sub_match_t *m = (sub_match_t *)xmalloc(cap * sizeof(sub_match_t));
        size_t k = sublimation_locate_f64(data.v, data.n, window, stride, target, m, cap);
        if (values) {
            // select-by-structure: emit the VALUES any matching window covers, each
            // once in input order -- "the part of the stream that IS this class".
            char *cov = (char *)xcalloc(data.n, 1);
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
        // Unreachable while the verbs[] table up top matches the dispatch --
        // unknown commands are rejected before any stdin read. Kept as the
        // exhaustiveness backstop should the two ever drift.
        fprintf(stderr, "sublimation: unknown command '%s'\n\n", cmd);
        usage(stderr);
        free(data.v);
        return 2;
    }

    free(data.v);
    return 0;
}
