// search_probe.c -- batch differential harness for the public sublimation_search
// API. One stdin line per case, every field of every entry point out, so the
// Python driver can hold each one to an independent oracle.
//
// in:  <face> <hexpattern|-> <hextext|->        face: regex | regexi
// out: 0 <error>                                 (pattern refused)
//      1 npos count start end full | C ok ng s e ... | S ns s e ... | X sel W sel
// A capture group that did not participate prints as -1 -1.
#include "sublimation_text.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { MAX_PAT = 4096, MAX_TXT = 1 << 18, MAX_GROUPS = 32, MAX_SPANS = 1024 };

static int hexval(int c) { return c <= '9' ? c - '0' : (c | 32) - 'a' + 10; }

static size_t unhex(const char *s, unsigned char *out, size_t cap) {
    if (!strcmp(s, "-")) return 0;
    size_t n = 0;
    while (s[0] && s[1] && n < cap) {
        out[n++] = (unsigned char)(hexval(s[0]) * 16 + hexval(s[1]));
        s += 2;
    }
    return n;
}

int main(void) {
    static char line[3 * MAX_TXT];
    static char face[16], hp[2 * MAX_PAT + 2], ht[2 * MAX_TXT + 2];
    static unsigned char pat[MAX_PAT + 1], txt[MAX_TXT];
    static sublimation_search s;
    while (fgets(line, sizeof line, stdin)) {
        if (sscanf(line, "%15s %8193s %524289s", face, hp, ht) != 3) {
            puts("bad");
            continue;
        }
        size_t plen = unhex(hp, pat, MAX_PAT);
        pat[plen] = 0;
        size_t n = unhex(ht, txt, MAX_TXT);
        int icase = !strcmp(face, "regexi");
        sublimation_search_compile(&s, (const char *)pat, plen,
                                   icase ? SUBLIMATION_SEARCH_ICASE : 0, 0);
        if (!sublimation_search_valid(&s)) {
            printf("0 %d\n", s.error);
            continue;
        }
        const char *t = (const char *)txt;
        size_t cnt = sublimation_search_count(&s, t, n);
        long end = -1, st = sublimation_search_find(&s, t, n, &end);
        int full = sublimation_search_full_match(&s, t, n);
        printf("1 %d %zu %ld %ld %d", s.g.npos, cnt, st, st >= 0 ? end : -1, full);

        if (st >= 0) {
            sublimation_match_span g[MAX_GROUPS];
            size_t ng = 0;
            int ok = sublimation_search_captures_at((const char *)pat, t, n, (size_t)st,
                                                    (size_t)end, icase, g,
                                                    MAX_GROUPS, &ng);
            printf(" | C %d %zu", ok, ok ? ng : 0);
            for (size_t i = 0; ok && i < ng; i++) {
                if (g[i].pat < 0) printf(" -1 -1");
                else printf(" %u %u", g[i].start, g[i].end);
            }
        } else {
            printf(" | C - 0");
        }

        static sublimation_match_span sp[MAX_SPANS];
        size_t ns = sublimation_search_spans(&s, 1, 1, t, n, 0, 0, sp, MAX_SPANS);
        printf(" | S %zu", ns);
        for (size_t i = 0; i < ns && i < MAX_SPANS; i++) printf(" %u %u", sp[i].start, sp[i].end);

        printf(" | X %d W %d\n",
               sublimation_search_selects(&s, 1, 1, t, n, 1, 0),
               sublimation_search_selects(&s, 1, 1, t, n, 0, 1));
    }
    return 0;
}
