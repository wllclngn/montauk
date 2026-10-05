// test_diff.c -- the line diff, and the borrowed literal needle.

#include "sublimation_text.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;

static void check(bool cond, const char *what) {
    printf("%s %s\n", cond ? "  ok  " : "  FAIL", what);
    if (!cond) failures++;
}

#define MAXH 64
static sublimation_diff_hunk H[MAXH];

static int run(const char *const *a, size_t na, const char *const *b, size_t nb) {
    return sublimation_diff_lines(a, NULL, na, b, NULL, nb, H, MAXH, 0);
}

// Applies the hunks to A and checks the result is B. A diff that does not
// reconstruct its target is wrong however plausible its hunks look, and this
// is the only assertion that catches every way of being wrong at once.
static bool reconstructs(const char *const *a, size_t na,
                         const char *const *b, size_t nb, int n) {
    size_t at = 0, bt = 0;
    for (int i = 0; i < n; i++) {
        const sublimation_diff_hunk *h = &H[i];
        if (h->a_start != at || h->b_start != bt) return false;
        switch (h->op) {
            case SUBLIMATION_DIFF_EQUAL:
                if (h->a_count != h->b_count) return false;
                for (size_t k = 0; k < h->a_count; k++)
                    if (strcmp(a[at + k], b[bt + k])) return false;
                at += h->a_count; bt += h->b_count;
                break;
            case SUBLIMATION_DIFF_DELETE:
                if (h->b_count) return false;
                at += h->a_count;
                break;
            case SUBLIMATION_DIFF_INSERT:
                if (h->a_count) return false;
                bt += h->b_count;
                break;
        }
    }
    return at == na && bt == nb;
}

int main(void) {
    printf("● diff:\n");

    {
        const char *a[] = {"one", "two", "three"};
        const int n = run(a, 3, a, 3);
        check(n == 1 && H[0].op == SUBLIMATION_DIFF_EQUAL && H[0].a_count == 3,
              "identical input is one equal hunk");
    }

    {
        const char *a[] = {"x"};
        const int n = sublimation_diff_lines(a, NULL, 1, NULL, NULL, 0, H, MAXH, 0);
        check(n == 1 && H[0].op == SUBLIMATION_DIFF_DELETE && H[0].a_count == 1,
              "everything deleted");
    }

    {
        const char *b[] = {"x", "y"};
        const int n = sublimation_diff_lines(NULL, NULL, 0, b, NULL, 2, H, MAXH, 0);
        check(n == 1 && H[0].op == SUBLIMATION_DIFF_INSERT && H[0].b_count == 2,
              "everything inserted");
    }

    {
        const char *a[] = {"a", "b", "c"};
        const char *b[] = {"a", "B", "c"};
        const int n = run(a, 3, b, 3);
        check(reconstructs(a, 3, b, 3, n), "a changed middle line reconstructs");
        check(n == 4, "as equal, delete, insert, equal");
    }

    {
        const char *a[] = {"k1", "k2", "k3", "k4", "k5"};
        const char *b[] = {"k1", "k2", "new", "k3", "k4", "k5"};
        const int n = run(a, 5, b, 6);
        check(reconstructs(a, 5, b, 6, n), "an insertion reconstructs");
    }

    {
        const char *a[] = {"d1", "gone", "d2"};
        const char *b[] = {"d1", "d2"};
        const int n = run(a, 3, b, 2);
        check(reconstructs(a, 3, b, 2, n), "a deletion reconstructs");
    }

    {
        // Runs coalesce: three consecutive deletions are one hunk, not three.
        const char *a[] = {"h", "1", "2", "3", "t"};
        const char *b[] = {"h", "t"};
        const int n = run(a, 5, b, 2);
        check(reconstructs(a, 5, b, 2, n), "a run of deletions reconstructs");
        int deletes = 0;
        for (int i = 0; i < n; i++)
            if (H[i].op == SUBLIMATION_DIFF_DELETE) { deletes++;
                check(H[i].a_count == 3, "and arrives as one hunk of three"); }
        check(deletes == 1, "with exactly one delete hunk");
    }

    {
        const char *a[] = {"1", "2", "3", "4"};
        const char *b[] = {"4", "3", "2", "1"};
        const int n = run(a, 4, b, 4);
        check(n > 0 && reconstructs(a, 4, b, 4, n), "a reversal reconstructs");
    }

    {
        // Sizing: one call with no buffer must predict what a second call writes.
        const char *a[] = {"p", "q", "r"};
        const char *b[] = {"p", "Q", "R"};
        const int want = sublimation_diff_lines(a, NULL, 3, b, NULL, 3, NULL, 0, 0);
        const int got = run(a, 3, b, 3);
        check(want == got && want > 0, "a counting pass predicts the hunk count");
    }

    {
        // The trim is what makes the common case cheap: one changed line in a
        // long file must not cost a search over the whole file.
        enum { N = 4000 };
        static const char *a[N], *b[N];
        static char storage[N][16];
        for (int i = 0; i < N; i++) {
            snprintf(storage[i], sizeof storage[i], "line%d", i);
            a[i] = b[i] = storage[i];
        }
        b[N / 2] = "CHANGED";
        const int n = sublimation_diff_lines(a, NULL, N, b, NULL, N, H, MAXH, 0);
        check(n == 4, "one change in 4000 lines is four hunks");
        check(H[0].a_count == (size_t)(N / 2), "with the prefix trimmed whole");
    }

    {
        // Explicit byte lengths, so embedded NULs and unterminated slices work.
        const char *a[] = {"ab\0cd", "x"};
        const size_t alen[] = {5, 1};
        const char *b[] = {"ab\0cd", "y"};
        const size_t blen[] = {5, 1};
        const int n = sublimation_diff_lines(a, alen, 2, b, blen, 2, H, MAXH, 0);
        check(n == 3 && H[0].op == SUBLIMATION_DIFF_EQUAL && H[0].a_count == 1,
              "a line holding a NUL compares by length");
    }

    {
        const char *a[] = {"a", "b", "c", "d"};
        const char *b[] = {"w", "x", "y", "z"};
        const int n = sublimation_diff_lines(a, NULL, 4, b, NULL, 4, H, MAXH, 1);
        check(n == -1, "an edit past max_cost is refused rather than paid for");
    }

    {
        // The shape that overflows a step list sized by edit distance alone:
        // the ends differ so neither trim fires, and a thousand identical
        // lines between them are all diagonal moves.
        enum { N = 1002 };
        static const char *a[N], *b[N];
        static char storage[N][16];
        for (int i = 1; i < N - 1; i++) {
            snprintf(storage[i], sizeof storage[i], "same%d", i);
            a[i] = b[i] = storage[i];
        }
        a[0] = "head-a"; b[0] = "head-b";
        a[N - 1] = "tail-a"; b[N - 1] = "tail-b";

        const int n = sublimation_diff_lines(a, NULL, N, b, NULL, N, H, MAXH, 0);
        check(n > 0 && reconstructs(a, N, b, N, n),
              "a small edit inside a large untrimmed region reconstructs");
    }

    printf("● borrowed literal needle:\n");
    {
        // The ceiling the literal face used to have. 4 KiB is an ordinary
        // anchor for a caller replacing a block of text.
        static char needle[4096];
        static char hay[8192];
        memset(needle, 'q', sizeof needle);
        memset(hay, '.', sizeof hay);
        memcpy(hay + 1000, needle, sizeof needle);

        sublimation_search s;
        sublimation_search_compile(&s, needle, sizeof needle,
                                   SUBLIMATION_SEARCH_FIXED, 0);
        check(sublimation_search_valid(&s), "a 4 KiB literal compiles");
        check(sublimation_search_error(&s) == NULL, "and reports no error");
        const long at = sublimation_search_find(&s, hay, sizeof hay, NULL);
        check(at == 1000, "and finds its occurrence");
    }

    {
        const char *needle = "needle";
        sublimation_search s;
        sublimation_search_compile(&s, needle, strlen(needle),
                                   SUBLIMATION_SEARCH_FIXED, 0);
        check(sublimation_search_find(&s, "a needle here", 13, NULL) == 2,
              "a short literal still works");
        check(sublimation_search_count(&s, "needle needle", 13) == 2,
              "and counts");
    }

    printf("● compile refusals name themselves:\n");
    {
        sublimation_search s;
        sublimation_search_compile(&s, "", 0, SUBLIMATION_SEARCH_FIXED, 0);
        check(!sublimation_search_valid(&s), "an empty pattern is invalid");
        const char *e = sublimation_search_error(&s);
        check(e && strstr(e, "empty"), "and says it was empty");
    }

    {
        // Too long and malformed used to be the same answer.
        static char big[SUBLIMATION_SEARCH_MAX_PATTERN + 64];
        memset(big, 'a', sizeof big);
        sublimation_search s;
        sublimation_search_compile(&s, big, sizeof big, 0, 0);
        const char *e = sublimation_search_error(&s);
        check(!sublimation_search_valid(&s) && e && strstr(e, "too long"),
              "an over-long regex says it was too long");

        sublimation_search bad;
        sublimation_search_compile(&bad, "[unclosed", 9, 0, 0);
        const char *eb = sublimation_search_error(&bad);
        check(!sublimation_search_valid(&bad) && eb && strstr(eb, "parse"),
              "a malformed regex says it does not parse");
    }

    printf("%s\n", failures == 0 ? "ok" : "FAILED");
    return failures == 0 ? 0 : 1;
}
