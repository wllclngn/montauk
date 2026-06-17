// bmh.c -- Boyer-Moore-Horspool literal substring search (sublimation_text.h).
// 1:1 C23 port of montauk's BoyerMooreSearch: same bad-character table, same
// right-to-left compare, same ASCII case-fold, same empty/over-length handling.
#include "sublimation_text.h"

// ASCII lowercase: A-Z -> a-z, everything else passthrough. Byte-identical to
// montauk's ascii_lower_table for all 256 values (non-letters are unchanged).
static inline unsigned char sub_lower(unsigned char c) {
    return (c >= 'A' && c <= 'Z') ? (unsigned char)(c + 32) : c;
}

void sublimation_bmh_compile(sublimation_bmh *out, const char *pattern, size_t len) {
    // Empty or over-length -> empty pattern (matches at 0), 1:1 with the C++ ctor.
    if (len == 0 || len > SUBLIMATION_BMH_MAX_PATTERN) {
        out->pattern_len = 0;
        return;
    }
    out->pattern_len = (int)len;
    for (size_t i = 0; i < len; ++i) out->pattern[i] = (unsigned char)pattern[i];
    // All bytes default to a full-length shift.
    for (int i = 0; i < 256; ++i) out->bad_char[i] = (int)len;
    // Pattern bytes except the last get their actual shift distance.
    for (int i = 0; i < (int)len - 1; ++i) {
        out->bad_char[sub_lower(out->pattern[i])] = (int)len - 1 - i;
    }
}

long sublimation_bmh_search(const sublimation_bmh *bmh, const char *text, size_t n) {
    int m = bmh->pattern_len;
    if (m == 0) return 0;            // empty pattern matches at position 0
    if ((size_t)m > n) return -1;

    long limit = (long)n - m;
    for (long i = 0; i <= limit;) {
        int j = m - 1;
        while (j >= 0 &&
               sub_lower((unsigned char)text[i + j]) == sub_lower(bmh->pattern[j])) {
            --j;
        }
        if (j < 0) return i;         // match
        int shift = bmh->bad_char[sub_lower((unsigned char)text[i + m - 1])];
        i += (shift > 0) ? shift : 1;
    }
    return -1;
}
