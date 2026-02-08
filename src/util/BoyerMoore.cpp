#include "util/BoyerMoore.hpp"

namespace montauk::util {

BoyerMooreSearch::BoyerMooreSearch(const std::string& pattern)
    : pattern_(pattern),
      pattern_len_(static_cast<int>(pattern.length())) {
    if (pattern_len_ < 0 || pattern_len_ > MAX_PATTERN) {
        pattern_len_ = 0;
        return;
    }
    if (pattern_len_ == 0) return; // empty pattern matches everything
    compute_bad_char();
}

void BoyerMooreSearch::compute_bad_char() {
    // All characters default to maximum shift (pattern length)
    for (int i = 0; i < ALPHABET_SIZE; ++i) {
        bad_char_[i] = pattern_len_;
    }
    // Characters in pattern (except last) get actual shift distances
    for (int i = 0; i < pattern_len_ - 1; ++i) {
        unsigned char c = ascii_lower(static_cast<unsigned char>(pattern_[i]));
        bad_char_[c] = pattern_len_ - 1 - i;
    }
}

int BoyerMooreSearch::search(const std::string& text) const {
    int n = static_cast<int>(text.length());
    int m = pattern_len_;

    if (m == 0) return 0; // empty pattern matches at position 0
    if (m > n) return -1;

    int i = 0;
    while (i <= n - m) {
        int j = m - 1;

        // Compare right to left
        while (j >= 0 &&
               ascii_lower(static_cast<unsigned char>(text[i + j])) ==
               ascii_lower(static_cast<unsigned char>(pattern_[j]))) {
            --j;
        }

        if (j < 0) return i; // match

        // Bad character shift
        unsigned char bad = ascii_lower(static_cast<unsigned char>(text[i + m - 1]));
        int shift = bad_char_[bad];
        i += (shift > 0) ? shift : 1;
    }

    return -1;
}

} // namespace montauk::util
