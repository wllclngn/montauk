#pragma once

#include <string>
#include <cstdint>
#include "util/AsciiLower.hpp"

namespace montauk::util {

// Boyer-Moore-Horspool literal search.
// O(1) extra space (fixed 256-byte bad character table).
// Average case: O(n/m) sublinear. Worst case: O(n*m).
// Case-insensitive via compile-time ascii_lower lookup table.
class BoyerMooreSearch {
public:
    explicit BoyerMooreSearch(const std::string& pattern);

    // Returns position of first match, or -1 if not found.
    [[nodiscard]] int search(const std::string& text) const;

private:
    static constexpr int ALPHABET_SIZE = 256;
    static constexpr int MAX_PATTERN = 256;

    int bad_char_[ALPHABET_SIZE];
    std::string pattern_;
    int pattern_len_;

    void compute_bad_char();
};

} // namespace montauk::util
