// sublimation_text.hpp -- header-only C++ adapters over the C text engines in
// sublimation_text.h. The engines (Boyer-Moore in bmh.c, Thompson NFA in nfa.c)
// are pure C23; these are zero-cost value wrappers so C++ callers read cleanly.
// API mirrors montauk's retired util::BoyerMooreSearch / util::ThompsonNFA.
#ifndef SUBLIMATION_TEXT_HPP
#define SUBLIMATION_TEXT_HPP

#include "sublimation_text.h"
#include <string_view>
#include <utility>

namespace sublimation {

// Boyer-Moore-Horspool literal substring search (ASCII case-insensitive --
// montauk's substring UX, e.g. "fire" matches "Firefox"). The C engine now
// defaults to case-sensitive (grep -F semantics); this wrapper pins the fold on
// to keep montauk's filter behavior unchanged.
class BMH {
public:
    explicit BMH(std::string_view pattern) {
        sublimation_bmh_compile_ex(&b_, pattern.data(), pattern.size(), /*icase=*/1);
    }
    // Offset of the first match, or -1.
    [[nodiscard]] long search(std::string_view text) const {
        return sublimation_bmh_search(&b_, text.data(), text.size());
    }
private:
    sublimation_bmh b_;
};

// Thompson NFA regex (byte-level, UTF-8-aware). Case-sensitive -- callers that
// want case-insensitivity fold the case themselves, as montauk's filter does.
class NFA {
public:
    explicit NFA(std::string_view pattern) {
        sublimation_nfa_compile(&n_, pattern.data(), pattern.size());
    }
    [[nodiscard]] bool valid() const { return sublimation_nfa_valid(&n_) != 0; }
    [[nodiscard]] bool full_match(std::string_view in) const {
        return sublimation_nfa_full_match(&n_, in.data(), in.size()) != 0;
    }
    // {start, end} (end exclusive), or {-1, -1} if no match.
    [[nodiscard]] std::pair<long, long> find(std::string_view in) const {
        long end = -1;
        long start = sublimation_nfa_find(&n_, in.data(), in.size(), &end);
        return { start, start < 0 ? -1 : end };
    }
private:
    sublimation_nfa n_;
};

} // namespace sublimation

#endif // SUBLIMATION_TEXT_HPP
