#include "minitest.hpp"
#include "sublimation_text.h"   // the Thompson NFA moved into sublimation (C engine)

#include <string_view>
#include <utility>

// The NFA moved from a montauk C++ class into sublimation's C engine. This thin
// adapter preserves the test surface (ctor / valid / full_match / find) over the
// sublimation_nfa_* C API, so the cases below keep their coverage on the new home.
namespace {
struct ThompsonNFA {
    sublimation_nfa nfa_;
    explicit ThompsonNFA(std::string_view pat) { sublimation_nfa_compile(&nfa_, pat.data(), pat.size()); }
    bool valid() const { return sublimation_nfa_valid(&nfa_) != 0; }
    bool full_match(std::string_view s) const { return sublimation_nfa_full_match(&nfa_, s.data(), s.size()) != 0; }
    std::pair<long, long> find(std::string_view s) const {
        long end = -1;
        long start = sublimation_nfa_find(&nfa_, s.data(), s.size(), &end);
        return start < 0 ? std::pair<long, long>{-1, -1} : std::pair<long, long>{start, end};
    }
};
}  // namespace

// BASIC LITERALS

TEST(nfa_literal_full_match) {
    ThompsonNFA nfa("hello");
    ASSERT_TRUE(nfa.valid());
    ASSERT_TRUE(nfa.full_match("hello"));
    ASSERT_TRUE(!nfa.full_match("hell"));
    ASSERT_TRUE(!nfa.full_match("helloo"));
    ASSERT_TRUE(!nfa.full_match(""));
}

TEST(nfa_literal_find) {
    ThompsonNFA nfa("world");
    ASSERT_TRUE(nfa.valid());
    auto [s, e] = nfa.find("hello world");
    ASSERT_EQ(s, 6);
    ASSERT_EQ(e, 11);
}

TEST(nfa_literal_find_not_found) {
    ThompsonNFA nfa("xyz");
    auto [s, e] = nfa.find("hello world");
    ASSERT_EQ(s, -1);
    ASSERT_EQ(e, -1);
}

TEST(nfa_single_char) {
    ThompsonNFA nfa("a");
    ASSERT_TRUE(nfa.full_match("a"));
    ASSERT_TRUE(!nfa.full_match("b"));
    ASSERT_TRUE(!nfa.full_match("aa"));
}

// DOT (ANY CHARACTER)

TEST(nfa_dot) {
    ThompsonNFA nfa("a.c");
    ASSERT_TRUE(nfa.full_match("abc"));
    ASSERT_TRUE(nfa.full_match("axc"));
    ASSERT_TRUE(!nfa.full_match("ac"));
    ASSERT_TRUE(!nfa.full_match("abbc"));
}

TEST(nfa_dot_star) {
    ThompsonNFA nfa("a.*c");
    ASSERT_TRUE(nfa.full_match("ac"));
    ASSERT_TRUE(nfa.full_match("abc"));
    ASSERT_TRUE(nfa.full_match("aXYZc"));
    ASSERT_TRUE(!nfa.full_match("ab"));
}

TEST(nfa_dot_plus) {
    ThompsonNFA nfa("a.+c");
    ASSERT_TRUE(!nfa.full_match("ac"));
    ASSERT_TRUE(nfa.full_match("abc"));
    ASSERT_TRUE(nfa.full_match("aXYZc"));
}

// QUANTIFIERS: * + ?

TEST(nfa_star) {
    ThompsonNFA nfa("ab*c");
    ASSERT_TRUE(nfa.full_match("ac"));
    ASSERT_TRUE(nfa.full_match("abc"));
    ASSERT_TRUE(nfa.full_match("abbbc"));
    ASSERT_TRUE(!nfa.full_match("abbc_"));
}

TEST(nfa_plus) {
    ThompsonNFA nfa("ab+c");
    ASSERT_TRUE(!nfa.full_match("ac"));
    ASSERT_TRUE(nfa.full_match("abc"));
    ASSERT_TRUE(nfa.full_match("abbbc"));
}

TEST(nfa_question) {
    ThompsonNFA nfa("ab?c");
    ASSERT_TRUE(nfa.full_match("ac"));
    ASSERT_TRUE(nfa.full_match("abc"));
    ASSERT_TRUE(!nfa.full_match("abbc"));
}

// ALTERNATION: |

TEST(nfa_alternation) {
    ThompsonNFA nfa("cat|dog");
    ASSERT_TRUE(nfa.full_match("cat"));
    ASSERT_TRUE(nfa.full_match("dog"));
    ASSERT_TRUE(!nfa.full_match("car"));
    ASSERT_TRUE(!nfa.full_match("catdog"));
}

TEST(nfa_alternation_in_find) {
    ThompsonNFA nfa("cat|dog");
    auto [s1, e1] = nfa.find("I have a dog");
    ASSERT_EQ(s1, 9);
    ASSERT_EQ(e1, 12);
    auto [s2, e2] = nfa.find("my cat is nice");
    ASSERT_EQ(s2, 3);
    ASSERT_EQ(e2, 6);
}

// GROUPING: ()

TEST(nfa_group_alternation) {
    ThompsonNFA nfa("(foo|bar)baz");
    ASSERT_TRUE(nfa.full_match("foobaz"));
    ASSERT_TRUE(nfa.full_match("barbaz"));
    ASSERT_TRUE(!nfa.full_match("bazbaz"));
}

TEST(nfa_group_quantifier) {
    ThompsonNFA nfa("(ab)+");
    ASSERT_TRUE(nfa.full_match("ab"));
    ASSERT_TRUE(nfa.full_match("abab"));
    ASSERT_TRUE(nfa.full_match("ababab"));
    ASSERT_TRUE(!nfa.full_match("a"));
    ASSERT_TRUE(!nfa.full_match("aba"));
}

TEST(nfa_nested_groups) {
    ThompsonNFA nfa("((a|b)c)+");
    ASSERT_TRUE(nfa.full_match("ac"));
    ASSERT_TRUE(nfa.full_match("bc"));
    ASSERT_TRUE(nfa.full_match("acbc"));
    ASSERT_TRUE(!nfa.full_match("ab"));
}

// CHARACTER CLASSES: [] [^]

TEST(nfa_char_class) {
    ThompsonNFA nfa("[abc]");
    ASSERT_TRUE(nfa.full_match("a"));
    ASSERT_TRUE(nfa.full_match("b"));
    ASSERT_TRUE(nfa.full_match("c"));
    ASSERT_TRUE(!nfa.full_match("d"));
    ASSERT_TRUE(!nfa.full_match("ab"));
}

TEST(nfa_char_class_range) {
    ThompsonNFA nfa("[a-z]");
    ASSERT_TRUE(nfa.full_match("a"));
    ASSERT_TRUE(nfa.full_match("m"));
    ASSERT_TRUE(nfa.full_match("z"));
    ASSERT_TRUE(!nfa.full_match("A"));
    ASSERT_TRUE(!nfa.full_match("0"));
}

TEST(nfa_char_class_negated) {
    ThompsonNFA nfa("[^abc]");
    ASSERT_TRUE(!nfa.full_match("a"));
    ASSERT_TRUE(!nfa.full_match("b"));
    ASSERT_TRUE(nfa.full_match("d"));
    ASSERT_TRUE(nfa.full_match("z"));
}

TEST(nfa_char_class_with_quantifier) {
    ThompsonNFA nfa("[0-9]+");
    ASSERT_TRUE(nfa.full_match("123"));
    ASSERT_TRUE(nfa.full_match("0"));
    ASSERT_TRUE(!nfa.full_match(""));
    ASSERT_TRUE(!nfa.full_match("12a"));
}

// ANCHORS: ^ $

TEST(nfa_anchor_start) {
    ThompsonNFA nfa("^hello");
    auto [s, e] = nfa.find("hello world");
    ASSERT_EQ(s, 0);
    ASSERT_EQ(e, 5);
    auto [s2, e2] = nfa.find("say hello");
    ASSERT_EQ(s2, -1);
}

TEST(nfa_anchor_end) {
    ThompsonNFA nfa("world$");
    auto [s, e] = nfa.find("hello world");
    ASSERT_EQ(s, 6);
    ASSERT_EQ(e, 11);
    auto [s2, e2] = nfa.find("world hello");
    ASSERT_EQ(s2, -1);
}

TEST(nfa_anchor_both) {
    ThompsonNFA nfa("^exact$");
    ASSERT_TRUE(nfa.full_match("exact"));
    auto [s, e] = nfa.find("exact");
    ASSERT_EQ(s, 0);
    ASSERT_EQ(e, 5);
    auto [s2, e2] = nfa.find("not exact");
    ASSERT_EQ(s2, -1);
}

TEST(nfa_anchor_empty) {
    ThompsonNFA nfa("^$");
    ASSERT_TRUE(nfa.valid());
    auto [s, e] = nfa.find("");
    ASSERT_EQ(s, 0);
    ASSERT_EQ(e, 0);
    auto [s2, e2] = nfa.find("notempty");
    ASSERT_EQ(s2, -1);
}

// FIND_FROM: continuation-safe offset search, anchors stay absolute

TEST(nfa_find_from_unanchored) {
    ThompsonNFA nfa("ab");
    std::string_view in = "ab ab ab";
    long end = -1;
    ASSERT_EQ(sublimation_nfa_find_from(&nfa.nfa_, in.data(), in.size(), 0, &end), 0);
    ASSERT_EQ(end, 2);
    ASSERT_EQ(sublimation_nfa_find_from(&nfa.nfa_, in.data(), in.size(), 2, &end), 3);
    ASSERT_EQ(end, 5);
    ASSERT_EQ(sublimation_nfa_find_from(&nfa.nfa_, in.data(), in.size(), 6, &end), 6);
    ASSERT_EQ(end, 8);
    ASSERT_EQ(sublimation_nfa_find_from(&nfa.nfa_, in.data(), in.size(), 7, &end), -1);
}

TEST(nfa_find_from_caret_absolute) {
    // ^ matches only at offset 0 of the full input; a continuation restart at
    // from > 0 must never re-match it. This is the replace/grep -o defect the
    // API exists to close.
    ThompsonNFA nfa("^");
    std::string_view in = "abc";
    long end = -1;
    ASSERT_EQ(sublimation_nfa_find_from(&nfa.nfa_, in.data(), in.size(), 0, &end), 0);
    ASSERT_EQ(end, 0);
    ASSERT_EQ(sublimation_nfa_find_from(&nfa.nfa_, in.data(), in.size(), 1, &end), -1);
    ASSERT_EQ(sublimation_nfa_find_from(&nfa.nfa_, in.data(), in.size(), 3, &end), -1);
}

TEST(nfa_find_from_anchored_prefix) {
    ThompsonNFA nfa("^ab");
    std::string_view in = "abab";
    long end = -1;
    ASSERT_EQ(sublimation_nfa_find_from(&nfa.nfa_, in.data(), in.size(), 0, &end), 0);
    ASSERT_EQ(end, 2);
    ASSERT_EQ(sublimation_nfa_find_from(&nfa.nfa_, in.data(), in.size(), 2, &end), -1);
}

TEST(nfa_find_from_dollar_absolute) {
    ThompsonNFA nfa("b$");
    std::string_view in = "b b";
    long end = -1;
    ASSERT_EQ(sublimation_nfa_find_from(&nfa.nfa_, in.data(), in.size(), 0, &end), 2);
    ASSERT_EQ(end, 3);
    ASSERT_EQ(sublimation_nfa_find_from(&nfa.nfa_, in.data(), in.size(), 3, &end), -1);
}

TEST(nfa_find_from_past_end) {
    ThompsonNFA nfa("a");
    std::string_view in = "a";
    long end = -1;
    ASSERT_EQ(sublimation_nfa_find_from(&nfa.nfa_, in.data(), in.size(), 2, &end), -1);
}

TEST(nfa_find_wrapper_equivalence) {
    // sublimation_nfa_find is now the from == 0 case of find_from.
    ThompsonNFA nfa("l+o");
    std::string_view in = "hello hello";
    long e1 = -1, e2 = -1;
    long s1 = sublimation_nfa_find(&nfa.nfa_, in.data(), in.size(), &e1);
    long s2 = sublimation_nfa_find_from(&nfa.nfa_, in.data(), in.size(), 0, &e2);
    ASSERT_EQ(s1, s2);
    ASSERT_EQ(e1, e2);
}

// Differential gate for find_from: every (pattern, input, from) triple is
// checked against a brute-force oracle built on full_match over substrings
// (leftmost start at or after `from`, longest end at that start; ^ only at
// absolute 0, $ only at absolute n). Any engine change, whatever its origin,
// must pass this before landing.
TEST(nfa_find_from_differential) {
    const char* patterns[] = {"a", "ab", "a+b", "a*", "(ab|ba)", "[0-9]+",
                              "^ab", "ab$", "^a*b$", "a.c"};
    const char* inputs[] = {"", "a", "ab", "ba", "abab", "xxabyy", "123ab9",
                            "aaab", "abc a1c", "bbbb"};
    for (const char* pat : patterns) {
        ThompsonNFA nfa(pat);
        ASSERT_TRUE(nfa.valid());
        const bool anch_start = nfa.nfa_.anchored_start != 0;
        const bool anch_end = nfa.nfa_.anchored_end != 0;
        // The core pattern with anchors stripped, for the substring oracle
        // (full_match is implicitly ^...$, so anchors are positional
        // constraints handled here, not in the machine).
        std::string core = pat;
        if (anch_start) core.erase(0, 1);
        if (anch_end) core.pop_back();
        ThompsonNFA oracle_nfa(core);
        for (const char* inp : inputs) {
            std::string_view in = inp;
            const long n = static_cast<long>(in.size());
            for (long from = 0; from <= n; ++from) {
                // Oracle: scan starts, then ends, via full_match.
                long os = -1, oe = -1;
                for (long st = from; st <= n && os < 0; ++st) {
                    if (anch_start && st != 0) break;
                    for (long en = n; en >= st; --en) {
                        if (anch_end && en != n) break;
                        if (sublimation_nfa_full_match(&oracle_nfa.nfa_,
                                                       in.data() + st,
                                                       static_cast<size_t>(en - st))) {
                            os = st;
                            oe = en;
                            break;
                        }
                    }
                }
                long ge = -1;
                long gs = sublimation_nfa_find_from(
                    &nfa.nfa_, in.data(), in.size(),
                    static_cast<size_t>(from), &ge);
                ASSERT_EQ(gs, os);
                if (os >= 0) ASSERT_EQ(ge, oe);
            }
        }
    }
}

// ESCAPES

TEST(nfa_escape_bracket) {
    ThompsonNFA nfa("\\[test\\]");
    ASSERT_TRUE(nfa.full_match("[test]"));
    ASSERT_TRUE(!nfa.full_match("test"));
}

TEST(nfa_escape_dot) {
    ThompsonNFA nfa("a\\.b");
    ASSERT_TRUE(nfa.full_match("a.b"));
    ASSERT_TRUE(!nfa.full_match("axb"));
}

TEST(nfa_escape_backslash) {
    ThompsonNFA nfa("a\\\\b");
    ASSERT_TRUE(nfa.full_match("a\\b"));
}

TEST(nfa_escape_star) {
    ThompsonNFA nfa("a\\*b");
    ASSERT_TRUE(nfa.full_match("a*b"));
    ASSERT_TRUE(!nfa.full_match("ab"));
    ASSERT_TRUE(!nfa.full_match("aab"));
}

// EDGE CASES

TEST(nfa_empty_pattern) {
    ThompsonNFA nfa("");
    ASSERT_TRUE(!nfa.valid());
}

TEST(nfa_empty_input_no_match) {
    ThompsonNFA nfa("a");
    ASSERT_TRUE(!nfa.full_match(""));
}

TEST(nfa_star_matches_empty) {
    ThompsonNFA nfa("a*");
    ASSERT_TRUE(nfa.full_match(""));
    ASSERT_TRUE(nfa.full_match("a"));
    ASSERT_TRUE(nfa.full_match("aaa"));
}

TEST(nfa_mismatched_parens) {
    ThompsonNFA nfa1("(abc");
    ASSERT_TRUE(!nfa1.valid());
    ThompsonNFA nfa2("abc)");
    ASSERT_TRUE(!nfa2.valid());
}

// KERNEL THREAD PATTERN (montauk integration)

TEST(nfa_kernel_thread_pattern) {
    ThompsonNFA nfa("^\\[.+\\]$");
    ASSERT_TRUE(nfa.valid());
    ASSERT_TRUE(nfa.full_match("[kworker/0:0]"));
    ASSERT_TRUE(nfa.full_match("[migration/1]"));
    ASSERT_TRUE(nfa.full_match("[ksoftirqd/0]"));
    ASSERT_TRUE(nfa.full_match("[rcu_preempt]"));
    // Not kernel threads
    ASSERT_TRUE(!nfa.full_match("firefox"));
    ASSERT_TRUE(!nfa.full_match("/usr/bin/bash"));
    ASSERT_TRUE(!nfa.full_match("[]"));  // .+ requires at least one char
    ASSERT_TRUE(!nfa.full_match("["));
    ASSERT_TRUE(!nfa.full_match("]"));
}

TEST(nfa_kernel_thread_find) {
    ThompsonNFA nfa("^\\[.+\\]$");
    auto [s1, e1] = nfa.find("[kworker/u64:0]");
    ASSERT_EQ(s1, 0);
    ASSERT_EQ(e1, 15);
    auto [s2, e2] = nfa.find("not a kernel thread");
    ASSERT_EQ(s2, -1);
}

// UTF-8: LITERAL MULTI-BYTE

TEST(nfa_utf8_literal) {
    ThompsonNFA nfa("café");
    ASSERT_TRUE(nfa.valid());
    ASSERT_TRUE(nfa.full_match("café"));
    ASSERT_TRUE(!nfa.full_match("cafe"));
    ASSERT_TRUE(!nfa.full_match("cafë"));
}

TEST(nfa_utf8_literal_3byte) {
    // 世 = U+4E16, 3-byte UTF-8
    ThompsonNFA nfa("世界");
    ASSERT_TRUE(nfa.valid());
    ASSERT_TRUE(nfa.full_match("世界"));
    ASSERT_TRUE(!nfa.full_match("世"));
}

TEST(nfa_utf8_find) {
    ThompsonNFA nfa("café");
    auto [s, e] = nfa.find("I love café latte");
    ASSERT_EQ(s, 7);
    ASSERT_EQ(e, 12);  // "café" is 5 bytes (c=1, a=1, f=1, é=2)
}

// UTF-8: DOT MATCHES CODEPOINT

TEST(nfa_utf8_dot_codepoint) {
    // "é" is 2 bytes but 1 codepoint. Dot should match it as 1 codepoint.
    ThompsonNFA nfa("^.x$");
    ASSERT_TRUE(nfa.valid());
    ASSERT_TRUE(nfa.full_match("ax"));    // ASCII: 1 byte, 1 codepoint
    ASSERT_TRUE(nfa.full_match("\xC3\xA9x"));  // é + x: 2 codepoints
}

TEST(nfa_utf8_dot_two_codepoints) {
    ThompsonNFA nfa("^..$");
    ASSERT_TRUE(nfa.full_match("ab"));              // 2 ASCII codepoints
    ASSERT_TRUE(nfa.full_match("\xC3\xA9x"));       // é(2 bytes) + x(1 byte) = 2 codepoints
    ASSERT_TRUE(nfa.full_match("\xC3\xA9\xC3\xA8")); // é + è = 2 codepoints (4 bytes)
    ASSERT_TRUE(!nfa.full_match("a"));              // 1 codepoint
    ASSERT_TRUE(!nfa.full_match("abc"));            // 3 codepoints
}

TEST(nfa_utf8_dot_3byte) {
    // 世 = U+4E16 = 3 bytes. Dot should match it as 1 codepoint.
    ThompsonNFA nfa("^.$");
    ASSERT_TRUE(nfa.full_match("a"));               // 1-byte codepoint
    ASSERT_TRUE(nfa.full_match("\xC3\xA9"));        // 2-byte codepoint (é)
    ASSERT_TRUE(nfa.full_match("\xE4\xB8\x96"));    // 3-byte codepoint (世)
}

// UTF-8: CHARACTER CLASSES WITH CODEPOINT RANGES

TEST(nfa_utf8_class_ascii_only) {
    // Pure ASCII class -- should work like byte-level
    ThompsonNFA nfa("[a-z]+");
    ASSERT_TRUE(nfa.full_match("hello"));
    ASSERT_TRUE(!nfa.full_match("Hello"));
}

TEST(nfa_utf8_class_2byte_range) {
    // [à-ÿ] = U+00E0 to U+00FF -- all 2-byte UTF-8 with lead byte 0xC3
    ThompsonNFA nfa("[à-ÿ]");
    ASSERT_TRUE(nfa.valid());
    ASSERT_TRUE(nfa.full_match("é"));   // U+00E9, in range
    ASSERT_TRUE(nfa.full_match("à"));   // U+00E0, range start
    ASSERT_TRUE(nfa.full_match("ÿ"));   // U+00FF, range end
    ASSERT_TRUE(!nfa.full_match("a"));  // ASCII, not in range
}

TEST(nfa_utf8_class_cross_boundary) {
    // [A-é] = U+0041 to U+00E9 -- spans ASCII and 2-byte UTF-8
    ThompsonNFA nfa("[A-é]");
    ASSERT_TRUE(nfa.valid());
    ASSERT_TRUE(nfa.full_match("A"));   // U+0041, ASCII
    ASSERT_TRUE(nfa.full_match("Z"));   // U+005A, ASCII
    ASSERT_TRUE(nfa.full_match("z"));   // U+007A, ASCII
    ASSERT_TRUE(nfa.full_match("é"));   // U+00E9, 2-byte
    ASSERT_TRUE(!nfa.full_match("ÿ"));  // U+00FF, above range
}

TEST(nfa_utf8_class_negated) {
    // [^à-ÿ] should match things NOT in the range
    ThompsonNFA nfa("[^à-ÿ]");
    ASSERT_TRUE(nfa.valid());
    ASSERT_TRUE(nfa.full_match("a"));   // ASCII, not in range
    ASSERT_TRUE(nfa.full_match("Z"));   // ASCII, not in range
    // Note: negated multi-byte classes only negate the ASCII portion currently
}
