#include "util/ThompsonNFA.hpp"
#include <algorithm>
#include <cstring>

namespace montauk::util {

// ── UTF-8 helpers ──────────────────────────────────────────────────────

// Decode one UTF-8 codepoint from pattern. Returns bytes consumed (0 on error).
static int decode_utf8(const char* s, size_t len, uint32_t* cp) {
    if (len == 0) return 0;
    auto c = (uint8_t)s[0];
    if (c < 0x80)        { *cp = c; return 1; }
    if ((c & 0xE0) == 0xC0 && len >= 2) {
        *cp = ((uint32_t)(c & 0x1F) << 6) | (s[1] & 0x3F);
        return (*cp >= 0x80) ? 2 : 0;
    }
    if ((c & 0xF0) == 0xE0 && len >= 3) {
        *cp = ((uint32_t)(c & 0x0F) << 12) | ((uint32_t)(s[1] & 0x3F) << 6) | (s[2] & 0x3F);
        return (*cp >= 0x800) ? 3 : 0;
    }
    if ((c & 0xF8) == 0xF0 && len >= 4) {
        *cp = ((uint32_t)(c & 0x07) << 18) | ((uint32_t)(s[1] & 0x3F) << 12)
            | ((uint32_t)(s[2] & 0x3F) << 6) | (s[3] & 0x3F);
        return (*cp >= 0x10000 && *cp <= 0x10FFFF) ? 4 : 0;
    }
    return 0;
}

// Encode one codepoint to UTF-8 bytes. Returns byte count.
static int encode_utf8(uint32_t cp, uint8_t out[4]) {
    if (cp < 0x80)    { out[0] = (uint8_t)cp; return 1; }
    if (cp < 0x800)   { out[0] = 0xC0 | (cp >> 6); out[1] = 0x80 | (cp & 0x3F); return 2; }
    if (cp < 0x10000) { out[0] = 0xE0 | (cp >> 12); out[1] = 0x80 | ((cp >> 6) & 0x3F);
                        out[2] = 0x80 | (cp & 0x3F); return 3; }
    out[0] = 0xF0 | (cp >> 18); out[1] = 0x80 | ((cp >> 12) & 0x3F);
    out[2] = 0x80 | ((cp >> 6) & 0x3F); out[3] = 0x80 | (cp & 0x3F);
    return 4;
}

// ── Parser tokens ──────────────────────────────────────────────────────

enum class TokType : uint8_t {
    LITERAL,    // codepoint literal
    DOT,        // .
    STAR, PLUS, QUES,  // * + ?
    PIPE,       // |
    LPAREN, RPAREN,
    ANCHOR_S, ANCHOR_E,  // ^ $
    CLASS,      // character class (index into a class list)
    CONCAT,     // explicit concatenation (inserted during processing)
};

struct CpRange { uint32_t lo, hi; };

struct Token {
    TokType type;
    uint32_t cp;         // LITERAL: codepoint value
    uint8_t  class_idx;  // CLASS: index
    bool     negated;    // CLASS: negated?
};

// ── NFA construction helpers ───────────────────────────────────────────

int ThompsonNFA::add_state(Op op, int16_t out, int16_t out1) {
    if ((int)states_.size() >= MAX_STATES) return -1;
    State s{};
    s.op = op; s.out = out; s.out1 = out1;
    states_.push_back(s);
    return (int)states_.size() - 1;
}

int ThompsonNFA::add_char_state(uint8_t ch, int16_t out) {
    int s = add_state(Op::CHAR, out);
    if (s >= 0) states_[s].ch = ch;
    return s;
}

int ThompsonNFA::add_class_state(uint8_t class_idx, bool negated, int16_t out) {
    int s = add_state(Op::CLASS, out);
    if (s >= 0) { states_[s].class_idx = class_idx; states_[s].negated = negated; }
    return s;
}

// NFA fragment: a start state and a list of dangling output pointers.
// Outputs are stored as (state_index, which_out) pairs.
struct Frag {
    int start;
    struct Patch { int16_t state; bool is_out1; };
    std::vector<Patch> outs;
};

static Frag make_frag(int start, std::vector<Frag::Patch> outs) {
    return {start, std::move(outs)};
}

// Patch all dangling outputs to point to a target state.
static void patch(std::vector<ThompsonNFA::State>& states, const std::vector<Frag::Patch>& outs, int target) {
    for (auto& p : outs) {
        if (p.is_out1)
            states[p.state].out1 = (int16_t)target;
        else
            states[p.state].out = (int16_t)target;
    }
}

// ── Compile ────────────────────────────────────────────────────────────

bool ThompsonNFA::compile(std::string_view pattern) {
    // Phase 1: Parse pattern into codepoint-level tokens
    std::vector<Token> tokens;
    std::vector<std::vector<CpRange>> class_ranges;  // parallel to CLASS tokens

    const char* p = pattern.data();
    const char* end = p + pattern.size();

    // Handle anchors
    if (p < end && *p == '^') { anchored_start_ = true; ++p; }

    // Check for trailing $ (but not \$)
    if (pattern.size() >= 1 && pattern.back() == '$') {
        // Check it's not escaped
        int backslashes = 0;
        for (int i = (int)pattern.size() - 2; i >= 0 && pattern[i] == '\\'; --i)
            ++backslashes;
        if (backslashes % 2 == 0) {
            anchored_end_ = true;
            end--;  // exclude $ from further parsing
        }
    }

    while (p < end) {
        uint8_t c = (uint8_t)*p;

        if (c == '\\' && p + 1 < end) {
            // Escape: next char is literal
            ++p;
            uint32_t cp;
            int n = decode_utf8(p, (size_t)(end - p), &cp);
            if (n == 0) return false;
            tokens.push_back({TokType::LITERAL, cp, 0, false});
            p += n;
        } else if (c == '.') {
            tokens.push_back({TokType::DOT, 0, 0, false});
            ++p;
        } else if (c == '*') {
            tokens.push_back({TokType::STAR, 0, 0, false});
            ++p;
        } else if (c == '+') {
            tokens.push_back({TokType::PLUS, 0, 0, false});
            ++p;
        } else if (c == '?') {
            tokens.push_back({TokType::QUES, 0, 0, false});
            ++p;
        } else if (c == '|') {
            tokens.push_back({TokType::PIPE, 0, 0, false});
            ++p;
        } else if (c == '(') {
            tokens.push_back({TokType::LPAREN, 0, 0, false});
            ++p;
        } else if (c == ')') {
            tokens.push_back({TokType::RPAREN, 0, 0, false});
            ++p;
        } else if (c == '[') {
            // Character class
            ++p;
            bool neg = false;
            if (p < end && *p == '^') { neg = true; ++p; }
            std::vector<CpRange> ranges;
            bool first = true;
            while (p < end && (*p != ']' || first)) {
                first = false;
                uint32_t lo;
                if (*p == '\\' && p + 1 < end) {
                    ++p;
                    int n = decode_utf8(p, (size_t)(end - p), &lo);
                    if (n == 0) return false;
                    p += n;
                } else {
                    int n = decode_utf8(p, (size_t)(end - p), &lo);
                    if (n == 0) return false;
                    p += n;
                }
                // Check for range: lo-hi
                if (p + 1 < end && *p == '-' && *(p+1) != ']') {
                    ++p; // skip '-'
                    uint32_t hi;
                    if (*p == '\\' && p + 1 < end) {
                        ++p;
                        int n = decode_utf8(p, (size_t)(end - p), &hi);
                        if (n == 0) return false;
                        p += n;
                    } else {
                        int n = decode_utf8(p, (size_t)(end - p), &hi);
                        if (n == 0) return false;
                        p += n;
                    }
                    if (hi < lo) { auto t = lo; lo = hi; hi = t; }
                    ranges.push_back({lo, hi});
                } else {
                    ranges.push_back({lo, lo});
                }
            }
            if (p < end && *p == ']') ++p; else return false;
            uint8_t cidx = (uint8_t)class_ranges.size();
            class_ranges.push_back(std::move(ranges));
            tokens.push_back({TokType::CLASS, 0, cidx, neg});
        } else {
            // Literal codepoint (possibly multi-byte UTF-8)
            uint32_t cp;
            int n = decode_utf8(p, (size_t)(end - p), &cp);
            if (n == 0) return false;
            tokens.push_back({TokType::LITERAL, cp, 0, false});
            p += n;
        }
    }

    if (tokens.empty() && !anchored_start_ && !anchored_end_) return false;

    // Phase 2: Insert explicit CONCAT tokens
    std::vector<Token> with_concat;
    for (size_t i = 0; i < tokens.size(); ++i) {
        with_concat.push_back(tokens[i]);
        if (i + 1 < tokens.size()) {
            auto& a = tokens[i];
            auto& b = tokens[i+1];
            // Insert concat between two atoms, or after a quantifier/rparen before an atom
            bool a_produces = (a.type == TokType::LITERAL || a.type == TokType::DOT
                            || a.type == TokType::CLASS || a.type == TokType::RPAREN
                            || a.type == TokType::STAR || a.type == TokType::PLUS
                            || a.type == TokType::QUES);
            bool b_consumes = (b.type == TokType::LITERAL || b.type == TokType::DOT
                            || b.type == TokType::CLASS || b.type == TokType::LPAREN);
            if (a_produces && b_consumes)
                with_concat.push_back({TokType::CONCAT, 0, 0, false});
        }
    }

    // Phase 3: Shunting-yard → postfix
    // Precedence: CONCAT=3, PIPE=2 (left-assoc)
    std::vector<Token> postfix;
    std::vector<Token> opstack;

    auto prec = [](TokType t) -> int {
        switch (t) {
            case TokType::PIPE:   return 2;
            case TokType::CONCAT: return 3;
            default: return 0;
        }
    };

    for (auto& tok : with_concat) {
        switch (tok.type) {
            case TokType::LITERAL:
            case TokType::DOT:
            case TokType::CLASS:
                postfix.push_back(tok);
                break;
            case TokType::STAR:
            case TokType::PLUS:
            case TokType::QUES:
                // Unary postfix -- goes directly to output
                postfix.push_back(tok);
                break;
            case TokType::LPAREN:
                opstack.push_back(tok);
                break;
            case TokType::RPAREN:
                while (!opstack.empty() && opstack.back().type != TokType::LPAREN) {
                    postfix.push_back(opstack.back());
                    opstack.pop_back();
                }
                if (opstack.empty()) return false; // mismatched parens
                opstack.pop_back(); // pop LPAREN
                break;
            case TokType::CONCAT:
            case TokType::PIPE: {
                int p1 = prec(tok.type);
                while (!opstack.empty() && opstack.back().type != TokType::LPAREN
                       && prec(opstack.back().type) >= p1) {
                    postfix.push_back(opstack.back());
                    opstack.pop_back();
                }
                opstack.push_back(tok);
                break;
            }
            default:
                break;
        }
    }
    while (!opstack.empty()) {
        if (opstack.back().type == TokType::LPAREN) return false; // mismatched
        postfix.push_back(opstack.back());
        opstack.pop_back();
    }

    if (postfix.empty()) {
        // Anchored empty pattern like ^$ -- match empty string
        start_ = add_state(Op::MATCH);
        return start_ >= 0;
    }

    // Phase 4: Lower codepoint tokens to byte-level NFA fragments
    // Build NFA fragments from postfix tokens using a stack.
    std::vector<Frag> fstack;

    // Helper: build a fragment that matches a single codepoint (1-4 byte sequence)
    auto make_codepoint_frag = [&](uint32_t cp) -> Frag {
        uint8_t buf[4];
        int n = encode_utf8(cp, buf);
        // Chain of CHAR states
        int first = add_char_state(buf[0]);
        if (first < 0) return {-1, {}};
        int prev = first;
        for (int i = 1; i < n; ++i) {
            int s = add_char_state(buf[i]);
            if (s < 0) return {-1, {}};
            states_[prev].out = (int16_t)s;
            prev = s;
        }
        return make_frag(first, {{(int16_t)prev, false}});
    };

    // Helper: build a fragment that matches any single UTF-8 codepoint (dot lowering)
    auto make_dot_frag = [&]() -> Frag {
        // Branch 1: ASCII [\x00-\x7F] (excluding \n for dot)
        uint8_t ci_ascii = (uint8_t)classes_.size();
        classes_.push_back({});
        classes_.back().clear();
        for (int c = 0; c < 0x80; ++c) {
            if (c != '\n') classes_.back().set((uint8_t)c);
        }
        int s_ascii = add_class_state(ci_ascii, false);

        // Branch 2: 2-byte [\xC2-\xDF][\x80-\xBF]
        uint8_t ci_lead2 = (uint8_t)classes_.size();
        classes_.push_back({});
        classes_.back().clear();
        classes_.back().set_range(0xC2, 0xDF);
        uint8_t ci_cont = (uint8_t)classes_.size();
        classes_.push_back({});
        classes_.back().clear();
        classes_.back().set_range(0x80, 0xBF);
        int s_cont2 = add_class_state(ci_cont, false);
        int s_lead2 = add_class_state(ci_lead2, false, (int16_t)s_cont2);

        // Branch 3: 3-byte [\xE0-\xEF][\x80-\xBF][\x80-\xBF]
        uint8_t ci_lead3 = (uint8_t)classes_.size();
        classes_.push_back({});
        classes_.back().clear();
        classes_.back().set_range(0xE0, 0xEF);
        // Reuse ci_cont for continuation bytes
        int s_cont3b = add_class_state(ci_cont, false);
        int s_cont3a = add_class_state(ci_cont, false, (int16_t)s_cont3b);
        int s_lead3 = add_class_state(ci_lead3, false, (int16_t)s_cont3a);

        // Branch 4: 4-byte [\xF0-\xF4][\x80-\xBF][\x80-\xBF][\x80-\xBF]
        uint8_t ci_lead4 = (uint8_t)classes_.size();
        classes_.push_back({});
        classes_.back().clear();
        classes_.back().set_range(0xF0, 0xF4);
        int s_cont4c = add_class_state(ci_cont, false);
        int s_cont4b = add_class_state(ci_cont, false, (int16_t)s_cont4c);
        int s_cont4a = add_class_state(ci_cont, false, (int16_t)s_cont4b);
        int s_lead4 = add_class_state(ci_lead4, false, (int16_t)s_cont4a);

        if (s_ascii < 0 || s_lead2 < 0 || s_lead3 < 0 || s_lead4 < 0) return {-1, {}};

        // Build SPLIT tree: split(ascii, split(2byte, split(3byte, 4byte)))
        int sp3 = add_state(Op::SPLIT, (int16_t)s_lead3, (int16_t)s_lead4);
        int sp2 = add_state(Op::SPLIT, (int16_t)s_lead2, (int16_t)sp3);
        int sp1 = add_state(Op::SPLIT, (int16_t)s_ascii, (int16_t)sp2);

        if (sp1 < 0) return {-1, {}};

        // Collect dangling outputs from leaf states
        return make_frag(sp1, {
            {(int16_t)s_ascii, false},
            {(int16_t)s_cont2, false},
            {(int16_t)s_cont3b, false},
            {(int16_t)s_cont4c, false}
        });
    };

    // Compute complement ranges over [0, cap] for negated classes
    auto complement_ranges = [](const std::vector<CpRange>& ranges, uint32_t cap) -> std::vector<CpRange> {
        // Sort ranges by lo
        auto sorted = ranges;
        std::sort(sorted.begin(), sorted.end(), [](auto& a, auto& b) { return a.lo < b.lo; });
        // Merge overlapping ranges
        std::vector<CpRange> merged;
        for (auto& r : sorted) {
            if (!merged.empty() && r.lo <= merged.back().hi + 1)
                merged.back().hi = std::max(merged.back().hi, r.hi);
            else
                merged.push_back(r);
        }
        // Compute complement
        std::vector<CpRange> result;
        uint32_t cursor = 0;
        for (auto& r : merged) {
            if (r.lo > cursor)
                result.push_back({cursor, r.lo - 1});
            cursor = r.hi + 1;
        }
        if (cursor <= cap)
            result.push_back({cursor, cap});
        return result;
    };

    // Helper: build a fragment for a character class with codepoint ranges
    // For negated classes, caller must compute complement ranges first.
    auto make_class_frag = [&](const std::vector<CpRange>& ranges) -> Frag {
        // Check if all ranges are ASCII-only (simple case)
        bool all_ascii = true;
        for (auto& r : ranges) {
            if (r.hi >= 0x80) { all_ascii = false; break; }
        }

        if (all_ascii) {
            // Simple byte-level class
            uint8_t ci = (uint8_t)classes_.size();
            classes_.push_back({});
            classes_.back().clear();
            for (auto& r : ranges)
                for (uint32_t c = r.lo; c <= r.hi; ++c)
                    classes_.back().set((uint8_t)c);
            int s = add_class_state(ci, false);
            if (s < 0) return {-1, {}};
            return make_frag(s, {{(int16_t)s, false}});
        }

        // Multi-byte: build alternation of byte sequences for each range.
        std::vector<Frag> branches;

        // Separate ASCII vs multi-byte ranges
        CharClass ascii_cls{};
        ascii_cls.clear();
        bool has_ascii = false;

        for (auto& r : ranges) {
            // ASCII portion
            uint32_t alo = r.lo, ahi = std::min(r.hi, (uint32_t)0x7F);
            if (alo <= 0x7F) {
                has_ascii = true;
                for (uint32_t c = alo; c <= ahi; ++c)
                    ascii_cls.set((uint8_t)c);
            }

            // 2-byte portion (0x80..0x7FF)
            uint32_t blo = std::max(r.lo, (uint32_t)0x80);
            uint32_t bhi = std::min(r.hi, (uint32_t)0x7FF);
            if (blo <= bhi) {
                // Build byte-level class for this range
                // Group by lead byte
                for (uint32_t lead_cp = blo; lead_cp <= bhi; ) {
                    uint8_t lead = 0xC0 | (lead_cp >> 6);
                    uint32_t group_end = std::min(bhi, (uint32_t)(((lead_cp >> 6) + 1) << 6) - 1);
                    uint8_t tlo = 0x80 | (lead_cp & 0x3F);
                    uint8_t thi = 0x80 | (group_end & 0x3F);
                    // CHAR(lead) · CLASS([tlo-thi])
                    uint8_t ci = (uint8_t)classes_.size();
                    classes_.push_back({});
                    classes_.back().clear();
                    classes_.back().set_range(tlo, thi);
                    int s_trail = add_class_state(ci, false);
                    int s_lead = add_char_state(lead, (int16_t)s_trail);
                    if (s_lead < 0 || s_trail < 0) return {-1, {}};
                    branches.push_back(make_frag(s_lead, {{(int16_t)s_trail, false}}));
                    lead_cp = group_end + 1;
                }
            }

            // 3-byte portion (0x800..0xFFFF)
            uint32_t clo = std::max(r.lo, (uint32_t)0x800);
            uint32_t chi = std::min(r.hi, (uint32_t)0xFFFF);
            if (clo <= chi) {
                // Group by first two lead bytes
                for (uint32_t cp = clo; cp <= chi; ) {
                    uint8_t b0 = 0xE0 | (cp >> 12);
                    uint8_t b1_base = (cp >> 6) & 0x3F;
                    // Find end of group sharing same b0 and b1
                    uint32_t group_end_b1 = std::min(chi, (uint32_t)((((cp >> 6) + 1) << 6) - 1));
                    uint32_t group_end_b0 = std::min(chi, (uint32_t)((((cp >> 12) + 1) << 12) - 1));

                    // If the group spans multiple b1 values, handle per-b1
                    if (group_end_b1 < group_end_b0) {
                        // Just the current b1 group
                        uint8_t tlo = 0x80 | (cp & 0x3F);
                        uint8_t thi = 0x80 | (group_end_b1 & 0x3F);
                        uint8_t ci = (uint8_t)classes_.size();
                        classes_.push_back({});
                        classes_.back().clear();
                        classes_.back().set_range(tlo, thi);
                        int s2 = add_class_state(ci, false);
                        int s1 = add_char_state(0x80 | b1_base, (int16_t)s2);
                        int s0 = add_char_state(b0, (int16_t)s1);
                        if (s0 < 0) return {-1, {}};
                        branches.push_back(make_frag(s0, {{(int16_t)s2, false}}));
                        cp = group_end_b1 + 1;
                    } else {
                        // Entire b0 group with same lead
                        uint8_t tlo = 0x80 | (cp & 0x3F);
                        uint8_t thi = 0x80 | (group_end_b0 & 0x3F);
                        // b1 range
                        uint8_t b1lo = 0x80 | ((cp >> 6) & 0x3F);
                        uint8_t b1hi = 0x80 | ((group_end_b0 >> 6) & 0x3F);
                        uint8_t ci_b1 = (uint8_t)classes_.size();
                        classes_.push_back({});
                        classes_.back().clear();
                        classes_.back().set_range(b1lo, b1hi);
                        uint8_t ci_b2 = (uint8_t)classes_.size();
                        classes_.push_back({});
                        classes_.back().clear();
                        classes_.back().set_range(tlo, thi);
                        int s2 = add_class_state(ci_b2, false);
                        int s1 = add_class_state(ci_b1, false, (int16_t)s2);
                        int s0 = add_char_state(b0, (int16_t)s1);
                        if (s0 < 0) return {-1, {}};
                        branches.push_back(make_frag(s0, {{(int16_t)s2, false}}));
                        cp = group_end_b0 + 1;
                    }
                }
            }

            // 4-byte: same approach (rare, skip for now -- can add when needed)
        }

        if (has_ascii) {
            uint8_t ci = (uint8_t)classes_.size();
            classes_.push_back(ascii_cls);
            int s = add_class_state(ci, false);
            if (s < 0) return {-1, {}};
            // Insert at front so ASCII branch is checked first
            branches.insert(branches.begin(), make_frag(s, {{(int16_t)s, false}}));
        }

        if (branches.empty()) return {-1, {}};
        if (branches.size() == 1) return branches[0];

        // Build alternation tree from branches
        Frag result = branches.back();
        for (int i = (int)branches.size() - 2; i >= 0; --i) {
            int sp = add_state(Op::SPLIT, (int16_t)branches[i].start, (int16_t)result.start);
            if (sp < 0) return {-1, {}};
            auto outs = branches[i].outs;
            outs.insert(outs.end(), result.outs.begin(), result.outs.end());
            result = make_frag(sp, std::move(outs));
        }

        return result;
    };

    for (auto& tok : postfix) {
        switch (tok.type) {
            case TokType::LITERAL: {
                auto f = make_codepoint_frag(tok.cp);
                if (f.start < 0) return false;
                fstack.push_back(std::move(f));
                break;
            }
            case TokType::DOT: {
                auto f = make_dot_frag();
                if (f.start < 0) return false;
                fstack.push_back(std::move(f));
                break;
            }
            case TokType::CLASS: {
                auto& cr = class_ranges[tok.class_idx];
                Frag f;
                if (tok.negated) {
                    // For ASCII-only negated classes, use runtime negation
                    // (avoids exploding complement into multi-byte ranges)
                    bool all_ascii = true;
                    for (auto& r : cr)
                        if (r.hi >= 0x80) { all_ascii = false; break; }
                    if (all_ascii) {
                        uint8_t ci = (uint8_t)classes_.size();
                        classes_.push_back({});
                        classes_.back().clear();
                        for (auto& r : cr)
                            for (uint32_t c = r.lo; c <= r.hi; ++c)
                                classes_.back().set((uint8_t)c);
                        int s = add_class_state(ci, true);
                        if (s < 0) return false;
                        f = make_frag(s, {{(int16_t)s, false}});
                    } else {
                        // Multi-byte: complement capped at 0x7FF to stay within state budget
                        auto comp = complement_ranges(cr, 0x7FF);
                        f = make_class_frag(comp);
                    }
                } else {
                    f = make_class_frag(cr);
                }
                if (f.start < 0) return false;
                fstack.push_back(std::move(f));
                break;
            }
            case TokType::CONCAT: {
                if (fstack.size() < 2) return false;
                auto f2 = std::move(fstack.back()); fstack.pop_back();
                auto f1 = std::move(fstack.back()); fstack.pop_back();
                patch(states_, f1.outs, f2.start);
                fstack.push_back(make_frag(f1.start, std::move(f2.outs)));
                break;
            }
            case TokType::PIPE: {
                if (fstack.size() < 2) return false;
                auto f2 = std::move(fstack.back()); fstack.pop_back();
                auto f1 = std::move(fstack.back()); fstack.pop_back();
                int sp = add_state(Op::SPLIT, (int16_t)f1.start, (int16_t)f2.start);
                if (sp < 0) return false;
                auto outs = std::move(f1.outs);
                outs.insert(outs.end(), f2.outs.begin(), f2.outs.end());
                fstack.push_back(make_frag(sp, std::move(outs)));
                break;
            }
            case TokType::STAR: {
                if (fstack.empty()) return false;
                auto f = std::move(fstack.back()); fstack.pop_back();
                int sp = add_state(Op::SPLIT, (int16_t)f.start);
                if (sp < 0) return false;
                patch(states_, f.outs, sp);
                fstack.push_back(make_frag(sp, {{(int16_t)sp, true}}));
                break;
            }
            case TokType::PLUS: {
                if (fstack.empty()) return false;
                auto f = std::move(fstack.back()); fstack.pop_back();
                int sp = add_state(Op::SPLIT, (int16_t)f.start);
                if (sp < 0) return false;
                patch(states_, f.outs, sp);
                fstack.push_back(make_frag(f.start, {{(int16_t)sp, true}}));
                break;
            }
            case TokType::QUES: {
                if (fstack.empty()) return false;
                auto f = std::move(fstack.back()); fstack.pop_back();
                int sp = add_state(Op::SPLIT, (int16_t)f.start);
                if (sp < 0) return false;
                auto outs = std::move(f.outs);
                outs.push_back({(int16_t)sp, true});
                fstack.push_back(make_frag(sp, std::move(outs)));
                break;
            }
            default:
                break;
        }
    }

    if (fstack.size() != 1) return false;

    // Patch final outputs to MATCH state
    int match = add_state(Op::MATCH);
    if (match < 0) return false;
    patch(states_, fstack[0].outs, match);
    start_ = fstack[0].start;
    return true;
}

// ── Constructor ────────────────────────────────────────────────────────

ThompsonNFA::ThompsonNFA(std::string_view pattern) {
    states_.reserve(64);
    valid_ = compile(pattern);
}

// ── Simulation ─────────────────────────────────────────────────────────

void ThompsonNFA::eps_closure(uint64_t* set, int s) const {
    if (s < 0 || s >= (int)states_.size()) return;
    if (test_bit(set, s)) return;
    set_bit(set, s);
    if (states_[s].op == Op::SPLIT) {
        eps_closure(set, states_[s].out);
        eps_closure(set, states_[s].out1);
    }
}

void ThompsonNFA::step(const uint64_t* cur, uint64_t* next, uint8_t byte) const {
    clear_set(next);
    for (int i = 0; i < (int)states_.size(); ++i) {
        if (!test_bit(cur, i)) continue;
        auto& st = states_[i];
        bool matched = false;
        switch (st.op) {
            case Op::CHAR:
                matched = (byte == st.ch);
                break;
            case Op::CLASS:
                if (st.negated)
                    matched = !classes_[st.class_idx].test(byte);
                else
                    matched = classes_[st.class_idx].test(byte);
                break;
            default:
                break;
        }
        if (matched && st.out >= 0)
            eps_closure(next, st.out);
    }
}

bool ThompsonNFA::has_match(const uint64_t* set) const {
    for (int i = 0; i < (int)states_.size(); ++i) {
        if (test_bit(set, i) && states_[i].op == Op::MATCH)
            return true;
    }
    return false;
}

bool ThompsonNFA::full_match(std::string_view input) const {
    if (!valid_) return false;

    uint64_t cur[SETWORDS], next[SETWORDS];
    clear_set(cur);
    eps_closure(cur, start_);

    for (size_t i = 0; i < input.size(); ++i) {
        step(cur, next, (uint8_t)input[i]);
        if (empty_set(next)) return false;
        std::memcpy(cur, next, sizeof(cur));
    }

    return has_match(cur);
}

std::pair<int,int> ThompsonNFA::find(std::string_view input) const {
    if (!valid_) return {-1, -1};

    int best_start = -1, best_end = -1;
    int start_limit = anchored_start_ ? 1 : (int)input.size() + 1;

    for (int start = 0; start < start_limit; ++start) {
        uint64_t cur[SETWORDS], next[SETWORDS];
        clear_set(cur);
        eps_closure(cur, start_);

        // Check for zero-length match at start position
        if (has_match(cur)) {
            if (!anchored_end_ || start == (int)input.size()) {
                if (best_start < 0) {
                    best_start = start;
                    best_end = start;
                }
            }
        }

        for (int i = start; i < (int)input.size(); ++i) {
            step(cur, next, (uint8_t)input[i]);
            if (empty_set(next)) break;
            std::memcpy(cur, next, sizeof(cur));

            if (has_match(cur)) {
                if (!anchored_end_ || i + 1 == (int)input.size()) {
                    if (best_start < 0 || start < best_start
                        || (start == best_start && i + 1 > best_end)) {
                        best_start = start;
                        best_end = i + 1;
                    }
                }
            }
        }

        // If we found a match at this start position, return it (leftmost)
        if (best_start == start) return {best_start, best_end};
    }

    return {best_start, best_end};
}

} // namespace montauk::util
