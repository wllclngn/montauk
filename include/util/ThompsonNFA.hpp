#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace montauk::util {

// Thompson NFA regex engine.
// Byte-level simulator with UTF-8-aware compiler.
// Supports: . [] [^] [a-z] * + ? | () ^ $ \ (escape)
// Zero heap allocation during simulation (uint64_t[4] bitset).
// O(nm) guaranteed -- no backtracking.
class ThompsonNFA {
public:
    explicit ThompsonNFA(std::string_view pattern);

    // Did the pattern compile successfully?
    [[nodiscard]] bool valid() const { return valid_; }

    // Does the entire input match the pattern? (implicitly anchored ^...$)
    [[nodiscard]] bool full_match(std::string_view input) const;

    // Find first match in input. Returns {start, end} (end exclusive), or {-1,-1}.
    [[nodiscard]] std::pair<int,int> find(std::string_view input) const;

    static constexpr int MAX_STATES = 256;
    static constexpr int SETWORDS = MAX_STATES / 64;  // 4

    enum class Op : uint8_t { CHAR, CLASS, SPLIT, MATCH };

    struct State {
        Op       op;
        uint8_t  ch;          // CHAR: byte to match
        uint8_t  class_idx;   // CLASS: index into classes_
        bool     negated;     // CLASS: negated?
        int16_t  out;         // next state (-1 = none)
        int16_t  out1;        // SPLIT: second epsilon target (-1 = none)
    };

    struct CharClass {
        uint8_t bits[32];     // 256-bit bitmask

        void clear()                        { for (auto& b : bits) b = 0; }
        void set(uint8_t c)                 { bits[c >> 3] |= (1u << (c & 7)); }
        [[nodiscard]] bool test(uint8_t c) const { return (bits[c >> 3] & (1u << (c & 7))) != 0; }
        void set_range(uint8_t lo, uint8_t hi) { for (int c = lo; c <= hi; ++c) set((uint8_t)c); }
    };

private:

    std::vector<State>     states_;
    std::vector<CharClass> classes_;
    int  start_{-1};
    bool anchored_start_{false};
    bool anchored_end_{false};
    bool valid_{false};

    // NFA construction
    bool compile(std::string_view pattern);

    // State helpers
    int add_state(Op op, int16_t out = -1, int16_t out1 = -1);
    int add_char_state(uint8_t ch, int16_t out = -1);
    int add_class_state(uint8_t class_idx, bool negated, int16_t out = -1);

    // Simulation (no allocation -- uses stack arrays)
    void eps_closure(uint64_t* set, int s) const;
    void step(const uint64_t* cur, uint64_t* next, uint8_t byte) const;
    [[nodiscard]] bool has_match(const uint64_t* set) const;

    static void set_bit(uint64_t* set, int s)  { set[s >> 6] |= (1ULL << (s & 63)); }
    static bool test_bit(const uint64_t* set, int s) { return (set[s >> 6] & (1ULL << (s & 63))) != 0; }
    static void clear_set(uint64_t* set) { for (int i = 0; i < SETWORDS; ++i) set[i] = 0; }
    static bool empty_set(const uint64_t* set) {
        for (int i = 0; i < SETWORDS; ++i) if (set[i]) return false;
        return true;
    }
};

} // namespace montauk::util
