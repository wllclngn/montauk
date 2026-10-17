// sublimation_fmt_double against std::to_chars, byte for byte.
//
// std::to_chars is the oracle, here and only here: It is the formatter the C
// port replaces, and every face that renders a double has to keep writing
// exactly what it wrote. Every power of two and of ten and both neighbours of
// each, the fixed/scientific crossovers, the subnormal floor, the specials, and
// tens of millions of random bit patterns and decade-uniform values.
#include <cfloat>
#include <charconv>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "sublimation_fmt.h"

static long checked = 0, failed = 0;

static void check(double v) {
    char want[64], got[64];
    auto [end, ec] = std::to_chars(want, want + sizeof want, v);
    if (ec != std::errc{}) { std::fprintf(stderr, "[fmt] oracle failed\n"); std::exit(2); }
    const int n = sublimation_fmt_double(got, sizeof got, v);
    ++checked;
    if (n != end - want || std::memcmp(got, want, (size_t)n)) {
        if (++failed <= 20) {
            uint64_t bits;
            std::memcpy(&bits, &v, sizeof bits);
            std::printf("[fmt] FAIL 0x%016llx: to_chars '%.*s', got '%.*s'\n",
                        (unsigned long long)bits, (int)(end - want), want,
                        n < 0 ? 0 : n, got);
        }
    }
}

static void check_around(double v) {
    check(v);
    check(std::nextafter(v, INFINITY));
    check(std::nextafter(v, -INFINITY));
    check(-v);
}

static uint64_t splitmix(uint64_t *s) {
    uint64_t z = (*s += 0x9e3779b97f4a7c15ull);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
    return z ^ (z >> 31);
}

int main(int argc, char **argv) {
    const long random_n = argc > 1 ? std::atol(argv[1]) : 20'000'000;

    const double edges[] = {0.0, -0.0, HUGE_VAL, -HUGE_VAL, std::nan(""), -std::nan(""),
                            DBL_MIN, DBL_MAX, DBL_TRUE_MIN, DBL_EPSILON, 0.1, 0.2, 0.3,
                            1.0 / 3, 2.0 / 3, 123456789012345680000.0, 1e21, 1e22, 1e23,
                            9.5e21, 1.5e300, 5e-324, 2.2250738585072009e-308,
                            9007199254740993.0};
    for (double v : edges) check_around(v);
    for (int k = -1074; k <= 1023; k++) check_around(std::ldexp(1.0, k));
    for (int k = -323; k <= 308; k++) {
        const std::string s = "1e" + std::to_string(k);
        check_around(std::strtod(s.c_str(), nullptr));
        for (int d = 2; d <= 9; d++) check_around(d * std::strtod(s.c_str(), nullptr));
    }
    // Where fixed and scientific trade places, at every digit count.
    for (int e = -12; e <= 24; e++)
        for (uint64_t m : {1ull, 12ull, 123ull, 1234567ull, 123456789012ull,
                           12345678901234567ull})
            check_around((double)m * std::pow(10.0, e - (int)std::to_string(m).size()));
    for (uint64_t i = 0; i < 4096; i++) {
        check((double)((1ull << 53) - i));
        check((double)((1ull << 53) + 2 * i));
    }

    uint64_t s = 0x5eed2026'10151984ull;
    for (long i = 0; i < random_n; i++) {
        double v;
        const uint64_t bits = splitmix(&s);
        std::memcpy(&v, &bits, sizeof v);
        check(v);
    }
    for (long i = 0; i < random_n / 4; i++) {
        const uint64_t r = splitmix(&s);
        const double unit = (double)(r >> 11) * 0x1.0p-53;
        check(std::ldexp(unit, (int)(r % 2100) - 1075));
    }

    char small[4];
    if (sublimation_fmt_double(small, sizeof small, 0.1) != 3 ||
        sublimation_fmt_double(small, 2, 0.1) != -1) {
        std::printf("[fmt] FAIL cap: a short buffer must return -1 and write nothing past cap\n");
        ++failed;
    }

    if (failed) {
        std::printf("[fmt] GATE FAILED: %ld of %ld differ from std::to_chars\n", failed, checked);
        return 1;
    }
    std::printf("[fmt] GATE PASSED: %ld doubles format byte-identically to std::to_chars\n", checked);
    return 0;
}
