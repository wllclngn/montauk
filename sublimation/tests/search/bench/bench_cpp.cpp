// Cross-language search bench, C++ standard library point.
// literal: std::string::find. regex: std::regex (ECMAScript, backtracking).
// Protocol: <corpusfile> <pattern> <runs> <literal|regex>
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <regex>
#include <string>
#include <vector>

static std::string slurp(const char *path) {
    std::ifstream f(path, std::ios::binary);
    std::string s((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    return s;
}

static size_t count_literal(const std::string &hay, const std::string &pat) {
    size_t c = 0, pos = 0;
    while ((pos = hay.find(pat, pos)) != std::string::npos) {
        c++; pos++;                         // overlapping
    }
    return c;
}

static size_t count_regex(const std::string &hay, const std::regex &re) {
    auto b = std::sregex_iterator(hay.begin(), hay.end(), re);
    return (size_t)std::distance(b, std::sregex_iterator());
}

int main(int argc, char **argv) {
    if (argc < 5) { fprintf(stderr, "usage: %s file pat runs literal|regex\n", argv[0]); return 2; }
    std::string hay = slurp(argv[1]);
    std::string pat = argv[2];
    bool is_regex = std::string(argv[4]) == "regex";
    std::regex re;
    if (is_regex) re = std::regex(pat, std::regex::extended);

    size_t count = is_regex ? count_regex(hay, re) : count_literal(hay, pat);
    std::vector<double> dt(9);
    for (int r = 0; r < 9; r++) {
        auto t0 = std::chrono::steady_clock::now();
        volatile size_t s = is_regex ? count_regex(hay, re) : count_literal(hay, pat);
        auto t1 = std::chrono::steady_clock::now();
        (void)s;
        dt[r] = std::chrono::duration<double>(t1 - t0).count();
    }
    std::sort(dt.begin(), dt.end());
    double mb = (double)hay.size() / 1e6 / dt[4];
    printf("{\"algo\":\"cpp_%s\",\"count\":%zu,\"mb_s\":%.0f}\n",
           is_regex ? "std_regex" : "string_find", count, mb);
    return 0;
}
