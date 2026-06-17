// sublimation_order.hpp -- header-only C++ helpers for ordering a vector of
// arbitrary records by one key through sublimation instead of std::sort. Pull a
// key from each element, index-sort it with the flow-model pack (numeric) or the
// MSD string sort, then gather into key order. Stable: equal keys keep input
// order (the index is the tiebreak), so output is deterministic where
// std::sort's tie order was not. This is how struct-by-one-key sorts move onto
// sublimation across montauk (collectors, analyzer rows, findings).
//
// Free functions, not a namespace: `sublimation` is already a function in
// sublimation.h (the qsort-style entry), so a `sublimation::` namespace would
// collide in any TU that includes it. The sublimation_ prefix is the convention.
#ifndef SUBLIMATION_ORDER_HPP
#define SUBLIMATION_ORDER_HPP

#include "sublimation_pack.h"
#include "sublimation_strings.h"

#include <vector>
#include <cstdint>
#include <utility>

// Order `v` by an unsigned/integral key (timestamps, counts, severities).
template <class T, class KeyFn>
void sublimation_order_u64(std::vector<T>& v, bool descending, KeyFn key) {
    const size_t n = v.size();
    if (n < 2) return;
    std::vector<uint64_t> keys(n);
    std::vector<uint32_t> idx(n);
    for (size_t i = 0; i < n; ++i) { keys[i] = (uint64_t)key(v[i]); idx[i] = (uint32_t)i; }
    sublimation_pack_sort_u64(keys.data(), idx.data(), n, descending);
    std::vector<T> out; out.reserve(n);
    for (size_t i = 0; i < n; ++i) out.push_back(std::move(v[idx[i]]));
    v = std::move(out);
}

// Order `v` by a floating-point key (percentages, rates, scores).
template <class T, class KeyFn>
void sublimation_order_f64(std::vector<T>& v, bool descending, KeyFn key) {
    const size_t n = v.size();
    if (n < 2) return;
    std::vector<double> keys(n);
    std::vector<uint32_t> idx(n);
    for (size_t i = 0; i < n; ++i) { keys[i] = (double)key(v[i]); idx[i] = (uint32_t)i; }
    sublimation_pack_sort_f64(keys.data(), idx.data(), n, descending);
    std::vector<T> out; out.reserve(n);
    for (size_t i = 0; i < n; ++i) out.push_back(std::move(v[idx[i]]));
    v = std::move(out);
}

// Order `v` by a string key (names, paths, label sets). `str(elem)` returns a
// NUL-terminated C string valid until the gather (e.g. std::string::c_str()).
template <class T, class StrFn>
void sublimation_order_strings(std::vector<T>& v, bool descending, StrFn str) {
    const size_t n = v.size();
    if (n < 2) return;
    std::vector<const char*> keys(n);
    std::vector<uint32_t> idx(n);
    for (size_t i = 0; i < n; ++i) keys[i] = str(v[i]);
    sublimation_strings_indices(keys.data(), idx.data(), n);  // ascending lex
    std::vector<T> out; out.reserve(n);
    if (descending) for (size_t i = n; i-- > 0;) out.push_back(std::move(v[idx[i]]));
    else            for (size_t i = 0; i < n; ++i) out.push_back(std::move(v[idx[i]]));
    v = std::move(out);
}

#endif // SUBLIMATION_ORDER_HPP
