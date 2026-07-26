// fuzz_sort_diff.cpp -- Seeded differential fuzzer for sublimation's sort.
//
// For every shipped type, over many seeded iterations and adversarial input
// patterns, checks the sort against an independent oracle:
//   - integers: the output must EQUAL std::sort byte-for-byte.
//   - floats:   the output must be a bitwise PERMUTATION of the input (the
//               multiset is preserved), AND every non-NaN element is
//               non-decreasing in output order.
//
// The multiset check is the one the old fuzz_sort.c lacked: it verified only the
// sorted PROPERTY for floats, which a value corrupting to NaN (the few-unique
// float bug) slips past -- a bitwise-multiset diff catches any value lost,
// duplicated, or corrupted. The input region that bug lived in (small arrays,
// <=8 distinct values, NaN / signed-zero present) is sampled heavily below.
//
// Every case is generated deterministically from a seed printed on failure, so
// any hit reproduces exactly. Runs in run.py's unit layer to guard every build.
// SUBLIMATION_FUZZ_ITERS overrides the iteration count for a longer local soak.

#include "sublimation.h"
#include "sublimation_pack.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <random>
#include <string>
#include <type_traits>
#include <vector>

namespace {

// One overload per shipped type so the templated driver dispatches by argument.
void sub_sort(int32_t* a, size_t n) { sublimation_i32(a, n); }
void sub_sort(int64_t* a, size_t n) { sublimation_i64(a, n); }
void sub_sort(uint32_t* a, size_t n) { sublimation_u32(a, n); }
void sub_sort(uint64_t* a, size_t n) { sublimation_u64(a, n); }
void sub_sort(float* a, size_t n) { sublimation_f32(a, n); }
void sub_sort(double* a, size_t n) { sublimation_f64(a, n); }

template <class T>
using bits_t = std::conditional_t<sizeof(T) == 4, uint32_t, uint64_t>;

// Canonical bitwise multiset: raw bits of every element, sorted. Two vectors
// share a multiset iff their canon forms are equal -- independent of ordering
// and of any value/NaN semantics.
template <class T>
std::vector<bits_t<T>> canon(const std::vector<T>& v) {
  std::vector<bits_t<T>> b(v.size());
  for (size_t i = 0; i < v.size(); ++i) {
    bits_t<T> u;
    std::memcpy(&u, &v[i], sizeof(T));
    b[i] = u;
  }
  std::sort(b.begin(), b.end());
  return b;
}

// A pool of at most `distinct` values to draw from, so few-unique inputs are
// easy to request. For floats, `specials` mixes in NaN (varied payloads),
// +/-0.0, +/-inf and subnormals -- the values that broke the fast path.
template <class T>
std::vector<T> value_pool(std::mt19937_64& rng, int distinct, bool specials) {
  std::vector<T> pool;
  pool.reserve(distinct);
  for (int i = 0; i < distinct; ++i) {
    if (specials && std::is_floating_point_v<T> && (rng() % 3 == 0)) {
      switch (rng() % 6) {
        case 0: pool.push_back(std::numeric_limits<T>::quiet_NaN()); break;
        case 1: pool.push_back(T(0.0)); break;
        case 2: pool.push_back(T(-0.0)); break;
        case 3: pool.push_back(std::numeric_limits<T>::infinity()); break;
        case 4: pool.push_back(-std::numeric_limits<T>::infinity()); break;
        default: pool.push_back(std::numeric_limits<T>::denorm_min() * T((rng() % 7) + 1)); break;
      }
    } else {
      bits_t<T> u = static_cast<bits_t<T>>(rng());
      if (sizeof(T) == 8) u ^= static_cast<bits_t<T>>(rng()) << 32;
      T t;
      std::memcpy(&t, &u, sizeof(T));
      if (std::is_integral_v<T>) pool.push_back(t);
      else {
        // Bias toward representable finite magnitudes plus the special mix.
        T f = T((int64_t)(u % 2001) - 1000) / T(7);
        pool.push_back(f);
      }
    }
  }
  return pool;
}

enum Pattern { RANDOM, FEW_UNIQUE, ALL_EQUAL, SORTED, REVERSED, ROTATED, SAWTOOTH, NEARLY };

template <class T>
std::vector<T> gen(std::mt19937_64& rng, size_t n, Pattern pat, bool specials) {
  std::vector<T> v(n);
  int distinct = pat == ALL_EQUAL ? 1
               : pat == FEW_UNIQUE ? (int)(rng() % 8 + 1)
               : (int)std::min<size_t>(n ? n : 1, 64);
  auto pool = value_pool<T>(rng, std::max(1, distinct), specials);
  for (size_t i = 0; i < n; ++i) v[i] = pool[rng() % pool.size()];

  switch (pat) {
    case SORTED: std::sort(v.begin(), v.end()); break;
    case REVERSED: std::sort(v.begin(), v.end()); std::reverse(v.begin(), v.end()); break;
    case ROTATED:
      std::sort(v.begin(), v.end());
      if (n > 1) std::rotate(v.begin(), v.begin() + (rng() % n), v.end());
      break;
    case SAWTOOTH:
      for (size_t i = 0; i < n; ++i) v[i] = pool[i % pool.size()];
      break;
    case NEARLY:
      std::sort(v.begin(), v.end());
      for (size_t k = 0, swaps = n / 20 + 1; k < swaps && n > 1; ++k)
        std::swap(v[rng() % n], v[rng() % n]);
      break;
    default: break;
  }
  return v;
}

const char* pat_name(Pattern p) {
  switch (p) {
    case RANDOM: return "random"; case FEW_UNIQUE: return "few-unique";
    case ALL_EQUAL: return "all-equal"; case SORTED: return "sorted";
    case REVERSED: return "reversed"; case ROTATED: return "rotated";
    case SAWTOOTH: return "sawtooth"; case NEARLY: return "nearly-sorted";
  }
  return "?";
}

// Returns "" on success, else a description of the failure.
template <class T>
std::string check(const std::vector<T>& in) {
  std::vector<T> out = in;
  sub_sort(out.data(), out.size());

  if (canon(in) != canon(out))
    return "multiset changed (values lost/duplicated/corrupted)";

  if constexpr (std::is_integral_v<T>) {
    std::vector<T> oracle = in;
    std::sort(oracle.begin(), oracle.end());
    if (out != oracle) return "order differs from std::sort";
  } else {
    T prev; bool have_prev = false;
    for (T x : out) {
      if (std::isnan(x)) continue;          // NaN placement is impl-defined
      if (have_prev && x < prev) return "non-NaN values not non-decreasing";
      prev = x; have_prev = true;
    }
  }
  return "";
}

// PACK / ORDER INDEX SORT differential. montauk's dominant sort is the index
// sort (sublimation_pack_sort_*): sort a companion index array by a numeric key,
// stably. The 64-bit path is now adaptive (radix for random keys, the keyed
// spectral merge for structured), so both arms must be fuzzed. Oracle: a
// std::stable_sort of the index permutation by key -- both the pack sort and the
// oracle are STABLE, so the produced index array must equal the oracle exactly.
// Finite keys only (montauk never index-sorts NaN keys; the pack float mapping's
// NaN placement is covered by the value-sort NaN fuzzing above).
void sub_pack(const int32_t* k, uint32_t* idx, size_t n, bool d) { sublimation_pack_sort_i32(k, idx, n, d); }
void sub_pack(const int64_t* k, uint32_t* idx, size_t n, bool d) { sublimation_pack_sort_i64(k, idx, n, d); }
void sub_pack(const uint32_t* k, uint32_t* idx, size_t n, bool d) { sublimation_pack_sort_u32(k, idx, n, d); }
void sub_pack(const uint64_t* k, uint32_t* idx, size_t n, bool d) { sublimation_pack_sort_u64(k, idx, n, d); }
void sub_pack(const float* k, uint32_t* idx, size_t n, bool d) { sublimation_pack_sort_f32(k, idx, n, d); }
void sub_pack(const double* k, uint32_t* idx, size_t n, bool d) { sublimation_pack_sort_f64(k, idx, n, d); }

template <class T>
std::string check_pack(const std::vector<T>& keys, bool desc) {
  size_t n = keys.size();
  if (n < 1) return "";
  std::vector<uint32_t> idx(n), ref(n);
  for (size_t i = 0; i < n; ++i) idx[i] = ref[i] = (uint32_t)i;
  sub_pack(keys.data(), idx.data(), n, desc);
  std::stable_sort(ref.begin(), ref.end(), [&](uint32_t a, uint32_t b) {
    return desc ? keys[b] < keys[a] : keys[a] < keys[b];
  });
  if (idx != ref) return "pack index permutation differs from stable_sort";
  return "";
}

template <class T>
bool run_pack_type(const char* tname, uint64_t base_seed, int iters) {
  const Pattern pats[] = {RANDOM, FEW_UNIQUE, ALL_EQUAL, SORTED,
                          REVERSED, ROTATED, SAWTOOTH, NEARLY};
  for (int it = 0; it < iters; ++it) {
    uint64_t seed = base_seed + (uint64_t)it;
    std::mt19937_64 rng(seed);
    // Bias above the 512 adaptivity gate so the merge arm is hit often, while
    // still sampling the small-n radix-only path.
    size_t n;
    switch (rng() % 8) {
      case 0: n = rng() % 64; break;                      // small: radix only
      case 1: case 2: n = rng() % 2049; break;            // straddles the gate
      default: n = 512 + rng() % 16384; break;            // adaptive: both arms
    }
    Pattern pat = pats[rng() % (sizeof(pats) / sizeof(pats[0]))];
    std::vector<T> keys = gen<T>(rng, n, pat, /*specials=*/false);
    bool desc = rng() & 1;
    std::string err = check_pack<T>(keys, desc);
    if (!err.empty()) {
      std::printf("[fuzz-diff] FAIL pack-%s: %s\n", tname, err.c_str());
      std::printf("           seed=%llu size=%zu pattern=%s desc=%d\n",
                  (unsigned long long)seed, n, pat_name(pat), desc ? 1 : 0);
      return false;
    }
  }
  return true;
}

template <class T>
bool run_type(const char* tname, uint64_t base_seed, int iters, bool specials) {
  const Pattern pats[] = {RANDOM, FEW_UNIQUE, ALL_EQUAL, SORTED,
                          REVERSED, ROTATED, SAWTOOTH, NEARLY};
  for (int it = 0; it < iters; ++it) {
    uint64_t seed = base_seed + (uint64_t)it;
    std::mt19937_64 rng(seed);
    // Weight small sizes (where the counting-sort / few-unique fast paths and
    // the bug lived) far more heavily than large ones.
    size_t n;
    switch (rng() % 10) {
      case 0: n = rng() % 3; break;                       // 0,1,2
      case 1: case 2: case 3: n = rng() % 33; break;      // <=32
      case 4: case 5: case 6: n = rng() % 129; break;     // <=128
      case 7: case 8: n = rng() % 2049; break;            // <=2048
      default: n = rng() % 16385; break;                  // <=16384
    }
    Pattern pat = pats[rng() % (sizeof(pats) / sizeof(pats[0]))];
    std::vector<T> in = gen<T>(rng, n, pat, specials);
    std::string err = check(in);
    if (!err.empty()) {
      std::printf("[fuzz-diff] FAIL %s: %s\n", tname, err.c_str());
      std::printf("           seed=%llu size=%zu pattern=%s specials=%d\n",
                  (unsigned long long)seed, n, pat_name(pat), specials ? 1 : 0);
      return false;
    }
  }
  return true;
}

}  // namespace

int main() {
  int iters = 20000;
  if (const char* e = std::getenv("SUBLIMATION_FUZZ_ITERS")) {
    long v = std::strtol(e, nullptr, 10);
    if (v > 0) iters = (int)v;
  }

  // A fixed base seed keeps the run reproducible build to build; a failure
  // prints the exact per-case seed to replay.
  const uint64_t B = 0x5EED1234ABCDEF01ull;
  bool ok = true;
  ok &= run_type<int32_t>("i32", B + 1u * 1000000u, iters, false);
  ok &= run_type<int64_t>("i64", B + 2u * 1000000u, iters, false);
  ok &= run_type<uint32_t>("u32", B + 3u * 1000000u, iters, false);
  ok &= run_type<uint64_t>("u64", B + 4u * 1000000u, iters, false);
  ok &= run_type<float>("f32", B + 5u * 1000000u, iters, true);
  ok &= run_type<double>("f64", B + 6u * 1000000u, iters, true);

  // Pack / order index sort (the dominant montauk path), both arms of the 64-bit
  // adaptive dispatch, index permutation vs std::stable_sort.
  ok &= run_pack_type<int32_t>("i32", B + 7u * 1000000u, iters);
  ok &= run_pack_type<int64_t>("i64", B + 8u * 1000000u, iters);
  ok &= run_pack_type<uint32_t>("u32", B + 9u * 1000000u, iters);
  ok &= run_pack_type<uint64_t>("u64", B + 10u * 1000000u, iters);
  ok &= run_pack_type<float>("f32", B + 11u * 1000000u, iters);
  ok &= run_pack_type<double>("f64", B + 12u * 1000000u, iters);

  if (ok) {
    std::printf("[fuzz-diff] PASS: 6 types x %d iters value sort (multiset + "
                "order vs std::sort; floats multiset + non-NaN ascending) + 6 "
                "types pack/order index sort (permutation vs std::stable_sort)\n",
                iters);
    return 0;
  }
  return 1;
}
