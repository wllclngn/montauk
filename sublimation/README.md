# sublimation

A flow-model sort built in C23. sublimation classifies every input by Young tableau shape via patience sorting, derives the information-theoretic lower bound on comparisons from the hook length formula, and routes by tableau shape: spectral R_eff merge tree (effective resistance on the run-boundary Laplacian), k-way merge for k-interleaved sequences, O(n) rotation fix for rotated sorted arrays, counting sort for few-unique data, binary insertion sort for low-displacement nearly-sorted data, layered PCF + BMI2 PEXT + pdqsort-style fat-pivot + AVX2 sort networks for random data, and Jacobi-eigendecomposition spectral fallback when CUSUM detects partition degradation.

Critically-damped oscillator drives the CUSUM threshold. Comparison efficiency reported against the information-theoretic minimum. Type-generic via macro template instantiation across i32, i64, u32, u64, f32, f64. IPS4o-style parallel sort via `sublimation_i64_parallel`. Alphanumeric (string) sort via `sublimation_strings` + `sublimation_strings_indices` — 4-byte big-endian prefix-pack feeds `sublimation_u64`, iterative MSD radix resolves prefix-collision tie clusters; 2.0-4.5x over `qsort + strcmp`. Struct-sort-by-one-numeric-key via `sublimation_pack_sort_{u32,i32,f32}` — stable for equal keys, zero new kernels. Ships pkg-config, CMake package config, and SONAME-versioned `.so` for distro-clean integration.

## Performance

GCC 15.2.1, `-O2 -march=native`, CachyOS kernel 6.19, AMD Ryzen 7 5800XT Zen 3 (8 cores / 16 threads, AVX2 + BMI2, 32 KB L1d per core, 512 KB L2 per core, 32 MB L3 shared). All values ns/element, best of 11 runs, `taskset -c 0`. Comparison points: glibc qsort, inline introsort (median-of-three quicksort + heapsort fallback), Rust `slice::sort_unstable` (ipnsort).

### sublimation vs The World (ns/element at 100K, best of 11)

| Pattern              | sublimation | introsort | qsort  | Rust   | vs introsort | vs qsort  | vs Rust  |
|----------------------|------------:|----------:|-------:|-------:|-------------:|----------:|---------:|
| sorted               | **0.13**    | 4.17      | 22.64  | 0.24   | **32.1x**    | **174.2x**| **1.85x**|
| reversed             | **0.38**    | 4.26      | 25.42  | 0.37   | **11.2x**    | **66.9x** | 0.97x    |
| equal                | **0.10**    | 5.45      | 22.63  | 0.24   | **54.5x**    | **226.3x**| **2.40x**|
| pipe_organ           | **2.53**    | 43.57     | 25.12  | 11.44  | **17.2x**    | **9.93x** | **4.52x**|
| nearly               | **6.20**    | 5.22      | 34.71  | 10.55  | 0.84x        | **5.60x** | **1.70x**|
| few_unique           | **10.96**   | 12.18     | 47.66  | 1.81   | **1.11x**    | **4.35x** | 0.17x    |
| random               | **18.64**   | 36.84     | 77.92  | 9.32   | **1.98x**    | **4.18x** | 0.50x    |
| zipfian              | **16.88**   | 23.87     | 60.37  | 9.33   | **1.41x**    | **3.58x** | 0.55x    |
| sorted_perturbed     | **5.39**    | 4.52      | 30.28  | 9.35   | 0.84x        | **5.62x** | **1.74x**|
| saw_mixed            | **14.53**   | 14.67     | 32.73  | 9.36   | **1.01x**    | **2.25x** | 0.64x    |

sublimation beats libstdc++ introsort on **8/10 patterns**. Beats glibc qsort on **10/10**, by 2.25x to 226x. Beats Rust ipnsort on **5/10** patterns: sorted/equal (cold-start fast paths), pipe_organ (R_eff merge tree, 4.52x), nearly_sorted (binary isort, 1.70x), and sorted_perturbed (1.74x). Trails Rust ipnsort on uniform random and Zipfian by ~2.0x at this size; the gap closes as n grows.

`zipfian`, `sorted_perturbed`, `saw_mixed`, and the test-only `antiqsort` McIlroy fixture were added in v1.1.0; alphanumeric (string) sort via `sublimation_strings` is new in v1.2.0.

### Random-data size sweep (ns/element, best of 11, `taskset -c 0`)

| n          | sublimation | introsort | qsort  | Rust ipnsort | sub vs Rust |
|-----------:|------------:|----------:|-------:|-------------:|------------:|
| 1,024      | 23.88       | 30.07     | 57.18  | **7.65**     | 3.12x slower|
| 10,000     | 17.66       | 32.18     | 66.02  | **8.71**     | 2.03x slower|
| 100,000    | 19.21       | 40.63     | 83.16  | **10.76**    | 1.78x slower|
| 1,000,000  | 21.29       | 40.91     | 86.60  | **11.02**    | 1.93x slower|
| 10,000,000 | 23.34       | 48.60     | 105.64 | **13.78**    | 1.69x slower|

Gap to Rust ipnsort: 3.12x at n=1K, 1.69x at n=10M. Rust ipnsort is the comparison-sort floor on AVX2-only hardware (vqsort and x86-simd-sort beat it but require AVX-512). sublimation beats introsort by 1.26x to 2.12x and qsort by 2.39x to 4.53x at every size on random data.

### Parallel sort (8 cores / 16 threads, ns/element, random int64)

| n          | serial sublimation | parallel sublimation | speedup | parallel Rust (rayon-shaped) | sub vs serial Rust |
|-----------:|-------------------:|---------------------:|--------:|-----------------------------:|-------------------:|
| 100,000    | 19.16              | 19.04                | 1.01x   | 8.39                         | 1.77x slower       |
| 1,000,000  | 20.76              | 10.72                | 1.94x   | 7.72                         | 1.03x faster       |
| 10,000,000 | 23.11              | 12.19                | 1.90x   | 7.96                         | 1.13x faster       |

`sublimation_i64_parallel` dispatches to an IPS4o-style parallel pool: each worker classifies its chunk, prefix-sum merges global bucket counts, parallel scatter to global positions, greedy load-balanced per-bucket sort. Sub-linear speedup due to memory bandwidth and the merge phase. `SUB_PARALLEL_THRESHOLD = 250K`; below threshold the parallel entry falls back to serial. At n ≥ 1M, parallel sublimation beats serial Rust `slice::sort_unstable` (1.13x at n=10M). Parallel Rust (rayon-shaped) is ~1.5x ahead of parallel sublimation at every size.

## Architecture

Flow-model architecture from Dinic max-flow: classification pass = initial BFS, partition/merge = blocking flow DFS. Connection to sorting via the Robinson-Schensted correspondence on Young tableaux.

### Classification (Initial BFS)

Single O(n) pass detects: run count, monotone runs, sorted/reversed, max run length, max descent gap (displacement proxy). Lazy fast paths short-circuit: sorted/reversed/equal detected in one comparison per element. High run count (> n/4) skips expensive passes and routes to partition. Low run count with long max run routes to R_eff merge. Only ambiguous inputs pay for sampled inversions, distinct value estimation, CUSUM phase boundary detection, and full Young tableau computation via patience sorting.

### Young Tableau and Information-Theoretic Bound

For ambiguous inputs, patience sorting computes the Young tableau shape λ = (λ₁, λ₂, ..., λ_d) by tracking pile sizes during RSK insertion:
- λ₁ = LIS length (longest increasing subsequence)
- d = number of rows = LDS length (longest decreasing subsequence)
- Balanced rows (λ_i ≈ n/d) = d interleaved sorted sequences → k-way merge
- Single descent with wraparound continuity = rotated sorted array → O(n) fix

The hook length formula (Frame-Robinson-Thrall) computes f^λ = n! / ∏ h(i,j), the number of standard Young tableaux of shape λ. log₂(f^λ) is the information-theoretic lower bound on comparisons. sublimation reports `actual_comparisons / info_theoretic_bound` after every sort.

### Displacement-Based Routing

For nearly-sorted data, the classifier tracks `max_descent_gap` -- the largest value drop at any descent point. This is a displacement proxy computed in the same O(n) run-counting pass, zero additional cost. Routing:
- `run_count <= 16`: structured data (pipe_organ), route to R_eff merge tree
- `run_count > 16, max_descent_gap <= sqrt(n)`: small perturbation, binary insertion sort -- O(n + inversions), 99% of elements skip in one comparison
- `run_count > 16, max_descent_gap > sqrt(n)`: large displacement, lightweight quicksort

### Random-Data Path

For data the classifier tags `SUB_RANDOM`, sublimation runs a four-layer pipeline.

**Layer 1: Linear PCF bucketing** (Sato-Matsui 2024). Sample S ∈ [256, 1024] elements at equal stride, sort the sample, derive lo_v and hi_v from the [5%, 95%] envelope expanded by a 10% margin and clamped to the actual sample extrema. Compute slope = B / (hi_v - lo_v + 1) where B is dynamic: `B = clamp(ceil(n / 24000), 256, 4096)`. The bucket index for each element is one fmul + cvtsd2si + clamp -- recomputed inline in both the histogram pass and the scatter pass (no `bucket_idx[n]` side array, saving 2n bytes of memory traffic). Scatter via 256-4096 software write-combine buffers (one cache line per bucket) keeps TLB pressure bounded. The dynamic-B formula clamps to 256 for n ≤ 6.1M (the empirical local optimum at common sizes) and grows for larger n to keep each bucket inside L2 cache.

**Layer 2: Per-bucket AVX2 quicksort.** Each bucket sub-sort runs the AVX2 quicksort engine (`avx2_quicksort_with_scratch_i64`), which is iterative (no call overhead), uses smaller-half-first recursion (stack bounded at log n), and threshold-switches its partition primitive at L1-fit (~4096 elements):
- **Above the threshold**: in-place block partition via BMI2 `PEXT` (Edelkamp-Weiss BlockQuicksort + AVX2/BMI2 inner loop). For each 16-element block, four `vpcmpgtq` instructions produce a 16-bit "wrong-side" mask; `_pdep_u64(mask, 0x1111111111111111)` expands each set bit to a nibble; bit-fill with two ORs produces a nibble mask; `_pext_u64(0xFEDCBA9876543210, mask)` packs the nibble-indices of "wrong" elements into a 64-bit register. Walk left/right block index lists, swap pairs in place. Memory traffic per partition level drops from 4n bytes (read arr → write scratch → read scratch → write arr) to 2n bytes (read arr → write arr in-place).
- **Below the threshold**: AVX2 vpcompressq emulation via a 16-entry shuffle table. Partition is out-of-place via a scratch buffer, but processes 4 i64 elements per `vpermd`. The SIMD parallelism dominates inside L1 where memory traffic isn't the bottleneck.

**Layer 3: Pdqsort-style fat-pivot equivalence-class detection.** After each partition, a 4-element probe checks the right-side array for elements equal to the pivot. On unique-value data the probe exits in 1-4 compares. On duplicate-heavy data (Zipfian, hash-clustered, categorical) the probe fires; a Lomuto-style sweep gathers all equal-to-pivot elements adjacent to the pivot; the right recursion skips the entire equivalence class. Without this layer, 2-way Lomuto degrades on duplicate-heavy inputs because all duplicates of the pivot pile onto the same side.

**Layer 4: AVX2 sorting networks at the leaves** (AlphaDev-shaped). At `len < 32` the recursion drops into `sub_small_sort_i64`, which dispatches to size-specific AVX2 networks: `sort4_avx2`, `sort8_avx2`, `sort16_avx2`, `sort32_avx2`. Fully vectorized (one YMM register holds 4 i64s) and branchless (`vpcmpgtq`/`vpermq`/`vpblendvb` chains, no data-dependent control flow). Bose-Nelson networks in the cmov-shape family of AlphaDev (Mankowitz et al., Nature 2023).

At n=100K random int64 on the 5800XT: 18.64 ns/elem, 1.98x faster than libstdc++ introsort, 2.00x slower than Rust ipnsort. Gap to Rust narrows from 3.12x at n=1K to 1.69x at n=10M.

### Partition (Structured-Data Path)

For data routed through the adaptive sort engine in `sort_impl.h` (the structured-data path), partition is a 2-way unrolled branchless block Lomuto with write prefetch. Median-of-three pivot selection (ninther for large arrays). Two elements per iteration, independent comparisons overlapped in the superscalar pipeline. Conditional pointer advance compiles to CMOVcc on x86. EWMA tracks partition quality. CUSUM with oscillator-controlled threshold detects degradation and triggers spectral fallback.

### Spectral Fallback

When partition quality degrades (CUSUM triggers), the Laplacian eigendecomposition of the comparison graph recovers the sorted order via Fiedler vector seriation (Atkins, Boman, Hendrickson 1998). Jacobi eigendecomposition extracts the spectral structure. Activates for subarrays in [64, 512] elements.

### R_eff Merge Tree

For structured nearly-sorted data with k runs: effective resistance on the run-boundary path graph determines merge order (Chandra et al. 1996). R_eff(i, i+1) = 1/w where w encodes the value gap between adjacent runs. Low resistance = small gap = galloping merge skips everything = merge first. Boundaries sorted by resistance in O(k log k), processed with union-find coalescing. Gap heuristic (Goldberg-Tarjan 1988): adjacent runs whose boundaries are already sorted coalesce into superruns before merge begins, often reducing k from hundreds to single digits.

### Counting Sort

For few-unique data (k <= 64 distinct values): single-pass fused discovery + histogram. Binary search in a small sorted distinct-values array classifies each element. Prefix sum + scatter writes the sorted output. O(n log k) with no recursion. Early-exit probe at 64 elements bails if k == 1 (all-equal data handled by the faster O(n) sorted path instead).

### Damped Harmonic Oscillator

CoDel-inspired sigmoid center adaptation. The oscillator's position (0..1) controls the CUSUM trigger threshold: tightens toward 0 on degradation (trigger spectral fallback sooner), relaxes toward 1 when stable (permit partition to continue). Critically-damped second-order dynamics converge without oscillation. The threshold is learned, not hardcoded.

### Hybrid DFS

Recursive for shallow depth (branch predictor friendly). Explicit stack with 128 frames for deep paths (stack-safe). Larger half pushed first, smaller half processed first (minimizes peak stack depth). Subarray reclassification every 8 levels (periodic global relabel from Push-Relabel). Equal element detection mid-partition (switches to Dutch national flag when pivot equals previous boundary).

### Parallel Sort (IPS4o-style BSP)

Parallel bucket distribution: each worker classifies its chunk independently (no contention), prefix-sum merge of bucket counts, parallel scatter to global positions, greedy load-balanced per-bucket sort. 4x bucket overpartitioning for load balance. Classification + scatter is O(n/p), removing the Amdahl bottleneck. `sublimation_i64_parallel` auto-dispatches at `SUB_PARALLEL_THRESHOLD = 250K`. Workers sort their buckets using the full sequential flow model independently.

### Sorting Networks

Optimal comparison counts for n = 2-8 (verified against all 40,320 permutations for n=8). Bose-Nelson networks for 7-8. AVX2 vectorized sort-4, sort-8, sort-16, and sort-32 via bitonic merge networks using `_mm256_cmpgt_epi64` + `_mm256_blendv_epi8` (falls back to scalar on non-AVX2). Branchless cmov-shape comparators throughout, the same family as AlphaDev's RL-discovered routines. Used as the leaf base case for both the structured-data partition and the random-data quicksort recursion.

## Build & Install

```bash
./install.py              # Build and install to /usr/local
./install.py build        # Build only (libsublimation.a + .so)
./install.py test         # Build and run tests
./install.py bench        # Build and run benchmarks
./install.py fuzz         # Build and run differential fuzzer (requires clang + compiler-rt)
./install.py clean        # Clean build artifacts
./install.py status       # Show build/install status
```

Requires GCC 13+ or Clang 16+ with C23 support, BMI2 (PEXT) and AVX2 for the random-data fast path. No external dependencies.

```bash
# Full test suite: correctness + sanitizers + cross-language + benchmarks + scaling
python3 tests/test.py                # All tests + benchmarks (~843K tests)
python3 tests/test.py --quick        # Tests only, no benchmarks

# Benchmarks with hardware profiling and statistical analysis
python3 tests/bench-sublimation.py --perf    # IPC, cache misses, branch misses per pattern
python3 tests/bench-sublimation.py --stats   # p50/p95/p99/stddev, 11 runs with CI

# Results logged to ~/.cache/sublimation/ (Prometheus + human-readable)
```

843,240 tests across all 6 numeric types (i32, i64, u32, u64, f32, f64). Includes: exhaustive permutation testing for all types (n=1..8, all permutations, including float edge cases NaN, INF, -0.0, denormals), Bentley-McIlroy 5x6 matrix (1,740 combinations), McIlroy 1999 dynamic adversarial input with subquadratic wall-clock budget verification, Zipfian-distributed input, sorted-with-perturbation, alternating ascending/descending chunks, 15 additional adversarial patterns across all types, comparison-count bound enforcement, ThreadSanitizer, AddressSanitizer, UBSan, differential fuzzing (libFuzzer vs qsort), cross-language roundtrip (Python, Rust, Go).

v1.1.0 fixtures: `test_zipfian`, `test_sorted_perturbed`, `test_saw_mixed`, `test_antiqsort`. `test_antiqsort` enforces a tiered wall-clock budget (1ms / 5ms / 25ms / 250ms across n ∈ {100, 1K, 10K, 100K}) catching quadratic regressions. v1.2.0 fixtures: `test_strings` (19 alphanumeric scenarios from trivial n=0,1 through n=1M random, adversarial 4 KB shared-prefix, embedded-NUL, and indices-output parity) and `test_pack` (15 scenarios across u32/i32/f32 pack-key sort including stability checks and signed/descending coverage).

## Usage

```c
#include <sublimation.h>

// Sort any numeric type -- full flow model for all six
int64_t arr[] = {5, 3, 8, 1, 9, 2, 7, 4, 6, 0};
sublimation_i64(arr, 10);

double prices[10000];
sublimation_f64(prices, 10000);

uint32_t ids[50000];
sublimation_u32(ids, 50000);

// _Generic dispatch picks the right function at compile time
sublimation_typed(arr, 10);

// With statistics (includes information-theoretic efficiency)
sub_stats_t stats = {0};
sublimation_i64_stats(arr, n, &stats);
printf("comparisons: %lu, info bound: %.0f, efficiency: %.1f%%\n",
       stats.comparisons, stats.info_theoretic_bound,
       stats.comparison_efficiency * 100.0);

// Classification only (inspect without sorting)
sub_profile_t profile = sublimation_classify_i64(arr, n);
printf("LIS: %zu, LDS: %zu (tableau rows), interleave k: %zu\n",
       profile.lis_length, profile.lds_length, profile.interleave_k);

// Explicit parallel (specify thread count)
sublimation_i64_parallel(arr, 1000000, 8);

// Alphanumeric (string) sort. Hybrid: 4-byte big-endian prefix-pack feeds
// sublimation_u64 for the bulk of the work, then iterative MSD radix
// resolves prefix-collision tie clusters. 2.0-4.5x over qsort+strcmp on
// the patterns measured (random, sorted, common-prefix, deep-prefix at
// n=100k, L=16). NOT stable. Capacity n < 2^32.
const char *names[] = {"banana", "apple", "cherry", "apricot"};
sublimation_strings(names, 4);

// Length-explicit variant for embedded-NUL or non-NUL-terminated data.
const char *blobs[] = { ... };
size_t lens[]      = { ... };
sublimation_strings_len(blobs, lens, n);

// Index-output variant: sort a vector<Process> by an embedded string
// field without permuting a pointer scratch vector.
const char *names_ro[n];        // read-only view
uint32_t order[n];
sublimation_strings_indices(names_ro, order, n);
// Iterate rows by order[i] to visit them in sorted-name order.

// Pack-key sort: sort indices by a companion numeric key array.
// Stable for equal keys (index as tiebreak). Returns the permutation in
// the indices array; keys array is untouched.
float cpu_pct[n];
uint32_t row_idx[n];
for (size_t i = 0; i < n; i++) row_idx[i] = (uint32_t)i;
sublimation_pack_sort_f32(cpu_pct, row_idx, n, true /* descending */);

// qsort-compatible (custom types, delegates to qsort internally)
sublimation(data, count, sizeof(element), comparator);
```

Compile:

```bash
# Via pkg-config (installed to $PREFIX/lib/pkgconfig/sublimation.pc)
gcc -O2 myapp.c $(pkg-config --cflags --libs sublimation) -o myapp

# Manual (if not using pkg-config)
gcc -O2 myapp.c -lsublimation -lpthread -lm -o myapp
```

CMake projects:

```cmake
find_package(Sublimation 1.2 REQUIRED)
target_link_libraries(my_target PRIVATE Sublimation::sublimation)
```

The shared library ships with SONAME `libsublimation.so.1` baked in, so
ldconfig and the dynamic linker resolve ABI-compatible upgrades
automatically. The soname major version bumps only on ABI break.

## References

### Spectral Graph Theory and Seriation
- Atkins, Boman, Hendrickson. "A Spectral Algorithm for Seriation and the Consecutive Ones Problem." SIAM J. Comput. 1998. *(Fiedler vector seriation: sorting by second eigenvector of the Laplacian recovers the ordering for Robinson matrices. Core theorem behind spectral merge tree.)*
- Fiedler. "Algebraic Connectivity of Graphs." Czechoslovak Mathematical Journal 1973. *(Fiedler vector, algebraic connectivity, spectral bisection.)*
- Klein, Randic. "Resistance Distance." J. Math. Chem. 1993. *(Effective resistance as graph distance metric. R_eff merge ordering.)*
- Chandra, Raghavan, Ruzzo, Smolensky, Tiwari. "The Electrical Resistance of a Graph Captures its Commute and Cover Times." Computational Complexity 1996. *(Commute time theorem. R_eff on run-boundary path graph determines merge order.)*

### Robinson-Schensted Correspondence and Sorting
- Schensted. "Longest Increasing and Decreasing Subsequences." Canadian J. Math. 1961. *(RSK correspondence, patience sorting computes LIS = first row of Young tableau.)*
- Baik, Deift, Johansson. "On the Distribution of the Length of the Longest Increasing Subsequence of Random Permutations." JAMS 1999. *(LIS ~ 2*sqrt(n) with Tracy-Widom fluctuations for random permutations.)*
- Mannila. "Measures of Presortedness and Optimal Sorting Algorithms." IEEE Trans. Computers 1985. *(Framework for presortedness measures: Inv, Runs, Rem, Max, Osc.)*

### Adaptive Control and Online Learning
- Nichols, Jacobson. "Controlled Delay Active Queue Management." RFC 8289, 2018. *(CoDel algorithm. Damped oscillation adapted for CUSUM threshold control.)*
- Page. "Continuous Inspection Schemes." Biometrika 1954. *(CUSUM change-point detection. Partition quality degradation and phase boundary detection.)*

### Maximum Flow and Graph Algorithms
- Chen, Kyng, Liu, Peng, Gutenberg, Sachdeva. "Maximum Flow and Minimum-Cost Flow in Almost-Linear Time." FOCS 2022 Best Paper. *(Kyng et al. research lineage. Laplacian solvers, spectral sparsification.)*
- Dinic. "Algorithm for Solution of a Problem of Maximum Flow in Networks with Power Estimation." Soviet Math. Doklady 1970. *(BFS level graph + DFS blocking flow. Architectural ancestor of sublimation's flow-model sort.)*
- Goldberg, Tarjan. "A New Approach to the Maximum-Flow Problem." J. ACM 1988. *(Push-Relabel with gap optimization. Gap heuristic run pruning.)*

### Sorting Algorithms (Comparison Points and Direct Influences)
- Sato, Matsui. "PCF Learned Sort: Linear Cost via Cumulative Distribution Functions." TMLR 2024. arXiv:2405.07122. *(The linear PCF wrapper used at the top of sublimation's random-data path.)*
- Mankowitz, Michi, Zhernov, Gelmi, Selvi, Paduraru, Leurent, Iqbal, Lespiau, Ahern, Köppe, Millikin, Gaffney, Elster, Broshear, Gao, Davies, Kohli, Vinyals, Hassabis, Silver. "Faster sorting algorithms discovered using deep reinforcement learning." Nature 618:257-263, 2023. *(AlphaDev. Branchless cmov-shape sorting networks at the leaves of the random-data quicksort.)*
- Edelkamp, Weiss. "BlockQuicksort: Avoiding Branch Mispredictions in Quicksort." ESA 2016. arXiv:1604.06697. *(Block partition with offset-buffer compaction. The basis for sublimation's PEXT in-place block partition.)*
- Peters. "Pattern-defeating Quicksort." arXiv:2106.05123, 2021. *(pdqsort: Rust and Go's default sort. The fat-pivot equivalence-class detector in sublimation's random-data quicksort is the same shape as pdqsort's fat-pivot path.)*
- Bergdoll, Peters. "ipnsort: Efficient, Generic and Robust Unstable Sort." 2024. *(The current Rust standard library `slice::sort_unstable`. Primary comparison point for sublimation's random-data path.)*
- Musser. "Introspective Sorting and Selection Algorithms." SPE 1997. *(Introsort: quicksort + heapsort fallback. libstdc++ `std::sort`.)*
- Axtmann, Witt, Ferizovic, Sanders. "In-Place Parallel Super Scalar Samplesort (IPS4o)." ESA 2017. *(Parallel bucket distribution pattern used in `sublimation_i64_parallel`.)*
- Bentley, McIlroy. "Engineering a Sort Function." Software--Practice and Experience 1993. *(Canonical sort testing methodology and the staggered/plateau adversarial patterns used in sublimation's test fixtures.)*
- McIlroy. "A Killer Adversary for Quicksort." Software--Practice and Experience 1999. *(Dynamic adversarial input construction. Ported into `tests/test_antiqsort.c` as a permanent regression guard with wall-clock budget verification.)*

## Project Status

4,559 lines of C across `src/` (5 source files, 4 type-template impl headers, 5 internal/public headers). 3,727 lines of test harness across 15 C test files plus the bench driver. 4 research documents in `research/`. 843,240 tests across all 6 numeric types pass on every `python3 tests/test.py` invocation. ThreadSanitizer clean (0 races). AddressSanitizer clean (0 errors). Cross-language roundtrip clean.

## License

GPL-2.0
