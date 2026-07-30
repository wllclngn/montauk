#!/usr/bin/env python3
"""
sublimation benchmark: sublimation vs the world.

Compiles and benchmarks sublimation against:
  - glibc qsort (C standard library)
  - Inline introsort (pdqsort-lite, no function pointer)
  - Rust slice::sort_unstable (actual pdqsort, ipnsort backend)
  - Go slices.Sort (pdqsort-based)

Each comparison point is an honest, native-compiled binary using its
ecosystem's standard sort. No tricks, no handicaps.

Usage:
    ./tests/bench-sublimation.py              # Full suite
    ./tests/bench-sublimation.py --quick      # Smaller sizes, fewer runs
    ./tests/bench-sublimation.py --sizes 1000,100000
    ./tests/bench-sublimation.py --patterns random,sorted
"""

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False


SCRIPT_DIR = Path(__file__).parent.resolve()
PROJECT_DIR = SCRIPT_DIR.parent
BUILD_DIR = PROJECT_DIR / "build"
BENCH_DIR = SCRIPT_DIR / "bench"
SRC_DIR = PROJECT_DIR / "src"

# Python benchmark support
import ctypes
import random
import array


# LOGGING

def _timestamp():
    return datetime.now().strftime("[%H:%M:%S]")

def log_info(msg):
    print(f"{_timestamp()} [INFO]   {msg}")

def log_warn(msg):
    print(f"{_timestamp()} [WARN]   {msg}")

def log_error(msg):
    print(f"{_timestamp()} [ERROR]  {msg}")


# RESULTS

class Results:
    def __init__(self):
        self.data = {}  # (pattern, size) -> {algo: ns_per_elem}

    def add(self, algo, pattern, size, ns_per_elem):
        key = (pattern, size)
        if key not in self.data:
            self.data[key] = {}
        self.data[key][algo] = ns_per_elem

    def print_table(self, algos):
        patterns = sorted(set(p for p, _ in self.data.keys()))
        sizes = sorted(set(s for _, s in self.data.keys()))

        for pattern in patterns:
            print()
            print(f"  Pattern: {pattern}")

            # header
            header = f"  {'N':>10}"
            for algo in algos:
                header += f"  {algo:>16}"
            # add speedup columns vs introsort
            if "introsort" in algos and "sublimation" in algos:
                header += f"  {'vs introsort':>14}"
            print(header)

            for size in sizes:
                key = (pattern, size)
                if key not in self.data:
                    continue
                row_data = self.data[key]

                row = f"  {size:>10}"
                kyng_ns = row_data.get("sublimation")
                intro_ns = row_data.get("introsort")

                for algo in algos:
                    ns = row_data.get(algo)
                    if ns is not None:
                        row += f"  {ns:>13.1f}ns"
                    else:
                        row += f"  {'N/A':>16}"

                # speedup vs introsort
                if kyng_ns is not None and intro_ns is not None and intro_ns > 0:
                    ratio = intro_ns / kyng_ns
                    if ratio >= 1.0:
                        row += f"  {ratio:>10.2f}x"
                    else:
                        row += f"  {ratio:>10.2f}x"
                elif "introsort" in algos and "sublimation" in algos:
                    row += f"  {'N/A':>14}"

                print(row)


# STATISTICAL RESULTS

class StatsResults:
    """Collects all run timings for statistical analysis."""

    def __init__(self):
        self.data = {}  # (algo, pattern, size) -> [ns_per_elem, ...]

    def add(self, algo, pattern, size, ns_per_elem):
        key = (algo, pattern, size)
        if key not in self.data:
            self.data[key] = []
        self.data[key].append(ns_per_elem)

    def print_table(self, algos):
        patterns = sorted(set(p for _, p, _ in self.data.keys()))
        sizes = sorted(set(s for _, _, s in self.data.keys()))

        for algo in algos:
            print()
            print(f"  Algorithm: {algo}")
            print(f"  {'Pattern':<14} {'N':>10}  {'min':>10}  {'p50':>10}  {'p95':>10}  "
                  f"{'p99':>10}  {'stddev':>10}  {'cv%':>8}")

            for pattern in patterns:
                for size in sizes:
                    key = (algo, pattern, size)
                    times = self.data.get(key)
                    if not times or len(times) < 2:
                        continue

                    arr = np.array(times)
                    p50, p95, p99 = np.percentile(arr, [50, 95, 99])
                    mn = arr.min()
                    sd = arr.std(ddof=1)
                    cv = (sd / arr.mean()) * 100.0 if arr.mean() > 0 else 0.0

                    print(f"  {pattern:<14} {size:>10}  {mn:>8.1f}ns  {p50:>8.1f}ns  "
                          f"{p95:>8.1f}ns  {p99:>8.1f}ns  {sd:>8.2f}ns  {cv:>6.1f}%")


# PERF STAT IS GONE, and not because it stopped working.
# montauk is the only tracer in this codebase: ftrace, bpftrace, strace and
# `perf record/trace/stat` are banned for every task in every project, and this
# harness was calling `perf stat` on every --perf run inside montauk's own
# repository. The replacement is montauk's per-process PMU attribution, which
# exists precisely so nobody needs perf -- see the radix ceiling item in
# ROADMAP.md, which is the first real consumer of it.

def _fmt_size(n):
    if n >= 1_000_000:
        return f"{n // 1_000_000}M"
    elif n >= 1_000:
        return f"{n // 1_000}K"
    return str(n)


# BUILD

def run_cmd(cmd, cwd=None, timeout=120, env=None):
    result = subprocess.run(cmd, capture_output=True, text=True,
                            cwd=cwd, timeout=timeout, env=env)
    return result.returncode, result.stdout, result.stderr


def build_c_bench():
    log_info("Building C benchmark (sublimation + qsort + introsort)")

    # Build libsublimation from the in-tree sources. sublimation is vendored
    # under montauk now -- there is no standalone install.py. Compile every
    # src/**/*.c into a static .a (LTO, linked by the C bench) and a shared .so
    # (real symbols, used by the Rust/Go-direct and Python paths -- the .a's LTO
    # GIMPLE objects aren't linkable by rustc/cgo).
    BUILD_DIR.mkdir(exist_ok=True)
    srcs = sorted(str(p) for p in SRC_DIR.rglob("*.c"))
    if not srcs:
        log_error(f"no sublimation sources under {SRC_DIR}")
        return None
    base = ["gcc", "-std=c2x", "-O2", "-march=native", "-fPIC",
            "-I", str(SRC_DIR / "include"), "-I", str(SRC_DIR)]
    a_objs, so_objs = [], []
    for s in srcs:
        stem = Path(s).stem
        a_o = BUILD_DIR / (stem + ".a.o")
        so_o = BUILD_DIR / (stem + ".so.o")
        ret, _, stderr = run_cmd(base + ["-flto=auto", "-c", s, "-o", str(a_o)])
        if ret != 0:
            log_error(f"lib compile failed ({Path(s).name}): {stderr[-300:]}")
            return None
        ret, _, stderr = run_cmd(base + ["-c", s, "-o", str(so_o)])
        if ret != 0:
            log_error(f"lib compile failed ({Path(s).name}): {stderr[-300:]}")
            return None
        a_objs.append(str(a_o))
        so_objs.append(str(so_o))
    # `ar rcs` REPLACES named members but keeps every other member already in the
    # archive, so a stale object from an earlier source layout survives forever
    # and collides at link time (pool.o vs dfspool.a.o both defining
    # sub_default_num_workers). Remove the archive first so it is rebuilt from
    # exactly the sources that exist now.
    (BUILD_DIR / "libsublimation.a").unlink(missing_ok=True)
    ret, _, stderr = run_cmd(["ar", "rcs", str(BUILD_DIR / "libsublimation.a")] + a_objs)
    if ret != 0:
        log_error(f"ar (static lib) failed: {stderr[-300:]}")
        return None
    ret, _, stderr = run_cmd(
        ["gcc", "-shared", "-o", str(BUILD_DIR / "libsublimation.so")] + so_objs + ["-lpthread", "-lm"])
    if ret != 0:
        log_error(f"shared lib link failed: {stderr[-300:]}")
        return None

    bench_bin = BUILD_DIR / "bench_c"
    cmd = [
        "gcc", "-std=c2x", "-O2", "-march=native", "-flto=auto",
        "-I", str(SRC_DIR / "include"), "-I", str(SRC_DIR),
        str(BENCH_DIR / "bench_c.c"),
        str(BUILD_DIR / "libsublimation.a"),
        "-lpthread", "-lm",
        "-o", str(bench_bin),
    ]
    ret, _, stderr = run_cmd(cmd)
    if ret != 0:
        log_error(f"C bench compile failed: {stderr[-300:]}")
        return None

    log_info(f"Built: {bench_bin}")
    return bench_bin


def build_rust_bench():
    log_info("Building Rust benchmark (sort_unstable / ipnsort)")

    bench_bin = BUILD_DIR / "bench_rust"
    cmd = [
        "rustc", "-O", "--edition", "2021",
        str(BENCH_DIR / "bench_rust.rs"),
        "-o", str(bench_bin),
    ]
    ret, _, stderr = run_cmd(cmd)
    if ret != 0:
        log_warn(f"Rust bench compile failed (skipping): {stderr[:200]}")
        return None

    log_info(f"Built: {bench_bin}")
    return bench_bin


def build_go_bench():
    log_info("Building Go benchmark (slices.Sort)")

    bench_bin = BUILD_DIR / "bench_go"
    env = {**os.environ, "GOWORK": "off"}
    cmd = [
        "go", "build",
        "-o", str(bench_bin),
        str(BENCH_DIR / "bench_go.go"),
    ]
    ret, _, stderr = run_cmd(cmd, env=env)
    if ret != 0:
        log_warn(f"Go bench compile failed (skipping): {stderr[:200]}")
        return None

    log_info(f"Built: {bench_bin}")
    return bench_bin


# THE DIRECT-FFI COMPARATORS ARE GONE, not fixed, and the distinction matters.
# They were meant to measure sublimation called over FFI from Rust and Go
# against those languages' native sorts -- a real question. But bindings/ never
# existed: not a missing bench_direct.rs, an absent directory tree. So both
# builders could only ever log a warning and return None, and every published
# run silently measured two fewer comparators than its own output implied.
# A skipped comparator that warns and continues is the worst of both; this
# release found two other gates passing while proving nothing, and this was the
# third. If the FFI comparison is wanted, write the bindings first and add the
# builder back with a hard failure.


# RUN

def run_bench(binary, size, pattern, runs):
    try:
        env = {**os.environ, "LD_LIBRARY_PATH": str(BUILD_DIR)}
        cmd = [str(binary), str(size), pattern, str(runs)]
        # Every published table is int64. bench_c otherwise measures all six
        # types against qsort, which at 100M is minutes of wall clock producing
        # columns no table shows. Other binaries ignore a 4th argument.
        if binary.name == "bench_c":
            cmd.append(os.environ.get("BENCH_TYPES", "i64"))


        # Scale with input size: one bench_c invocation runs every type variant
        # (6 qsort + 6 sublimation + introsort) x `runs` at the requested n, so
        # cost is linear in n and a fixed ceiling silently drops the largest
        # tier. A flat 300s lost 100M random / few_unique / phased entirely --
        # the rows the README headlines -- and burned the full timeout before
        # giving up on each. 20s per million elements, floored at the old 300s.
        size_timeout = max(300, int(size / 1_000_000) * 20)
        result = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=size_timeout, env=env)
        if result.returncode != 0:
            return [], ""

        results = []
        for line in result.stdout.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                results.append(obj)
            except json.JSONDecodeError:
                pass
        return results, ""
    except subprocess.TimeoutExpired:
        log_warn(f"Timeout: {binary.name} size={size} pattern={pattern}")
        return [], ""


# PYTHON BENCHMARKS (in-process, no subprocess overhead)

def _py_generate(pattern, n, seed=42):
    """Generate test data as a list of ints."""
    rng = random.Random(seed)
    if pattern == "random":
        return [rng.randint(-n*5, n*5) for _ in range(n)]
    elif pattern == "sorted":
        return list(range(n))
    elif pattern == "reversed":
        return list(range(n, 0, -1))
    elif pattern == "equal":
        return [42] * n
    elif pattern == "nearly":
        arr = list(range(n))
        swaps = max(1, n // 100)
        for _ in range(swaps):
            i, j = rng.randint(0, n-1), rng.randint(0, n-1)
            arr[i], arr[j] = arr[j], arr[i]
        return arr
    elif pattern == "few_unique":
        return [rng.randint(0, 9) for _ in range(n)]
    elif pattern == "pipe_organ":
        half = n // 2
        return list(range(half)) + list(range(half, 0, -1))
    elif pattern == "phased":
        boundary = int(n * 0.75)
        return list(range(boundary)) + [rng.randint(0, n) for _ in range(n - boundary)]
    else:
        return [rng.randint(-n*5, n*5) for _ in range(n)]


def _load_sublimation_ctypes():
    """Load libsublimation.so for Python benchmarks."""
    so = BUILD_DIR / "libsublimation.so"
    if not so.exists():
        return None
    lib = ctypes.CDLL(str(so))
    lib.sublimation_i64.argtypes = [ctypes.POINTER(ctypes.c_int64), ctypes.c_size_t]
    lib.sublimation_i64.restype = None
    return lib


def run_python_bench(pattern, size, runs):
    """Benchmark Python sorted() and sublimation-via-ctypes."""
    import time
    results = []

    # Python sorted()
    best = float('inf')
    for r in range(runs):
        data = _py_generate(pattern, size, seed=42 + r)
        t0 = time.perf_counter_ns()
        sorted(data)
        t1 = time.perf_counter_ns()
        ns = (t1 - t0) / size
        best = min(best, ns)
    results.append({"algo": "python_sorted", "ns_per_elem": round(best, 1)})

    # sublimation via ctypes
    sub_lib = _load_sublimation_ctypes()
    if sub_lib:
        best = float('inf')
        for r in range(runs):
            data = _py_generate(pattern, size, seed=42 + r)
            c_arr = (ctypes.c_int64 * size)(*data)
            t0 = time.perf_counter_ns()
            sub_lib.sublimation_i64(c_arr, size)
            t1 = time.perf_counter_ns()
            ns = (t1 - t0) / size
            best = min(best, ns)
        results.append({"algo": "sublimation_via_python", "ns_per_elem": round(best, 1)})

    return results


# MAIN

def main():
    parser = argparse.ArgumentParser(description="sublimation benchmark suite")
    parser.add_argument("--quick", action="store_true",
                       help="Quick mode: smaller sizes, fewer runs")
    parser.add_argument("--sizes", type=str, default=None,
                       help="Comma-separated sizes (e.g., 1000,100000)")
    parser.add_argument("--patterns", type=str, default=None,
                       help="Comma-separated patterns")
    parser.add_argument("--runs", type=int, default=None,
                       help="Number of runs per benchmark")
    parser.add_argument("--publish", action="store_true",
                       help="Numbers from this run are going in a document: "
                            "refuse unless the CPU governor is 'performance'")
    parser.add_argument("--stats", action="store_true",
                       help="Statistical mode: 11 runs, report min/p50/p95/p99/stddev/cv%%")
    args = parser.parse_args()

    if args.stats and not HAS_NUMPY:
        log_error("--stats requires numpy. Install with: pip install numpy")
        return 1

    if args.quick:
        sizes = [100, 1000, 10000, 100000]
        patterns = ["random", "sorted", "reversed", "nearly", "few_unique"]
        runs = 3
    else:
        sizes = [100, 1000, 10000, 100000, 1000000]
        patterns = ["random", "sorted", "reversed", "nearly",
                     "few_unique", "pipe_organ", "phased", "equal"]
        runs = 5

    if args.stats:
        runs = 11  # statistical mode overrides default

    if args.sizes:
        sizes = [int(s) for s in args.sizes.split(",")]
    if args.patterns:
        patterns = args.patterns.split(",")
    if args.runs:
        runs = args.runs  # explicit --runs always wins

    print()
    log_info("sublimation benchmark: sublimation vs the world")
    log_info(f"Sizes: {sizes}")
    log_info(f"Patterns: {patterns}")
    if args.stats:
        log_info(f"Runs: {runs} (statistical: min/p50/p95/p99/stddev/cv%)")
    else:
        log_info(f"Runs: {runs} (best of)")
    print()

    # CPU GOVERNOR. A warning here is exactly how the published README numbers
    # came to be taken on 'powersave': the run said so and nobody stopped. With
    # --publish it is a hard refusal instead, so a number that lands in a
    # document cannot be measured on an uncontrolled clock by accident. An
    # exploratory run still only warns.
    try:
        gov = open("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor").read().strip()
        if gov != "performance":
            if args.publish:
                log_error(f"CPU governor is '{gov}', not 'performance'. Refusing a "
                          f"--publish run on an uncontrolled clock. Set it with: "
                          f"sudo cpupower frequency-set -g performance")
                return 1
            log_warn(f"CPU governor is '{gov}', not 'performance'. Results may be "
                     f"noisy; do not publish them (see --publish).")
        elif args.publish:
            log_info("governor is 'performance'; this run is publishable")
    except Exception:
        if args.publish:
            log_error("cannot read the CPU governor; refusing a --publish run")
            return 1

    BUILD_DIR.mkdir(exist_ok=True)

    # build all comparison points
    c_bin = build_c_bench()
    rust_bin = build_rust_bench()
    go_bin = build_go_bench()
    print()

    if not c_bin:
        log_error("Cannot proceed without C benchmark")
        return 1

    results = Results()
    stats_results = StatsResults() if args.stats else None
    algos_seen = set()

    total = len(sizes) * len(patterns)
    done = 0

    for size in sizes:
        for pattern in patterns:
            done += 1
            log_info(f"[{done}/{total}] n={size:>10} pattern={pattern}")

            binaries = [
                ("c", c_bin),
                ("rust", rust_bin),
                ("go", go_bin),
            ]

            # Python benchmarks (in-process)
            py_results = run_python_bench(pattern, size, runs)
            for obj in py_results:
                algo = obj["algo"]
                results.add(algo, pattern, size, obj["ns_per_elem"])
                algos_seen.add(algo)
                if args.stats and stats_results:
                    stats_results.add(algo, pattern, size, obj["ns_per_elem"])

            for label, binary in binaries:
                if not binary:
                    continue

                if args.stats:
                    # statistical mode: run one-at-a-time, collect all timings
                    for _ in range(runs):
                        bench_results, _ = run_bench(
                            binary, size, pattern, 1
                        )
                        for obj in bench_results:
                            algo = obj["algo"]
                            stats_results.add(algo, pattern, size, obj["ns_per_elem"])
                            results.add(algo, pattern, size, obj["ns_per_elem"])
                            algos_seen.add(algo)
                else:
                    bench_results, _ = run_bench(
                        binary, size, pattern, runs
                    )
                    for obj in bench_results:
                        algo = obj["algo"]
                        results.add(algo, pattern, size, obj["ns_per_elem"])
                        algos_seen.add(algo)

    # print results
    # order: sublimation first, then alphabetical
    algo_order = ["sublimation"]
    for a in sorted(algos_seen):
        if a != "sublimation":
            algo_order.append(a)

    print()
    print(f"  {'=' * 90}")
    print(f"  sublimation benchmark results (ns/element, best of {runs} runs)")
    print(f"  {'=' * 90}")

    results.print_table(algo_order)

    print()
    print(f"  {'=' * 90}")
    print(f"  vs introsort: >1.00x = sublimation is faster, <1.00x = introsort is faster")
    print(f"  {'=' * 90}")

    # statistical report
    if args.stats and stats_results:
        print()
        print(f"  {'=' * 90}")
        print(f"  STATISTICAL PROFILE ({runs} runs per configuration)")
        print(f"  {'=' * 90}")
        stats_results.print_table(algo_order)

    # hardware profile
        print()
        print(f"  {'=' * 90}")
        print(f"  {'=' * 90}")

    print()

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(130)
