#!/usr/bin/env python3
"""
sublimation test suite.

Unified test + benchmark orchestrator. Builds, tests, benchmarks, and
logs results to ~/.cache/sublimation/ in Prometheus exposition format.

Usage:
    ./test.py                  Run all tests + benchmarks
    ./test.py --quick          Tests only, no benchmarks
    ./test.py --skip-build     Skip build phase
    ./test.py --verbose        Show compiler output
"""

import argparse
import ctypes
import json
import multiprocessing
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path


SCRIPT_DIR = Path(__file__).parent.resolve()
PROJECT_DIR = SCRIPT_DIR.parent
BUILD_DIR = PROJECT_DIR / "build"
SRC_DIR = PROJECT_DIR / "src"
TEST_DIR = SCRIPT_DIR  # tests/ is where we are
BENCH_DIR = SCRIPT_DIR / "bench"
LOG_DIR = Path.home() / ".cache" / "sublimation"

VERBOSE = False
VERSION = "1.2.0"


# LOGGING ([HH:MM:SS] [LEVEL]   message)

def _ts():
    return datetime.now().strftime("[%H:%M:%S]")

def log_info(msg):
    print(f"{_ts()} [INFO]   {msg}")

def log_warn(msg):
    print(f"{_ts()} [WARN]   {msg}")

def log_error(msg):
    print(f"{_ts()} [ERROR]  {msg}")


# GIT INFO

def get_git_info():
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, cwd=str(PROJECT_DIR), timeout=5,
        ).stdout.strip()
        dirty = subprocess.run(
            ["git", "diff", "--quiet"],
            capture_output=True, cwd=str(PROJECT_DIR), timeout=5,
        ).returncode != 0
        return {"commit": commit or "unknown", "dirty": dirty}
    except Exception:
        return {"commit": "unknown", "dirty": False}


# RESULTS TRACKER

class Results:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.skipped = 0
        self.sections = []
        self.bench_data = {}  # (pattern, size) -> {algo: ns_per_elem}
        self.scaling_data = {}  # cores -> ns_per_elem
        self.start_time = time.time()

    def section(self, name):
        print(f"\n  {'=' * 64}")
        print(f"  {name}")
        print(f"  {'=' * 64}")
        self.sections.append(name)

    def ok(self, msg):
        print(f"  [PASS] {msg}")
        self.passed += 1

    def fail(self, msg, detail=None):
        print(f"  [FAIL] {msg}")
        if detail:
            for line in detail.strip().split('\n')[:5]:
                print(f"         {line}")
        self.failed += 1

    def skip(self, msg, reason=None):
        extra = f" ({reason})" if reason else ""
        print(f"  [SKIP] {msg}{extra}")
        self.skipped += 1

    def summary(self):
        elapsed = time.time() - self.start_time
        total = self.passed + self.failed + self.skipped
        print(f"\n  {'=' * 64}")
        print(f"  RESULTS: {self.passed} passed, {self.failed} failed, "
              f"{self.skipped} skipped (of {total}) in {elapsed:.1f}s")
        print(f"  {'=' * 64}\n")
        return self.failed == 0


def run_cmd(cmd, timeout=300, cwd=None, env=None):
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, cwd=cwd, env=env,
        )
        if VERBOSE and result.stderr.strip():
            for line in result.stderr.strip().split('\n')[:5]:
                print(f"    {line}")
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "TIMEOUT"
    except FileNotFoundError:
        return -2, "", "NOT FOUND"


# BUILD

def build_library(R):
    R.section("BUILD")
    ret, _, stderr = run_cmd(
        [sys.executable, str(PROJECT_DIR / "install.py"), "build"],
        cwd=str(PROJECT_DIR),
    )
    if ret == 0:
        static = BUILD_DIR / "libsublimation.a"
        shared = BUILD_DIR / "libsublimation.so"
        if static.exists() and shared.exists():
            R.ok(f"libsublimation.a ({static.stat().st_size} bytes)")
            R.ok(f"libsublimation.so ({shared.stat().st_size} bytes)")
        else:
            R.fail("library files not found after build")
    else:
        R.fail("build failed", stderr[-300:])


def compile_c(name, src, extra_flags=None, lib_name="libsublimation.a"):
    out = BUILD_DIR / name
    cmd = [
        "gcc", "-std=c2x", "-O2", "-march=native",
        "-I", str(SRC_DIR / "include"), "-I", str(SRC_DIR),
        str(src), str(BUILD_DIR / lib_name),
        "-lpthread", "-lm", "-o", str(out),
    ]
    if extra_flags:
        cmd[2:2] = extra_flags
    ret, _, stderr = run_cmd(cmd, timeout=30)
    return out if ret == 0 else None


def run_c_test(R, name, binary, timeout=120):
    if not binary or not binary.exists():
        R.skip(name, "binary not found")
        return
    env = {**os.environ, "ASAN_OPTIONS": "detect_leaks=0"}
    ret, stdout, stderr = run_cmd([str(binary)], timeout=timeout, env=env)
    for line in (stdout + stderr).split('\n'):
        m = re.search(r'(\d+)\s+passed.*?(\d+)\s+failed', line.strip())
        if m:
            passed, failed = int(m.group(1)), int(m.group(2))
            R.passed += passed
            if failed > 0:
                R.failed += failed
                R.fail(f"{name}: {passed} passed, {failed} failed")
            else:
                R.ok(f"{name}: {passed} passed")
            return
    if ret == 0:
        R.ok(f"{name}: completed")
    else:
        R.fail(f"{name}: exit code {ret}", stderr[-200:])


# C TEST SUITES

def test_c_suites(R):
    R.section("CORRECTNESS")
    for name, src, timeout in [
        ("basic",       TEST_DIR / "test_basic.c",        60),
        ("tier1",       TEST_DIR / "test_tier1.c",       120),
        ("tier2",       TEST_DIR / "test_tier2.c",       120),
        ("tier4",       TEST_DIR / "test_tier4.c",       300),
        ("tier5",       TEST_DIR / "test_tier5.c",       120),
        ("adversarial", TEST_DIR / "test_adversarial.c", 300),
        ("bentley_mcilroy", TEST_DIR / "test_bentley_mcilroy.c", 120),
        ("types",       TEST_DIR / "test_types.c",       300),
        ("adversarial_types", TEST_DIR / "test_adversarial_types.c", 300),
        ("sorted_perturbed",  TEST_DIR / "test_sorted_perturbed.c",  120),
        ("zipfian",           TEST_DIR / "test_zipfian.c",           120),
        ("saw_mixed",         TEST_DIR / "test_saw_mixed.c",         120),
        ("antiqsort",         TEST_DIR / "test_antiqsort.c",         300),
        ("strings",           TEST_DIR / "test_strings.c",           120),
    ]:
        if not src.exists():
            R.skip(name, "source not found")
            continue
        binary = compile_c(f"test_{name}", src)
        if not binary:
            R.fail(f"{name}: compile failed")
            continue
        run_c_test(R, name, binary, timeout)


# THREAD SANITIZER

def test_tsan(R):
    R.section("THREAD SANITIZER")
    src = TEST_DIR / "test_basic.c"
    if not src.exists():
        R.skip("tsan", "source not found")
        return

    tsan_objects = []
    for f in sorted(SRC_DIR.glob("**/*.c")):
        obj = BUILD_DIR / f"tsan_{f.stem}.o"
        ret, _, _ = run_cmd([
            "gcc", "-std=c2x", "-O1", "-g", "-fsanitize=thread", "-fPIC",
            "-I", str(SRC_DIR / "include"), "-I", str(SRC_DIR),
            "-c", str(f), "-o", str(obj),
        ], timeout=30)
        if ret != 0:
            R.fail(f"tsan compile: {f.name}")
            return
        tsan_objects.append(obj)

    tsan_lib = BUILD_DIR / "libsublimation_tsan.a"
    run_cmd(["ar", "rcs", str(tsan_lib)] + [str(o) for o in tsan_objects], timeout=10)

    tsan_bin = compile_c("test_tsan", src, ["-O1", "-g", "-fsanitize=thread"], "libsublimation_tsan.a")
    if not tsan_bin:
        R.fail("tsan link failed")
        return

    ret, stdout, stderr = run_cmd([str(tsan_bin)], timeout=120)
    races = [l for l in stderr.split('\n') if 'ThreadSanitizer' in l and 'WARNING' in l]
    if races:
        R.fail(f"tsan: {len(races)} race(s)", '\n'.join(races[:3]))
    else:
        m = re.search(r'(\d+)\s+passed', stdout)
        count = m.group(1) if m else "?"
        R.ok(f"tsan: {count} tests, 0 races")

    # tier5 under TSan (exercises parallel path)
    tier5_src = TEST_DIR / "test_tier5.c"
    if tier5_src.exists():
        tsan_tier5 = compile_c("test_tsan_tier5", tier5_src,
                               ["-O1", "-g", "-fsanitize=thread"], "libsublimation_tsan.a")
        if tsan_tier5:
            ret, stdout, stderr = run_cmd([str(tsan_tier5)], timeout=120)
            races = [l for l in stderr.split('\n') if 'ThreadSanitizer' in l and 'WARNING' in l]
            if races:
                R.fail(f"tsan_tier5: {len(races)} race(s)", '\n'.join(races[:3]))
            else:
                m = re.search(r'(\d+)\s+passed', stdout)
                count = m.group(1) if m else "?"
                R.ok(f"tsan_tier5: {count} tests, 0 races")


# ADDRESS SANITIZER

def test_asan(R):
    R.section("ADDRESS SANITIZER")
    src = TEST_DIR / "test_basic.c"
    if not src.exists():
        R.skip("asan", "source not found")
        return

    asan_objects = []
    for f in sorted(SRC_DIR.glob("**/*.c")):
        obj = BUILD_DIR / f"asan_{f.stem}.o"
        ret, _, stderr = run_cmd([
            "gcc", "-std=c2x", "-O1", "-g",
            "-fsanitize=address,undefined",
            "-fno-omit-frame-pointer", "-fPIC",
            "-I", str(SRC_DIR / "include"), "-I", str(SRC_DIR),
            "-c", str(f), "-o", str(obj),
        ], timeout=30)
        if ret != 0:
            R.fail(f"asan compile: {f.name}")
            return
        asan_objects.append(obj)

    asan_lib = BUILD_DIR / "libsublimation_asan.a"
    run_cmd(["ar", "rcs", str(asan_lib)] + [str(o) for o in asan_objects], timeout=10)

    asan_bin = compile_c("test_asan", src,
                         ["-O1", "-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer"],
                         "libsublimation_asan.a")
    if not asan_bin:
        R.fail("asan link failed")
        return

    env = {**os.environ, "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1"}
    ret, stdout, stderr = run_cmd([str(asan_bin)], timeout=120, env=env)
    asan_errors = [l for l in stderr.split('\n')
                   if 'ERROR: AddressSanitizer' in l or 'ERROR: UndefinedBehaviorSanitizer' in l
                   or 'runtime error:' in l]
    if asan_errors:
        R.fail(f"asan: {len(asan_errors)} error(s)", '\n'.join(asan_errors[:5]))
    else:
        m = re.search(r'(\d+)\s+passed', stdout)
        count = m.group(1) if m else "?"
        R.ok(f"asan: {count} tests, 0 errors")

    # tier5 under ASan (exercises parallel path + spectral allocations)
    tier5_src = TEST_DIR / "test_tier5.c"
    if tier5_src.exists():
        asan_tier5 = compile_c("test_asan_tier5", tier5_src,
                               ["-O1", "-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer"],
                               "libsublimation_asan.a")
        if asan_tier5:
            ret, stdout, stderr = run_cmd([str(asan_tier5)], timeout=120, env=env)
            asan_errors = [l for l in stderr.split('\n')
                           if 'ERROR: AddressSanitizer' in l or 'ERROR: UndefinedBehaviorSanitizer' in l
                           or 'runtime error:' in l]
            if asan_errors:
                R.fail(f"asan_tier5: {len(asan_errors)} error(s)", '\n'.join(asan_errors[:5]))
            else:
                m = re.search(r'(\d+)\s+passed', stdout)
                count = m.group(1) if m else "?"
                R.ok(f"asan_tier5: {count} tests, 0 errors")


# CROSS-LANGUAGE ROUNDTRIP

def test_crosslang(R):
    R.section("CROSS-LANGUAGE ROUNDTRIP")
    lib_path = BUILD_DIR / "libsublimation.so"
    if not lib_path.exists():
        R.skip("crosslang", ".so not found")
        return

    try:
        lib = ctypes.CDLL(str(lib_path))
        lib.sublimation_i64.argtypes = [ctypes.POINTER(ctypes.c_int64), ctypes.c_size_t]
        lib.sublimation_i64.restype = None
        lib.sublimation_i64_parallel.argtypes = [
            ctypes.POINTER(ctypes.c_int64), ctypes.c_size_t, ctypes.c_size_t
        ]
        lib.sublimation_i64_parallel.restype = None
    except OSError as e:
        R.fail(f"crosslang: {e}")
        return

    def lcg(s):
        return (s * 6364136223846793005 + 1442695040888963407) & ((1 << 64) - 1)

    seed = 0x5B1174710
    for n, label, parallel in [(10000, "sequential", False), (200000, "parallel", True)]:
        data = []
        s = seed
        for _ in range(n):
            s = lcg(s)
            data.append(ctypes.c_int64(s >> 16).value)

        c_arr = (ctypes.c_int64 * n)(*data)
        if parallel:
            lib.sublimation_i64_parallel(c_arr, n, 4)
        else:
            lib.sublimation_i64(c_arr, n)

        if list(c_arr) == sorted(data):
            R.ok(f"C {label} == Python sorted() ({n} elements)")
        else:
            R.fail(f"C {label} != Python sorted()")


# BENCHMARKS (all comparison points)

def build_bench_binaries():
    """Build all comparison binaries. Returns dict of name -> path."""
    bins = {}

    # C bench (sublimation + qsort + introsort)
    b = compile_c("bench_c", BENCH_DIR / "bench_c.c")
    if b:
        bins["c"] = b

    # Rust standalone
    rust_bin = BUILD_DIR / "bench_rust"
    ret, _, _ = run_cmd([
        "rustc", "-O", "--edition", "2021",
        str(BENCH_DIR / "bench_rust.rs"), "-o", str(rust_bin),
    ], timeout=60)
    if ret == 0:
        bins["rust"] = rust_bin

    # Go standalone
    go_bin = BUILD_DIR / "bench_go"
    env = {**os.environ, "GOWORK": "off"}
    ret, _, _ = run_cmd(
        ["go", "build", "-o", str(go_bin), str(BENCH_DIR / "bench_go.go")],
        timeout=60, env=env,
    )
    if ret == 0:
        bins["go"] = go_bin

    # Rust direct (sublimation linked)
    rust_direct = BUILD_DIR / "bench_rust_direct"
    ret, _, _ = run_cmd([
        "rustc", "-O", "--edition", "2021",
        "-L", str(BUILD_DIR), "-l", "dylib=sublimation",
        "-l", "dylib=pthread", "-l", "dylib=m",
        str(PROJECT_DIR / "bindings" / "rust" / "bench_direct.rs"),
        "-o", str(rust_direct),
    ], timeout=60)
    if ret == 0:
        bins["rust_direct"] = rust_direct

    # Go direct (sublimation via cgo)
    go_direct = BUILD_DIR / "bench_go_direct"
    env_cgo = {**os.environ, "GOWORK": "off", "CGO_ENABLED": "1"}
    ret, _, _ = run_cmd(
        ["go", "build", "-o", str(go_direct),
         str(PROJECT_DIR / "bindings" / "go" / "bench_direct.go")],
        timeout=60, env=env_cgo,
    )
    if ret == 0:
        bins["go_direct"] = go_direct

    return bins


def run_bench(binary, size, pattern, runs):
    env = {**os.environ, "LD_LIBRARY_PATH": str(BUILD_DIR)}
    ret, stdout, _ = run_cmd(
        [str(binary), str(size), pattern, str(runs)],
        timeout=120, env=env,
    )
    results = []
    if ret == 0:
        for line in stdout.strip().split('\n'):
            try:
                results.append(json.loads(line.strip()))
            except (json.JSONDecodeError, ValueError):
                pass
    return results


def test_benchmark(R):
    R.section("BENCHMARK (all comparison points)")

    bins = build_bench_binaries()
    built = [k for k in bins]
    log_info(f"Built: {', '.join(built)}")

    if "c" not in bins:
        R.fail("C bench binary not found")
        return

    patterns = ["random", "sorted", "reversed", "nearly", "few_unique", "pipe_organ", "equal"]
    sizes = [1000, 10000, 100000]

    all_data = {}  # (pattern, size) -> {algo: ns}

    for size in sizes:
        for pattern in patterns:
            key = (pattern, size)
            all_data[key] = {}

            for bname, binary in bins.items():
                for obj in run_bench(binary, size, pattern, 3):
                    all_data[key][obj["algo"]] = obj["ns_per_elem"]

    # determine all algorithms seen
    all_algos = set()
    for d in all_data.values():
        all_algos.update(d.keys())

    # preferred column order
    order = ["sublimation", "introsort", "qsort",
             "go_slices_sort", "rust_sort_unstable",
             "sublimation_via_rust", "rust_sort_unstable_direct",
             "sublimation_via_go", "go_slices_sort_direct"]
    algo_cols = [a for a in order if a in all_algos]

    # print table per pattern
    for pattern in patterns:
        print(f"\n  Pattern: {pattern}")
        header = f"  {'N':>8}"
        for algo in algo_cols:
            short = algo.replace("_sort_unstable", "").replace("_slices_sort", "")
            short = short.replace("_direct", "(d)").replace("sublimation_via_", "sub/")
            header += f"  {short:>14}"
        header += f"  {'vs intro':>10}"
        print(header)

        for size in sizes:
            key = (pattern, size)
            d = all_data.get(key, {})
            row = f"  {size:>8}"
            sub_ns = d.get("sublimation")
            intro_ns = d.get("introsort")
            for algo in algo_cols:
                ns = d.get(algo)
                if ns is not None:
                    row += f"  {ns:>11.1f}ns"
                else:
                    row += f"  {'':>14}"
            if sub_ns and intro_ns and sub_ns > 0:
                row += f"  {intro_ns/sub_ns:>8.2f}x"
            print(row)

    R.ok(f"benchmark: {len(patterns)} patterns x {len(sizes)} sizes x {len(bins)} binaries")
    R.bench_data = all_data


# CORE SCALING

def test_scaling(R):
    R.section("CORE SCALING")

    bench = BUILD_DIR / "bench_c"
    if not bench.exists():
        bench = compile_c("bench_c", BENCH_DIR / "bench_c.c")
    if not bench or not bench.exists():
        R.skip("scaling", "bench binary not found")
        return

    max_cpus = multiprocessing.cpu_count()
    cores = sorted(set([c for c in [1, 2, 4, 8, max_cpus] if c <= max_cpus]))

    for c in cores:
        mask = ",".join(str(i) for i in range(c))
        env = {**os.environ, "LD_LIBRARY_PATH": str(BUILD_DIR)}
        ret, stdout, _ = run_cmd(
            ["taskset", "-c", mask, str(bench), "1000000", "random", "3"],
            timeout=60, env=env,
        )
        if ret == 0:
            for line in stdout.strip().split('\n'):
                try:
                    obj = json.loads(line.strip())
                    if obj.get("algo") == "sublimation":
                        R.scaling_data[c] = obj["ns_per_elem"]
                except (json.JSONDecodeError, KeyError, ValueError):
                    pass

    if not R.scaling_data:
        R.skip("scaling", "no results")
        return

    baseline = R.scaling_data.get(1, list(R.scaling_data.values())[0])
    print(f"\n  {'Cores':>6}  {'ns/elem':>10}  {'Speedup':>8}  {'Efficiency':>10}")
    for c in sorted(R.scaling_data.keys()):
        ns = R.scaling_data[c]
        spd = baseline / ns if ns > 0 else 0
        eff = spd / c * 100
        print(f"  {c:>6}  {ns:>9.1f}  {spd:>7.2f}x  {eff:>8.1f}%")

    R.ok(f"scaling: {len(R.scaling_data)} core counts")


# PROMETHEUS + REPORT OUTPUT

def write_prometheus(R, git, stamp):
    lines = []
    emitted = set()

    def gauge(name, help_text, value, labels=None):
        if name not in emitted:
            lines.append(f"# HELP {name} {help_text}")
            lines.append(f"# TYPE {name} gauge")
            emitted.add(name)
        if labels:
            label_str = ",".join(f'{k}="{v}"' for k, v in labels.items())
            lines.append(f"{name}{{{label_str}}} {value}")
        else:
            lines.append(f"{name} {value}")

    dirty = "true" if git["dirty"] else "false"
    gauge("sublimation_info", "Build metadata", 1,
          {"version": VERSION, "git_commit": git["commit"], "git_dirty": dirty})
    gauge("sublimation_tests_passed", "Total tests passed", R.passed)
    gauge("sublimation_tests_failed", "Total tests failed", R.failed)
    gauge("sublimation_cpus", "CPUs available", multiprocessing.cpu_count())

    for (pattern, size), algos in R.bench_data.items():
        for algo, ns in algos.items():
            gauge("sublimation_bench_ns_per_elem",
                  "Benchmark ns/element",
                  f"{ns:.2f}",
                  {"pattern": pattern, "size": str(size), "algo": algo})

    for cores, ns in R.scaling_data.items():
        gauge("sublimation_scaling_ns_per_elem",
              "Scaling ns/element",
              f"{ns:.2f}",
              {"cores": str(cores)})

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    path = LOG_DIR / f"test-{VERSION}-{stamp}.prom"
    path.write_text("\n".join(lines) + "\n")
    return path


def write_report(R, git, stamp):
    report = []
    dirty = " (dirty)" if git["dirty"] else ""
    report.append(f"sublimation v{VERSION} [{git['commit']}{dirty}]")
    report.append(f"cpus: {multiprocessing.cpu_count()}  "
                  f"tests: {R.passed} passed, {R.failed} failed")
    report.append("")

    if R.bench_data:
        patterns = sorted(set(p for p, _ in R.bench_data.keys()))
        sizes = sorted(set(s for _, s in R.bench_data.keys()))
        algos = ["sublimation", "introsort", "qsort",
                 "go_slices_sort", "rust_sort_unstable"]

        header = f"{'PATTERN':<15} {'SIZE':>8}"
        for a in algos:
            short = a[:12]
            header += f" {short:>12}"
        report.append(header)

        for pattern in patterns:
            for size in sizes:
                d = R.bench_data.get((pattern, size), {})
                row = f"{pattern:<15} {size:>8}"
                for a in algos:
                    ns = d.get(a)
                    row += f" {ns:>10.1f}ns" if ns else f" {'':>12}"
                report.append(row)

    if R.scaling_data:
        report.append("")
        report.append(f"{'CORES':>6} {'NS/ELEM':>10} {'SPEEDUP':>8}")
        baseline = R.scaling_data.get(1, list(R.scaling_data.values())[0])
        for c in sorted(R.scaling_data.keys()):
            ns = R.scaling_data[c]
            spd = baseline / ns if ns > 0 else 0
            report.append(f"{c:>6} {ns:>9.1f} {spd:>7.2f}x")

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    path = LOG_DIR / f"test-{VERSION}-{stamp}.log"
    path.write_text("\n".join(report) + "\n")
    return path


# MAIN

bins_cache = {}

def main():
    global VERBOSE, bins_cache

    parser = argparse.ArgumentParser(description="sublimation test suite")
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--quick", action="store_true", help="Tests only, no bench")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()
    VERBOSE = args.verbose

    R = Results()
    git = get_git_info()
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    dirty = " (dirty)" if git["dirty"] else ""

    print()
    log_info(f"sublimation v{VERSION} [{git['commit']}{dirty}]")
    log_info(f"Source: {PROJECT_DIR}")
    log_info(f"CPUs: {multiprocessing.cpu_count()}")

    BUILD_DIR.mkdir(exist_ok=True)

    if not args.skip_build:
        build_library(R)

    test_c_suites(R)
    test_tsan(R)
    test_asan(R)
    test_crosslang(R)

    if not args.quick:
        test_benchmark(R)
        test_scaling(R)

    # write logs
    prom_path = write_prometheus(R, git, stamp)
    report_path = write_report(R, git, stamp)

    success = R.summary()

    log_info(f"Report:     {report_path}")
    log_info(f"Prometheus: {prom_path}")

    # print the report
    print()
    print(report_path.read_text())

    return 0 if success else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(130)
