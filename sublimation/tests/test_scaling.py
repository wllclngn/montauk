#!/usr/bin/env python3
"""
sublimation core scaling sweep.

Measures ns/element for 1M random at different core counts using taskset.
Reports speedup and parallel efficiency.

Usage:
    python3 tests/test_scaling.py
    python3 tests/test_scaling.py --size 10000000
"""
import argparse
import csv
import json
import multiprocessing
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent.resolve()
PROJECT_DIR = SCRIPT_DIR.parent
BUILD_DIR = PROJECT_DIR / "build"
BENCH_DIR = SCRIPT_DIR / "bench"
SRC_DIR = PROJECT_DIR / "src"

def _ts():
    return datetime.now().strftime("[%H:%M:%S]")

def log(msg):
    print(f"{_ts()} [INFO]   {msg}")

def build():
    log("Building...")
    ret = subprocess.run(
        [sys.executable, str(PROJECT_DIR / "install.py"), "build"],
        capture_output=True, cwd=str(PROJECT_DIR)
    )
    if ret.returncode != 0:
        print("Build failed")
        sys.exit(1)

    bench = BUILD_DIR / "bench_c"
    ret = subprocess.run([
        "gcc", "-std=c2x", "-O2", "-march=native", "-flto=auto",
        "-I", str(SRC_DIR / "include"), "-I", str(SRC_DIR),
        str(BENCH_DIR / "bench_c.c"),
        str(BUILD_DIR / "libsublimation.a"),
        "-lpthread", "-lm", "-o", str(bench),
    ], capture_output=True)
    if ret.returncode != 0:
        print("Bench compile failed")
        sys.exit(1)
    return bench

def get_max_cpus():
    return multiprocessing.cpu_count()

def run_with_cores(bench, n_cores, size, runs, pattern="random"):
    """Run benchmark restricted to n_cores CPUs via taskset."""
    # build CPU mask: cores 0 to n_cores-1
    mask = ",".join(str(i) for i in range(n_cores))
    cmd = ["taskset", "-c", mask, str(bench), str(size), pattern, str(runs)]

    try:
        ret = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if ret.returncode != 0:
            return None

        for line in ret.stdout.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if obj.get("algo") == "sublimation":
                    return obj["ns_per_elem"]
            except (json.JSONDecodeError, KeyError):
                pass
    except subprocess.TimeoutExpired:
        return None

    return None

def run_single_threaded(bench, size, runs, pattern="random"):
    """Run benchmark with taskset pinning to a single core (core 0)."""
    cmd = ["taskset", "-c", "0", str(bench), str(size), pattern, str(runs)]
    try:
        ret = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if ret.returncode != 0:
            return None
        for line in ret.stdout.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if obj.get("algo") == "sublimation":
                    return obj["ns_per_elem"]
            except (json.JSONDecodeError, KeyError):
                pass
    except subprocess.TimeoutExpired:
        return None
    return None


def sweep(args):
    """Logarithmic size sweep: reveals cache-level transitions."""
    sweep_sizes = [64, 256, 1_000, 4_000, 16_000, 64_000, 256_000, 1_000_000, 4_000_000]
    runs = args.runs

    print()
    log(f"sublimation size sweep (single-threaded, random)")
    log(f"Sizes: {[_fmt_size(s) for s in sweep_sizes]}")
    log(f"Runs: {runs} (best of)")
    print()

    # CPU governor warning
    try:
        gov = open("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor").read().strip()
        if gov != "performance":
            log(f"WARNING: CPU governor is '{gov}', not 'performance'. Results may be noisy.")
    except Exception:
        pass

    bench = build()
    log(f"Built: {bench}")
    print()

    results = {}
    for size in sweep_sizes:
        log(f"  n={_fmt_size(size):>6} ...")
        ns = run_single_threaded(bench, size, runs, "random")
        if ns is not None:
            results[size] = ns
            log(f"  n={_fmt_size(size):>6}: {ns:.1f} ns/elem")
        else:
            log(f"  n={_fmt_size(size):>6}: FAILED")

    if not results:
        log("No results.")
        return 1

    # print table
    print()
    print(f"  {'N':>10}  {'ns/elem':>10}  {'bytes':>12}  {'cache level':>12}")
    for size in sweep_sizes:
        ns = results.get(size)
        if ns is None:
            continue
        nbytes = size * 8  # int64_t = 8 bytes
        if nbytes <= 32 * 1024:
            level = "L1d"
        elif nbytes <= 256 * 1024:
            level = "L2"
        elif nbytes <= 8 * 1024 * 1024:
            level = "L3"
        else:
            level = "DRAM"
        print(f"  {_fmt_size(size):>10}  {ns:>8.1f}ns  {_fmt_bytes(nbytes):>12}  {level:>12}")

    # write CSV
    cache_dir = Path.home() / ".cache" / "sublimation"
    cache_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    csv_path = cache_dir / f"scaling-sweep-{timestamp}.csv"

    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["size", "ns_per_elem", "bytes", "cache_level"])
        for size in sweep_sizes:
            ns = results.get(size)
            if ns is None:
                continue
            nbytes = size * 8
            if nbytes <= 32 * 1024:
                level = "L1d"
            elif nbytes <= 256 * 1024:
                level = "L2"
            elif nbytes <= 8 * 1024 * 1024:
                level = "L3"
            else:
                level = "DRAM"
            writer.writerow([size, f"{ns:.2f}", nbytes, level])

    print()
    log(f"CSV written: {csv_path}")
    print()
    return 0


def _fmt_size(n):
    if n >= 1_000_000:
        return f"{n // 1_000_000}M"
    elif n >= 1_000:
        return f"{n // 1_000}K"
    return str(n)


def _fmt_bytes(n):
    if n >= 1024 * 1024:
        return f"{n / (1024 * 1024):.1f} MiB"
    elif n >= 1024:
        return f"{n / 1024:.1f} KiB"
    return f"{n} B"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--size", type=int, default=1000000)
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--pattern", type=str, default="random")
    parser.add_argument("--sweep", action="store_true",
                       help="Logarithmic size sweep (single-threaded): "
                            "64 to 4M, reveals cache-level transitions")
    args = parser.parse_args()

    if args.sweep:
        return sweep(args)

    max_cpus = get_max_cpus()
    core_counts = [1, 2, 4]
    if max_cpus >= 6:
        core_counts.append(6)
    if max_cpus >= 8:
        core_counts.append(8)
    if max_cpus >= 12:
        core_counts.append(12)
    if max_cpus >= 16:
        core_counts.append(max_cpus)

    print()
    log(f"sublimation core scaling sweep")
    log(f"n={args.size}, pattern={args.pattern}, runs={args.runs}")
    log(f"max CPUs: {max_cpus}")
    print()

    bench = build()
    log(f"Built: {bench}")
    print()

    results = {}
    for cores in core_counts:
        log(f"Testing {cores}C...")
        ns = run_with_cores(bench, cores, args.size, args.runs, args.pattern)
        if ns is not None:
            results[cores] = ns
            log(f"  {cores}C: {ns:.1f} ns/elem")
        else:
            log(f"  {cores}C: FAILED")

    print()
    if not results:
        log("No results.")
        return 1

    baseline = results.get(1)
    if not baseline:
        baseline = list(results.values())[0]

    print(f"  {'Cores':>6}  {'ns/elem':>10}  {'Speedup':>8}  {'Efficiency':>10}")
    for cores in sorted(results.keys()):
        ns = results[cores]
        speedup = baseline / ns if ns > 0 else 0
        efficiency = speedup / cores * 100
        marker = ""
        if speedup > cores * 0.8:
            marker = " (super-linear)"
        elif efficiency < 50:
            marker = " (plateau)"
        print(f"  {cores:>6}  {ns:>9.1f}  {speedup:>7.2f}x  {efficiency:>8.1f}%{marker}")

    print()
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(130)
