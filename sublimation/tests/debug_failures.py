#!/usr/bin/env python3
"""
Debug failing sort patterns. Generates test data, sorts via sublimation,
checks correctness, and traces the classification path to find where
the corruption happens.
"""
import ctypes
import os
import sys
import struct
from pathlib import Path
from datetime import datetime

def _ts():
    return datetime.now().strftime("[%H:%M:%S]")

def log(msg):
    print(f"{_ts()} [INFO]   {msg}")

def fail(msg):
    print(f"{_ts()} [FAIL]   {msg}")

def ok(msg):
    print(f"{_ts()} [PASS]   {msg}")

# load libsublimation
lib_path = Path(__file__).parent.parent / "build" / "libsublimation.so"
if not lib_path.exists():
    print(f"ERROR: {lib_path} not found. Run ./install.py build first.")
    sys.exit(1)

lib = ctypes.CDLL(str(lib_path))
lib.sublimation_i64.argtypes = [ctypes.POINTER(ctypes.c_int64), ctypes.c_size_t]
lib.sublimation_i64.restype = None

lib.sublimation_classify_i64.argtypes = [ctypes.POINTER(ctypes.c_int64), ctypes.c_size_t]
# profile struct: n, run_count, mono_count, max_run_len, lis_length,
#                 distinct_estimate, inversion_ratio, phase_boundary,
#                 spectral_gap, spectral_gap_ratio, disorder
# Let's just call and check via sort correctness -- the struct layout
# is complex to marshal from Python.

def lcg(seed):
    return (seed * 6364136223846793005 + 1442695040888963407) & ((1 << 64) - 1)

def fill_random(n, seed):
    arr = []
    s = seed
    for _ in range(n):
        s = lcg(s)
        arr.append(ctypes.c_int64(s >> 16).value)
    return arr

def fill_sorted_random_tail(n, seed):
    boundary = n * 3 // 4
    arr = list(range(boundary))
    s = seed
    for _ in range(n - boundary):
        s = lcg(s)
        arr.append(ctypes.c_int64(s >> 16).value)
    return arr

def fill_reverse_random_tail(n, seed):
    boundary = n * 3 // 4
    arr = list(range(boundary, 0, -1))
    s = seed
    for _ in range(n - boundary):
        s = lcg(s)
        arr.append(ctypes.c_int64(s >> 16).value)
    return arr

def fill_mcilroy_lite(n, seed):
    arr = list(range(n))
    s = seed
    for i in range(0, n, 8):
        s = lcg(s)
        arr[i] = ctypes.c_int64(s >> 16).value
    return arr

def fill_disp1(n, seed):
    arr = list(range(n))
    s = seed
    for i in range(n):
        s = lcg(s)
        j = i + int((s >> 33) % 2)
        if j >= n:
            j = n - 1
        arr[i], arr[j] = arr[j], arr[i]
    return arr

def fill_sorted_random_middle(n, seed):
    arr = list(range(n))
    start = n // 4
    end = n * 3 // 4
    s = seed
    for i in range(start, end):
        s = lcg(s)
        arr[i] = ctypes.c_int64(s >> 16).value
    return arr

def sort_and_check(name, arr):
    n = len(arr)
    original = list(arr)
    expected = sorted(original)

    c_arr = (ctypes.c_int64 * n)(*arr)
    lib.sublimation_i64(c_arr, n)
    result = list(c_arr)

    # check sorted
    sorted_ok = all(result[i] <= result[i+1] for i in range(n-1))

    # check permutation (same multiset)
    perm_ok = sorted(result) == expected

    if sorted_ok and perm_ok:
        ok(f"{name} (n={n})")
        return True

    if not sorted_ok:
        for i in range(n-1):
            if result[i] > result[i+1]:
                fail(f"{name} (n={n}): NOT SORTED at [{i}]: {result[i]} > {result[i+1]}")

                # show context around failure
                lo = max(0, i - 3)
                hi = min(n, i + 5)
                print(f"         result[{lo}:{hi}] = {result[lo:hi]}")
                print(f"         expected[{lo}:{hi}] = {expected[lo:hi]}")

                # find where the bad value came from in the original
                bad_val = result[i]
                orig_positions = [j for j, v in enumerate(original) if v == bad_val]
                print(f"         bad value {bad_val} was at original positions: {orig_positions}")

                break

    if not perm_ok:
        # find first difference
        sr = sorted(result)
        for i in range(n):
            if sr[i] != expected[i]:
                fail(f"{name} (n={n}): NOT PERMUTATION at [{i}]: got {sr[i]}, expected {expected[i]}")
                break

    return False


def run_pattern(name, fill_fn, sizes, seed=0xDEADC0DE):
    for n in sizes:
        arr = fill_fn(n, seed)
        sort_and_check(name, arr)


def main():
    print()
    log("sublimation debug: tracing failing patterns")
    print()

    sizes = [100, 500, 1000, 5000, 10000]
    large_sizes = [100000]

    log("SORTED + RANDOM TAIL")
    run_pattern("sorted_random_tail", fill_sorted_random_tail, sizes)
    print()

    log("REVERSE + RANDOM TAIL")
    run_pattern("reverse_random_tail", fill_reverse_random_tail, sizes)
    print()

    log("MCILROY LITE")
    run_pattern("mcilroy_lite", fill_mcilroy_lite, sizes)
    print()

    log("DISPLACEMENT 1")
    run_pattern("disp_1", fill_disp1, sizes, seed=0xABCDEF01)
    print()

    log("SORTED + RANDOM MIDDLE")
    run_pattern("sorted_random_middle", fill_sorted_random_middle, sizes, seed=0xCAFEBABE)
    print()

    log("RANDOM (control)")
    run_pattern("random", fill_random, sizes, seed=42)
    print()

    log("LARGE PATTERNS")
    run_pattern("sorted_random_tail_large", fill_sorted_random_tail, large_sizes)
    run_pattern("mcilroy_lite_large", fill_mcilroy_lite, large_sizes)
    run_pattern("disp_1_large", fill_disp1, large_sizes, seed=0xABCDEF01)
    print()

    # direct small test to isolate merge_pair
    log("MANUAL MERGE TEST: 10 sorted + 10 random")
    arr = list(range(10)) + fill_random(10, 99)
    sort_and_check("manual_10_10", arr)

    log("MANUAL MERGE TEST: 50 sorted + 50 random")
    arr = list(range(50)) + fill_random(50, 99)
    sort_and_check("manual_50_50", arr)

    log("MANUAL MERGE TEST: 100 sorted + 100 random")
    arr = list(range(100)) + fill_random(100, 99)
    sort_and_check("manual_100_100", arr)

    log("MANUAL MERGE TEST: 500 sorted + 500 random")
    arr = list(range(500)) + fill_random(500, 99)
    sort_and_check("manual_500_500", arr)

    print()
    log("Done.")


if __name__ == "__main__":
    main()
