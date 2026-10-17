#!/usr/bin/env python3
"""Emit sublimation/src/text/pow10_cache.h, the binary64 cache Dragonbox reads.

Entry k holds ceil(10^k * 2^(127 - floor(k * log2 10))) for k in [-292, 326]:
10^k scaled into [2^127, 2^128), rounded up, as two 64-bit halves. Computed
here in exact integer arithmetic, so the table is derived rather than copied.

    python3 sublimation/tools/genpow10.py > sublimation/src/text/pow10_cache.h
"""
MIN_K, MAX_K = -292, 326


def floor_log2_pow10(k):
    return (k * 1741647) >> 19


def entry(k):
    e = floor_log2_pow10(k)
    shift = 127 - e
    if k >= 0:
        num, den = 10 ** k, 1
    else:
        num, den = 1, 10 ** -k
    if shift >= 0:
        num <<= shift
    else:
        den <<= -shift
    v = -(-num // den)
    assert 1 << 127 <= v < 1 << 128, k
    return v


def main():
    # The shift formula is exact over the range, or every entry is off by a bit.
    # For k < 0, floor(k log2 10) = -ceil(-k log2 10), and since 10^-k is never a
    # power of two its ceiling log2 is (10^-k - 1).bit_length().
    for k in range(MIN_K, MAX_K + 1):
        want = (10 ** k).bit_length() - 1 if k >= 0 else -((10 ** -k - 1).bit_length())
        assert floor_log2_pow10(k) == want, k
    print("// GENERATED -- do not hand-edit. Regenerate with:")
    print("//")
    print("//   python3 sublimation/tools/genpow10.py > sublimation/src/text/pow10_cache.h")
    print("//")
    print("// Entry k - SUB_POW10_MIN_K holds ceil(10^k * 2^(127 - floor(k log2 10))),")
    print("// the 128-bit multiplier Dragonbox (Junekey Jeon) reads for binary64.")
    print("#pragma once")
    print("#include <stdint.h>")
    print(f"#define SUB_POW10_MIN_K ({MIN_K})")
    print(f"#define SUB_POW10_MAX_K {MAX_K}")
    print("static const uint64_t sub_pow10_cache[][2] = {")
    for k in range(MIN_K, MAX_K + 1):
        v = entry(k)
        print(f"    {{0x{v >> 64:016x}, 0x{v & ((1 << 64) - 1):016x}}},")
    print("};")


if __name__ == "__main__":
    main()
