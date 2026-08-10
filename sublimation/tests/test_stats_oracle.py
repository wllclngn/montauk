#!/usr/bin/env python3
"""numpy oracle for the shipped sublimation_stats and tally APIs.

These are the newest code under the byte-parity mandate, and byte-parity only
proves they do not CHANGE -- it says nothing about whether they were right when
frozen. The corpus CLI gate would happily freeze a wrong quantile forever. This
gate diffs the shipped API against numpy directly.

Two things are matched exactly rather than approximately, because both are where
a reimplementation drifts:

  THE ESTIMATOR INDEX. sublimation_quantile_f64 takes floor(q*n) when nearest is
  0 and nearest-rank ceil(q*n)-1 when it is 1, both clamped. Neither is numpy's
  default linear interpolation, so the oracle reproduces the INDEX and indexes
  the sorted array itself -- comparing against np.quantile's default would be
  comparing against a different definition and would fail for the wrong reason.

  THE SUMMATION ORDER. sublimation_describe_f64 takes its moments over the
  SORTED array, so its sum is a different floating-point sequence from a sum over
  the input order. The oracle sorts first for exactly that reason; without it the
  low bits disagree and the failure looks like a bug in the reduction.
"""
import shutil
import subprocess
import sys
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
SRC_DIR = HERE.parent / "src"
BUILD = HERE / "_stats_build"
BIN = BUILD / "harness"

RTOL, ATOL = 1e-12, 1e-12


def note(m):
    print(f"[stats] {m}", flush=True)


def build():
    cc = shutil.which("clang") or shutil.which("cc") or shutil.which("gcc")
    if not cc:
        note("no C compiler; DECLINED")
        return None
    std = "-std=c23"
    if subprocess.run([cc, std, "-fsyntax-only", "-x", "c", "-"],
                      input="int main(void){return 0;}", capture_output=True,
                      text=True).returncode != 0:
        std = "-std=c2x"
    BUILD.mkdir(exist_ok=True)
    srcs = sorted(str(p) for p in SRC_DIR.rglob("*.c"))
    cmd = [cc, std, "-O2", "-march=native",
           "-I", str(SRC_DIR / "include"), "-I", str(SRC_DIR),
           str(HERE / "test_stats_oracle.c"), *srcs,
           "-o", str(BIN), "-lm", "-lpthread"]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        note("FAIL: harness did not build")
        sys.stdout.write(r.stderr[:2000])
        return None
    return BIN


def run(mode, data, *args):
    r = subprocess.run([str(BIN), mode, *[str(a) for a in args]],
                       input=data, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"harness {mode} failed: {r.stderr[:400]}")
    return r.stdout.strip().split("\n")


def feed(v):
    return "\n".join(repr(float(x)) for x in v) + "\n"


def close(got, ref):
    return np.allclose([got], [ref], rtol=RTOL, atol=ATOL)


def est_index(n, q, nearest):
    """sublimation's own estimator index, clamped -- see the module docstring."""
    if nearest:
        i = int(np.ceil(q * n)) - 1
    else:
        i = int(np.floor(q * n))
    return max(0, min(n - 1, i))


def main():
    if build() is None:
        return 2
    rng = np.random.default_rng(20260810)
    fails = 0

    # Three shapes: plain normal, heavy-tailed (outliers move quartiles and
    # fences), and one with exact ties (the estimator index has to land the same
    # way on duplicates).
    cases = {
        "normal": rng.normal(50, 12, 997),
        "heavy-tailed": np.concatenate([rng.normal(10, 1, 900), rng.normal(500, 90, 97)]),
        "tied": np.repeat(rng.integers(0, 12, 120).astype(float), 8),
    }

    for name, v in cases.items():
        note(f"case {name} (n={len(v)})")
        data = feed(v)
        s = np.sort(v)

        got = [float(x) for x in run("reduce", data)]
        refs = [("sum", np.sum(v)), ("mean", np.mean(v)),
                ("variance", np.var(v, ddof=1)), ("stdev", np.std(v, ddof=1)),
                ("min", np.min(v)), ("max", np.max(v))]
        for (label, ref), g in zip(refs, got):
            ok = close(g, ref)
            fails += not ok
            note(f"  {label:9} {'ok' if ok else f'DIVERGED got {g!r} ref {ref!r}'}")

        for q in (0.0, 0.25, 0.5, 0.75, 0.9, 0.99, 1.0):
            for nearest in (0, 1):
                g = float(run("quantile", data, q, nearest)[0])
                ref = s[est_index(len(v), q, nearest)]
                ok = close(g, ref)
                fails += not ok
                if not ok:
                    note(f"  quantile q={q} nearest={nearest} DIVERGED got {g!r} ref {ref!r}")
        note(f"  quantile  ok (7 q x 2 estimators)")

        d = run("describe", data)
        n_got = int(d[0])
        vals = [float(x) for x in d[1:]]
        # Moments over the SORTED array -- see the docstring.
        ref_d = [np.mean(s), np.std(s, ddof=1), s[0],
                 s[est_index(len(v), 0.25, 0)], s[est_index(len(v), 0.50, 0)],
                 s[est_index(len(v), 0.75, 0)], s[-1]]
        ok = n_got == len(v) and all(close(g, r) for g, r in zip(vals, ref_d))
        fails += not ok
        note(f"  describe  {'ok' if ok else f'DIVERGED got {vals!r} ref {ref_d!r}'}")

        lo, hi = [float(x) for x in run("fences", data)]
        q1 = s[est_index(len(v), 0.25, 0)]
        q3 = s[est_index(len(v), 0.75, 0)]
        iqr = q3 - q1
        ok = close(lo, q1 - 1.5 * iqr) and close(hi, q3 + 1.5 * iqr)
        fails += not ok
        note(f"  fences    {'ok' if ok else f'DIVERGED got ({lo!r}, {hi!r})'}")

        nbins = 16
        h = run("histogram", data, nbins)
        mn, w = float(h[0]), float(h[1])
        counts = [int(x) for x in h[2:]]
        ok = close(mn, np.min(v)) and sum(counts) == len(v) and len(counts) == nbins
        # Every value must land in the bin its own width implies.
        if ok and w > 0:
            idx = np.clip(((v - mn) / w).astype(int), 0, nbins - 1)
            ok = list(np.bincount(idx, minlength=nbins)) == counts
        fails += not ok
        note(f"  histogram {'ok' if ok else f'DIVERGED counts={counts!r} sum={sum(counts)}'}")

    # tally: distinct records by count desc, then first-seen.
    note("tally: distinct records, count desc then first-seen")
    words = ["alpha", "beta", "gamma", "delta", "beta", "alpha", "beta", "eps"]
    seq = [words[i % len(words)] for i in range(500)] + ["zzz"]
    out = run("tally", "\n".join(seq) + "\n")
    total = int(out[0])
    pairs = [(int(ln.split("\t")[0]), ln.split("\t")[1]) for ln in out[1:]]
    first_seen = {}
    for i, wd in enumerate(seq):
        first_seen.setdefault(wd, i)
    counts = {}
    for wd in seq:
        counts[wd] = counts.get(wd, 0) + 1
    ref = sorted(counts.items(), key=lambda kv: (-kv[1], first_seen[kv[0]]))
    ref_pairs = [(c, wd) for wd, c in ref]
    ok = total == len(seq) and pairs == ref_pairs
    fails += not ok
    note(f"  tally     {'ok' if ok else f'DIVERGED got {pairs[:6]!r} ref {ref_pairs[:6]!r}'}")

    note("")
    if fails:
        note(f"GATE FAILED: {fails} check(s) diverged from the oracle")
        return 1
    note("GATE PASSED: the shipped sublimation_stats API matches numpy (reductions, "
         "both quantile estimators, describe, Tukey fences, histogram) and tally "
         "orders by count then first-seen")
    return 0


if __name__ == "__main__":
    sys.exit(main())
