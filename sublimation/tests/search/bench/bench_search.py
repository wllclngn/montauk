#!/usr/bin/env python3
"""sublimation search bench: our engine vs the standard libraries.

Mirrors the sort's bench-sublimation.py: tiny native programs per language, each
calling its ecosystem's own search, a Python driver sweeping shared corpora.

Throughput is MB/s, median of 9, on corpora reused verbatim from
test_search_research.gen_corpora. Match counts are shown for transparency, NOT
gated: engines differ on match semantics (overlapping vs not, POSIX
leftmost-longest vs RE2 leftmost-first), so counts are a sanity signal only. Our
engine's own correctness is gated separately by that file's byte-parity oracle.

Two tracks: literal (exact substring) and regex.

Tiers, so the numbers mean something:
  soft targets  python re, c++ std::regex, POSIX regcomp   (known-slow backtrackers)
  fair fights   go regexp, glibc memmem, go bytes.Index     (RE2 lineage / two-way)
  gold standard rust regex crate                            (ripgrep's engine)
"""
import json
import os
import re as _re
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent           # .../search/bench
SEARCH = HERE.parent                             # .../search
BUILD = HERE / "build"
sys.path.insert(0, str(SEARCH))
from test_search_research import gen_corpora      # noqa: E402  reuse exact corpora

OURBIN = SEARCH / "search_research"
BENCH_SIZE = 4_000_000                            # slice: keeps std::regex/re tractable


def _ts():
    return datetime.now().strftime("[%H:%M:%S]")

def info(m):
    print(f"{_ts()} [INFO]   {m}", flush=True)

def warn(m):
    print(f"{_ts()} [WARN]   {m}", flush=True)


# regex patterns per corpus: bounded, field-supported, valid POSIX/RE2,
# unambiguous. real_src carries a common-literal case AND rare-byte cases so the
# rare-byte anchor (E1) is visible, not hidden as it was in the first bench.
REGEX = {
    "english": ["th[aeiou]"],
    "dna": ["A[CG]TT"],
    "base64": ["[A-Z][0-9]"],
    "frozen_adversarial": ["zqxj[kvwy]"],
    "repetitive": ["MARK[A-Z]R"],
    "markov": ["ACGT[a-z]"],
    "real_src": ["str[a-z]ct", "EXPORT[A-Z]", "SIG[A-Z]LL"],
}
# fuzzy k-mismatch cases (our engine only: no standard library ships fuzzy search).
FUZZY = {"real_src": [("struct", 1), ("SIGKILL", 1), ("return", 2)]}
# which corpora to bench (story: controls, our edge, real, correlated, rare-literal)
CORPORA = ["english", "dna", "base64", "frozen_adversarial", "markov",
           "repetitive", "real_src"]
# ASCII/UTF-8 corpora (rust std str::find only runs on these)
UTF8_OK = {"english", "dna", "base64", "markov", "repetitive", "real_src"}


def build():
    BUILD.mkdir(exist_ok=True)
    bins = {}

    def run(cmd, **kw):
        return subprocess.run(cmd, capture_output=True, text=True, **kw)

    # our engine: always rebuild from source (the checked-in binary may be stale)
    r = run(["cc", "-O2", "-march=native", "-std=c23", "-o", str(OURBIN),
             str(SEARCH / "search_research.c"), "-lm"])
    if r.returncode != 0:
        warn(f"our engine build failed: {r.stderr[-300:]}")

    c = BUILD / "bench_c"
    r = run(["gcc", "-O2", "-march=native", str(HERE / "bench_c.c"), "-o", str(c)])
    bins["c"] = c if r.returncode == 0 else warn(f"C skip: {r.stderr[-200:]}")

    cpp = BUILD / "bench_cpp"
    r = run(["g++", "-O2", "-march=native", "-std=c++20", str(HERE / "bench_cpp.cpp"), "-o", str(cpp)])
    bins["cpp"] = cpp if r.returncode == 0 else warn(f"C++ skip: {r.stderr[-200:]}")

    go = BUILD / "bench_go"
    r = run(["go", "build", "-o", str(go), str(HERE / "bench_go.go")],
            env={**os.environ, "GOWORK": "off"})
    bins["go"] = go if r.returncode == 0 else warn(f"Go skip: {r.stderr[-200:]}")

    rs = BUILD / "bench_rust_std"
    r = run(["rustc", "-O", "--edition", "2021", str(HERE / "bench_rust_std.rs"), "-o", str(rs)])
    bins["rust_std"] = rs if r.returncode == 0 else warn(f"Rust std skip: {r.stderr[-200:]}")

    rr_dir = HERE / "rust_regex"
    r = run(["cargo", "build", "--release", "--offline"], cwd=str(rr_dir))
    rr = rr_dir / "target" / "release" / "bench_rust_regex"
    bins["rust_regex"] = rr if r.returncode == 0 and rr.exists() else warn(
        f"Rust regex crate skip: {r.stderr[-200:]}")

    return {k: v for k, v in bins.items() if v}


def native(binary, corpusfile, pat, mode):
    try:
        r = subprocess.run([str(binary), corpusfile, pat, "9", mode],
                           capture_output=True, text=True, timeout=600)
        for line in r.stdout.strip().splitlines():
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                pass
    except subprocess.TimeoutExpired:
        warn(f"timeout: {Path(binary).name} {mode} {pat}")
    return None


def _median9(fn):
    count = fn()
    dt = []
    for _ in range(9):
        t0 = time.perf_counter()
        fn()
        dt.append(time.perf_counter() - t0)
    dt.sort()
    return dt[4], count


def py_literal(data, pat):
    b = pat.encode() if isinstance(pat, str) else pat

    def run():
        c, i = 0, 0
        while True:
            j = data.find(b, i)
            if j < 0:
                break
            c += 1
            i = j + 1
        return c
    sec, count = _median9(run)
    return len(data) / 1e6 / sec, count


def py_regex(data, pat):
    rx = _re.compile(pat.encode())
    sec, count = _median9(lambda: sum(1 for _ in rx.finditer(data)))
    return len(data) / 1e6 / sec, count


def ours(mode_args, data):
    r = subprocess.run([str(OURBIN)] + mode_args, input=data, capture_output=True)
    try:
        return r.stdout.decode().strip()
    except Exception:
        return None


def bench():
    info("sublimation search bench: our engine vs the standard libraries")
    bins = build()
    info(f"built: {', '.join(sorted(bins))} + our engine")
    info(f"corpus slice: {BENCH_SIZE // 1_000_000} MB, MB/s = median of 9")

    corpora = {name: (data, lit) for name, data, lit, _ in gen_corpora()}

    for name in CORPORA:
        if name not in corpora:
            warn(f"corpus '{name}' unavailable, skipped")
            continue
        data, litpat = corpora[name]
        data = data[:BENCH_SIZE]
        litpat = litpat.decode()
        rxpats = REGEX.get(name, [])

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tf:
            tf.write(data)
            cf = tf.name
        try:
            print()
            info(f"corpus: {name}  ({len(data)//1_000_000} MB)")

            # LITERAL track
            print(f"  literal  pattern={litpat!r}")
            print(f"    {'engine':<22}{'MB/s':>10}{'count':>12}")
            rows = []
            mb = ours(["bench", "classify", litpat], data)
            cnt = ours(["count", "classify", litpat], data)
            if mb and cnt:
                rows.append(("sublimation (anchor)", float(mb), int(cnt)))
            for key, algo_mode in [("c", "literal"), ("cpp", "literal"),
                                   ("go", "literal"), ("rust_regex", "literal")]:
                if key in bins:
                    o = native(bins[key], cf, litpat, "literal")
                    if o:
                        rows.append((o["algo"], o["mb_s"], o["count"]))
            if "rust_std" in bins and name in UTF8_OK:
                o = native(bins["rust_std"], cf, litpat, "literal")
                if o:
                    rows.append((o["algo"], o["mb_s"], o["count"]))
            pmb, pc = py_literal(data, litpat)
            rows.append(("python_bytes_find", pmb, pc))
            for algo, mbs, c in sorted(rows, key=lambda x: -x[1]):
                print(f"    {algo:<22}{mbs:>10.0f}{c:>12}")

            # REGEX track (one or more patterns per corpus)
            for rxpat in rxpats:
                print(f"  regex    pattern={rxpat!r}")
                print(f"    {'engine':<22}{'MB/s':>10}{'count':>12}")
                rows = []
                mbf = ours(["benchre", rxpat], data)
                cf2 = ours(["regexcount", rxpat], data)
                if mbf and cf2:
                    rows.append(("sublimation (field)", float(mbf), int(cf2)))
                mbp = ours(["benchpre", rxpat], data)
                cp = ours(["regexpre", rxpat], data)
                if mbp and cp:
                    rows.append(("sublimation (prefilt)", float(mbp), int(cp)))
                for key in ["c", "cpp", "go", "rust_regex"]:
                    if key in bins:
                        o = native(bins[key], cf, rxpat, "regex")
                        if o:
                            rows.append((o["algo"], o["mb_s"], o["count"]))
                pmb, pc = py_regex(data, rxpat)
                rows.append(("python_re", pmb, pc))
                for algo, mbs, c in sorted(rows, key=lambda x: -x[1]):
                    print(f"    {algo:<22}{mbs:>10.0f}{c:>12}")

            # FUZZY track (our engine only: no standard library ships fuzzy search)
            for fpat, k in FUZZY.get(name, []):
                print(f"  fuzzy    pattern={fpat!r} k={k}  (no stdlib competitor)")
                print(f"    {'engine':<22}{'MB/s':>10}{'count':>12}")
                bc = ours(["fuzzycount", str(k), fpat], data)
                bm = ours(["benchfz", str(k), fpat], data)
                pmb_ = ours(["benchfzpre", str(k), fpat], data)
                pc_ = ours(["fuzzypre", str(k), fpat], data)
                rows = []
                if bm and bc:
                    rows.append(("sublimation (brute)", float(bm), int(bc)))
                if pmb_ and pc_:
                    rows.append(("sublimation (pigeonhole)", float(pmb_), int(pc_)))
                for algo, mbs, c in sorted(rows, key=lambda x: -x[1]):
                    print(f"    {algo:<24}{mbs:>8.0f}{c:>12}")
        finally:
            os.unlink(cf)

    print()
    info("done. counts differ by match semantics across engines; throughput is the metric.")
    return 0


if __name__ == "__main__":
    sys.exit(bench())
