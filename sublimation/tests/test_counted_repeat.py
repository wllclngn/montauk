#!/usr/bin/env python3
"""Bounded repeats as counters, held to GNU grep -E.

A pattern that does not fit the regex field unrolled is rebuilt with each
single-position repeat X{lo,hi} as one position and a counter. That build is
reached only by patterns the field refuses, so every random pattern P here
runs as `z{0,200}(P)`, which forces it (z never occurs in the input, so the
prefix matches only empty, and with no top-level | the front end has nothing
to split the pattern on):
Every bounded repeat in the rest of the pattern then runs as a counter, small
bounds included, and the whole pattern must answer as grep answers it under
-c, -o, -n, -w, -x and -v. A pattern still too long with its repeats counted
(a group repeated, which no counter can carry) must be refused as too long
rather than as malformed, and at most a fifth of the random patterns may be.
Fixed cases cover the forms the counter has to get
right on its own terms: Bounds past the old 128-position cap, a counted repeat
under ^ and $, inside a repeated group and at both ends of an alternation.
"""
import os
import random
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

SUB = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else None
GREP = shutil.which("grep", path="/usr/bin:/bin")
ENV = {**os.environ, "LC_ALL": "C"}
# -w selects lines rather than printing spans: GNU grep's -w -o, after a
# rejected candidate, resumes past a word it should report (`[ab]*.{3}` on
# `abc abc ab` prints one abc, not two), with or without counters.
FLAGS = (["-c"], ["-o"], ["-n"], ["-w"], ["-x"], ["-v", "-c"])

fails = 0
refused = set()


def note(m):
    print(f"[counted] {m}", flush=True)


def run(argv, path):
    r = subprocess.run([*argv, path], capture_output=True, env=ENV)
    return r.returncode, r.stdout, r.stderr


def same(pat, path, flags, label):
    global fails
    s = run([str(SUB), "search", *flags, "-e", pat], path)
    g = run([GREP, "-E", *flags, "-e", pat], path)
    if s[0] == 2 and g[0] != 2 and b"128 positions" in s[2]:
        refused.add(pat)
        return True
    s, g = s[:2], g[:2]
    if s != g:
        fails += 1
        if fails <= 12:
            note(f"FAIL {label} {' '.join(flags)} {pat!r}: rc {s[0]} vs {g[0]}, "
                 f"stdout {s[1][:120]!r} vs {g[1][:120]!r}")
    return s == g


def atom(rng, depth):
    r = rng.random()
    if depth < 2 and r < 0.15:
        return "(" + alt(rng, depth + 1) + ")"
    return rng.choice(["a", "b", "c", ".", "[ab]", "[^c]", "[bc]"])


def quant(rng):
    r = rng.random()
    if r < 0.35:
        return ""
    if r < 0.45:
        return rng.choice(["*", "+", "?"])
    lo = rng.randint(0, 5)
    kind = rng.random()
    if kind < 0.3:
        return f"{{{lo}}}" if lo else "{1}"
    if kind < 0.45:
        return f"{{{lo},}}"
    if kind < 0.55:
        return f"{{,{rng.randint(1, 6)}}}"
    return f"{{{lo},{lo + rng.randint(0, 6)}}}"


def concat(rng, depth):
    return "".join(atom(rng, depth) + quant(rng) for _ in range(rng.randint(1, 4)))


def alt(rng, depth):
    return "|".join(concat(rng, depth) for _ in range(rng.randint(1, 2)))


def pattern(rng):
    p = alt(rng, 0)
    if rng.random() < 0.15:
        p = "^" + p
    if rng.random() < 0.15:
        p = p + "$"
    return p


def main() -> int:
    global fails
    if SUB is None or not SUB.is_file() or not GREP:
        note("DECLINED: usage: test_counted_repeat.py PATH/TO/sublimation (needs GNU grep)")
        return 2
    rng = random.Random(8140)
    checks = 0
    with tempfile.TemporaryDirectory() as td:
        hay = Path(td) / "hay.txt"
        lines = ["".join(rng.choice("abc") for _ in range(rng.randint(0, 40)))
                 for _ in range(60)]
        lines += ["a" * 130, "ab" * 70, "b" + "a" * 129 + "b", "", "abc abc ab"]
        hay.write_text("\n".join(lines) + "\n")
        for i in range(400):
            pat = pattern(rng)
            for flags in FLAGS:
                checks += 1
                same("z{0,200}(" + pat + ")", str(hay), flags, f"random #{i}")
        nrand_refused = len(refused)
        if nrand_refused > 80:
            fails += 1
            note(f"FAIL {nrand_refused} of 400 random patterns refused; the comparison is too thin")

        long_hay = Path(td) / "long.txt"
        long_hay.write_text("\n".join([
            "see Draft note here] and Draft more",
            "Draft" + "x" * 130 + "]",
            "Draft" + "x" * 200 + "]",
            "a" * 127, "a" * 128, "a" * 129, "a" * 300,
            "b" + "a" * 150 + "b" + "a" * 20 + "b",
            "", "ab" * 100,
        ]) + "\n")
        fixed = [
            r"Draft[^]]{0,126}", r"Draft[^]]{0,126}\]", r"Draft[^]]{3,200}\]",
            r"a{128}", r"a{129}", r"^a{128}$", r"^a{127,129}$", r"a{130,}",
            r"ba{100,200}b", r"(ba{10,150})+b", r"(a{130}|b)", r"(b|a{130})",
            r"x{0,200}", r"^x{0,200}$", r"[ab]{2,150}", r"(ab){0,3}a{140}",
        ]
        for pat in fixed:
            for flags in FLAGS:
                checks += 1
                same(pat, str(long_hay), flags, "fixed")
                if pat in refused:
                    fails += 1
                    note(f"FAIL fixed {pat!r} refused; every fixed form must run")

    if fails:
        note(f"GATE FAILED: {fails} of {checks} differ from grep -E")
        return 1
    note(f"{checks} checks match grep -E: {400 - nrand_refused} random patterns forced onto "
         f"counters ({nrand_refused} refused as too long, a group repeated) and 16 fixed "
         f"forms past the old cap, under -c -o -n -w -x and -v")
    return 0


if __name__ == "__main__":
    sys.exit(main())
