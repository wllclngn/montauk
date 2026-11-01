#!/usr/bin/env python3
"""The estimators the help names, held to the numbers it promises.

quantile and describe's quartiles take the element at floor(q*n) and never
interpolate; group's median interpolates between the two middle values. The
help says so with 1 2 3 4 as its example, where the two disagree (3 against
2.5), so each claim is checked here on that example and on random samples
against a reference computed from the definition.
"""
import random
import subprocess
import sys
from pathlib import Path

SUB = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else None

fails = 0


def note(m):
    print(f"[median-cli] {m}", flush=True)


def fail(m):
    global fails
    fails += 1
    note(f"FAIL: {m}")


def run(args, values, keyed=False):
    text = "".join((f"k {v}\n" if keyed else f"{v}\n") for v in values)
    r = subprocess.run([str(SUB), *args], input=text.encode(), capture_output=True)
    return r.returncode, r.stdout.decode()


def floor_element(xs, q):
    s = sorted(xs)
    return s[min(int(q * len(s)), len(s) - 1)]


def middle(xs):
    s, n = sorted(xs), len(xs)
    return s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2


def main():
    if SUB is None or not SUB.exists():
        note("usage: test_median_cli.py PATH/TO/sublimation")
        return 2

    ex = [1, 2, 3, 4]
    rc, out = run(["quantile", "0.5"], ex)
    if (rc, out.strip()) != (0, "3"):
        fail(f"quantile 0.5 of 1 2 3 4: rc {rc} {out!r}, want 3")
    rc, out = run(["group", "1", "median", "2"], ex, keyed=True)
    if (rc, out.strip()) != (0, "k 2.5"):
        fail(f"group median of 1 2 3 4: rc {rc} {out!r}, want 2.5")
    rc, out = run(["describe"], ex)
    rows = dict(l.split(None, 1) for l in out.splitlines() if l.strip())
    if (rows.get("25%"), rows.get("50%"), rows.get("75%")) != ("2", "3", "4"):
        fail(f"describe's quartiles of 1 2 3 4: {rows}, want 2 3 4")
    note("the help's example holds: quantile 3, group median 2.5, quartiles 2 3 4")

    rng = random.Random(11)
    for trial in range(40):
        xs = [rng.randint(-50, 50) for _ in range(rng.randint(1, 9))]
        for q in (0.25, 0.5, 0.75):
            rc, out = run(["quantile", str(q)], xs)
            if rc != 0 or float(out) != floor_element(xs, q):
                fail(f"quantile {q} of {xs}: {out!r}, want {floor_element(xs, q)}")
        rc, out = run(["group", "1", "median", "2"], xs, keyed=True)
        if rc != 0 or float(out.split()[1]) != middle(xs):
            fail(f"group median of {xs}: {out!r}, want {middle(xs)}")
    note("40 random samples of 1 to 9 values: quantile is the floor(q*n) element, "
         "group median the interpolated middle")

    if fails:
        note(f"GATE FAILED: {fails} check(s)")
        return 1
    note("GATE PASSED: each estimator is the one the help names")
    return 0


if __name__ == "__main__":
    sys.exit(main())
