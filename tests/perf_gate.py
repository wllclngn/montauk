#!/usr/bin/env python3
"""Performance envelopes: the tripwires the 7-minute population regression
class never had.

Three defenses, stacked so no box or load level flakes:
  - CPU time, not wall time (ru_utime + ru_stime of the child), nearly
    immune to a busy box and to parallelism hiding a slowdown
  - generous ABSOLUTE ceilings sized to the regression class (the observed
    failure was minutes vs seconds, so 10-20x headroom bounds catch every
    order-of-magnitude regression at ~zero flake risk)
  - a GROWTH bound (2x the input must cost < 4x the CPU) that catches
    superlinear parse or pairing regressions machine-independently
  - a self-calibrating oracle for the CLI: sublimation sort races real
    sort -n on the same input in the same run; "never grossly slower than
    the tool it replaces" is the envelope that matters, and it cancels
    machine speed

Run:  python3 tests/perf_gate.py   (or via tests/run.py, perf layer)
"""
import os
import resource
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import gen_synthetic_prom as gen
import harness

ANALYZE = harness.ROOT / "build" / "montauk_analyze"
SUB = harness.ROOT / "build" / "sublimation"
FIXTURE = harness.ROOT / "tests" / "fixtures" / "synthetic.mtk"
note = harness.logger("perf")


def cpu_seconds(argv, stdin_file=None, env=None) -> float:
    """Child CPU time (user+sys) via wait4 rusage."""
    with open(stdin_file, "rb") if stdin_file else open(os.devnull, "rb") as fin, \
         open(os.devnull, "wb") as fout:
        pid = os.posix_spawn(argv[0], argv, env or os.environ,
                             file_actions=[(os.POSIX_SPAWN_DUP2, fin.fileno(), 0),
                                           (os.POSIX_SPAWN_DUP2, fout.fileno(), 1),
                                           (os.POSIX_SPAWN_DUP2, fout.fileno(), 2)])
        _, status, ru = os.wait4(pid, 0)
        if os.waitstatus_to_exitcode(status) != 0:
            raise RuntimeError(f"{argv[0]} exited nonzero")
        return ru.ru_utime + ru.ru_stime


def main() -> int:
    missing = [str(p) for p in (ANALYZE, SUB) if not p.exists()]
    if missing:
        note(f"FAIL: missing {', '.join(missing)} -- build first")
        return 1
    fails = []

    def check(name, ok, detail):
        note(("PASS " if ok else "FAIL ") + f"{name} ({detail})")
        if not ok:
            fails.append(name)

    with tempfile.TemporaryDirectory(prefix="montauk-perf-gate-") as td:
        td = Path(td)

        # Population scale: the exact workload shape that ran 7m25s before
        # the fixed-effort stats were fixed. Ceiling is ~20x the healthy cost.
        small = td / "arch-small"
        big = td / "arch-big"
        gen.write_archive(small, versions=10, runs=3)     # 30 files
        gen.write_archive(big, versions=20, runs=3)       # 60 files, 2x
        base = [str(ANALYZE), "--by", "version", "--seed", "1729", "--no-emit"]
        t_small = cpu_seconds([base[0], str(small)] + base[1:])
        t_big = cpu_seconds([base[0], str(big)] + base[1:])
        check("population-ceiling", t_small < 60.0, f"{t_small:.2f}s cpu")
        # Guard the ratio against sub-resolution timings on fast boxes.
        ratio = t_big / max(t_small, 0.05)
        check("population-growth", ratio < 4.0, f"2x files -> {ratio:.2f}x cpu")

        # Trajectory ceiling: the permutation scan over the same archive.
        t_traj = cpu_seconds([base[0], str(small)] + base[1:] + ["--trajectory"])
        check("trajectory-ceiling", t_traj < 60.0, f"{t_traj:.2f}s cpu")

        # Analyzer ceiling on the deterministic trace fixture: full default
        # report set. Small fixture, so the bound is a coarse tripwire for
        # a superlinear finalize (the idle-interval scan class).
        if FIXTURE.exists():
            t_an = cpu_seconds([str(ANALYZE), str(FIXTURE)])
            check("analyzer-ceiling", t_an < 30.0, f"{t_an:.2f}s cpu")
        else:
            note("skip analyzer-ceiling (no synthetic.mtk; run corpus_check)")

        # CLI oracle: sublimation sort vs coreutils sort -n on 2M lines.
        stream = td / "stream.txt"
        with open(stream, "w") as f:
            x = 1234567
            for _ in range(2_000_000):
                x = (x * 6364136223846793005 + 1442695040888963407) % (1 << 63)
                f.write(f"{x % 10_000_000}\n")
        t_sub = cpu_seconds([str(SUB), "sort"], stdin_file=stream)
        real_sort = shutil.which("sort")
        if real_sort:
            t_real = cpu_seconds([real_sort, "-n"], stdin_file=stream,
                                 env=dict(os.environ, LC_ALL="C"))
            ratio = t_sub / max(t_real, 0.05)
            check("cli-sort-oracle", ratio < 5.0,
                  f"sublimation {t_sub:.2f}s vs sort -n {t_real:.2f}s cpu")
        else:
            check("cli-sort-ceiling", t_sub < 30.0, f"{t_sub:.2f}s cpu")

    note("PASS: all envelopes hold" if not fails
         else f"FAIL: {len(fails)} envelope(s) breached")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
