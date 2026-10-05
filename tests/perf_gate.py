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

ANALYZE = harness.ANALYZE
SUB = harness.ROOT / "build" / "sublimation"
FIXTURE = harness.ROOT / "tests" / "fixtures" / "synthetic.mtk"
note = harness.logger("perf")


def cpu_seconds(argv, stdin_file=None, env=None, ok_codes=(0,)) -> float:
    """Child CPU time (user+sys) via wait4 rusage. A signal, or an exit outside
    ok_codes, raises."""
    with open(stdin_file, "rb") if stdin_file else open(os.devnull, "rb") as fin, \
         open(os.devnull, "wb") as fout:
        pid = os.posix_spawn(argv[0], argv, env or os.environ,
                             file_actions=[(os.POSIX_SPAWN_DUP2, fin.fileno(), 0),
                                           (os.POSIX_SPAWN_DUP2, fout.fileno(), 1),
                                           (os.POSIX_SPAWN_DUP2, fout.fileno(), 2)])
        _, status, ru = os.wait4(pid, 0)
        if os.waitstatus_to_exitcode(status) not in ok_codes:
            raise RuntimeError(f"{argv[0]} exited nonzero")
        return ru.ru_utime + ru.ru_stime


def main() -> int:
    missing = [str(p) for p in (harness.MONTAUK, SUB) if not p.exists()]
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
        # FLAGS ONLY. This used to be one `base` list with the binary at [0] and
        # the archive spliced in as [base[0], archive] + base[1:]. That idiom
        # broke the moment the analyzer became a MODE of montauk rather than its
        # own binary: base[0] is the montauk path and base[1] is "--analyze", so
        # splicing produced `montauk ARCHIVE --analyze ...`, argv[1] was not a
        # mode word, and montauk fell through to the TUI and span forever.
        # Keeping the flags separate from the argv prefix makes that unspellable.
        flags = ["--by", "version", "--seed", "1729", "--no-emit"]
        t_small = cpu_seconds([*ANALYZE, str(small), *flags])
        t_big = cpu_seconds([*ANALYZE, str(big), *flags])
        check("population-ceiling", t_small < 60.0, f"{t_small:.2f}s cpu")
        # Guard the ratio against sub-resolution timings on fast boxes.
        ratio = t_big / max(t_small, 0.05)
        check("population-growth", ratio < 4.0, f"2x files -> {ratio:.2f}x cpu")

        # Trajectory ceiling: the permutation scan over the same archive.
        t_traj = cpu_seconds([*ANALYZE, str(small), *flags, "--trajectory"])
        check("trajectory-ceiling", t_traj < 60.0, f"{t_traj:.2f}s cpu")

        # Analyzer ceiling on the deterministic trace fixture: full default
        # report set. Small fixture, so the bound is a coarse tripwire for
        # a superlinear finalize (the idle-interval scan class).
        if FIXTURE.exists():
            t_an = cpu_seconds([*ANALYZE, str(FIXTURE)])
            check("analyzer-ceiling", t_an < 30.0, f"{t_an:.2f}s cpu")
            # The ceiling passes a superlinear fold or finalize until a capture
            # is large enough to hurt; the growth bound does not. The record
            # body after the 64-byte header repeated 32 and 64 times is a trace
            # of n and 2n events with the fixture's whole mix in each.
            data = FIXTURE.read_bytes()
            sized = []
            for copies in (32, 64):
                path = td / f"trace-x{copies}.mtk"
                path.write_bytes(data[:64] + data[64:] * copies)
                sized.append(cpu_seconds([*ANALYZE, str(path)]))
            ratio = sized[1] / max(sized[0], 0.05)
            check("analyzer-growth", ratio < 4.0,
                  f"2x events -> {ratio:.2f}x cpu, {sized[0]:.2f}s at n")
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

        # The regex face's interface. A byte-parity gate cannot see these: every
        # answer was correct while find went quadratic, captures went
        # exponential, and a long line took the stack.
        def one_line(name, n):
            p = td / f"{name}-{n}.txt"
            p.write_bytes(b"a" * n + b"\n")
            return p

        def cpu_or_crash(argv, stdin_file):
            # Exit 1 is grep's "nothing matched", which is the point of the
            # find case; a signal or a 2 is not.
            try:
                return cpu_seconds(argv, stdin_file=stdin_file, ok_codes=(0, 1))
            except RuntimeError:
                return None

        # find from every start re-read the field: a.*b over a^n, no match.
        t1 = cpu_or_crash([str(SUB), "search", "-c", "a.*b"], one_line("find", 200_000))
        t2 = cpu_or_crash([str(SUB), "search", "-c", "a.*b"], one_line("find", 400_000))
        ok = t1 is not None and t2 is not None
        ratio = t2 / max(t1, 0.05) if ok else 0.0
        check("regex-find-growth", ok and ratio < 4.0,
              f"2x line -> {ratio:.2f}x cpu" if ok else "crashed")

        # One group spanning a long line: the backtracker recursed per byte and
        # crashed at 100k.
        t1 = cpu_or_crash([str(SUB), "replace", "(a*)", r"[\1]"], one_line("cap", 200_000))
        t2 = cpu_or_crash([str(SUB), "replace", "(a*)", r"[\1]"], one_line("cap", 400_000))
        ok = t1 is not None and t2 is not None
        ratio = t2 / max(t1, 0.05) if ok else 0.0
        check("regex-captures-growth", ok and ratio < 4.0,
              f"2x line -> {ratio:.2f}x cpu" if ok else "crashed")

        # (a?){n}a{n} over a^n doubled per n under backtracking (n=26: 9.8s).
        # n=40 is past any backtracker's reach and trivial for a linear engine.
        t = cpu_or_crash([str(SUB), "replace", "(a?){40}a{40}", r"[\1]"], one_line("capexp", 40))
        check("regex-captures-ceiling", t is not None and t < 1.0,
              f"{t:.2f}s cpu" if t is not None else "crashed")

    note("PASS: all envelopes hold" if not fails
         else f"FAIL: {len(fails)} envelope(s) breached")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
