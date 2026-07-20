#!/usr/bin/env python3
"""Population-mode gate: correctness, determinism and structure.

Four properties, each the pin for a defect class this mode has actually
shipped with:

  output      the report reaches stdout at all (the g_pop_out sink defect
              silently ate every population report until 2026-07-14)
  correctness the injected +50% shift is FOUND: the pairwise engine sees it
              at the boundary pair with a full-magnitude Cliff's delta, the
              trajectory engine names the boundary version, and the stable
              family yields no change point (false-positive half)
  determinism same seed twice is byte-identical stdout, and --threads 1 vs
              --threads N is byte-identical, pinning the fan-out's
              thread-invariance guarantee forever
  structure   emitted pair counts exactly match the --pairs selector
              (adjacent: V-1, all: C(V,2), vs-best: V-1 per cell), so a
              selector regression is caught by counting, not timing

Run:  python3 tests/pop_gate.py   (or via tests/run.py, gate layer)
"""
import sys
import tempfile
from pathlib import Path

import gen_synthetic_prom as gen
import harness

ANALYZE = harness.MONTAUK_ANALYZE
note = harness.logger("pop")

VERSIONS = 10
BOUNDARY_A = f"1.{gen.SHIFT_AT - 1}.0"
BOUNDARY_B = f"1.{gen.SHIFT_AT}.0"


def run(archive: Path, *args: str) -> str:
    proc = harness.run_text([str(ANALYZE), str(archive), "--by", "version",
                             "--seed", "1729", "--no-emit", *args])
    return proc.stdout


def family_lines(text: str, family: str) -> list:
    """The comparison lines inside one METRIC block."""
    out, inside = [], False
    for line in text.splitlines():
        if line.startswith("METRIC "):
            inside = line == f"METRIC {family}"
        elif inside and " vs " in line and "[N=" in line:
            out.append(line.strip())
    return out


def pair_lines(text: str, family: str) -> int:
    return len(family_lines(text, family))


def main() -> int:
    if harness.missing_bins(ANALYZE):
        note(f"FAIL: missing {ANALYZE} -- build first")
        return 1
    fails = []

    def check(name: str, ok: bool, detail: str = ""):
        note(("PASS " if ok else "FAIL ") + name + (f" ({detail})" if detail else ""))
        if not ok:
            fails.append(name)

    with tempfile.TemporaryDirectory(prefix="montauk-pop-gate-") as td:
        archive = Path(td) / "arch"
        gen.write_archive(archive, versions=VERSIONS, runs=3)

        # output + correctness, pairwise engine (adjacent default on version).
        # Scope the boundary assertion to the SHIFTED family's own block: the
        # +50% jump must show as a full-magnitude Cliff's delta there.
        out = run(archive)
        check("report-reaches-stdout", "METRIC " in out)
        boundary = [l for l in family_lines(out, gen.SHIFTED_FAMILY)
                    if l.startswith(f"{BOUNDARY_A} vs {BOUNDARY_B}")]
        check("shift-found-pairwise",
              len(boundary) >= 1 and all("cliff -1.00" in l for l in boundary),
              f"{len(boundary)} boundary pair line(s)")

        # correctness, trajectory engine: names the boundary, and the stable
        # family stays quiet (the false-positive half of the assertion)
        traj = run(archive, "--trajectory")
        check("shift-found-trajectory",
              f"jump {BOUNDARY_A} -> {BOUNDARY_B}" in traj)
        stable_quiet = False
        lines = traj.splitlines()
        for i, l in enumerate(lines):
            if l.startswith(f"TRAJECTORY {gen.STABLE_FAMILY}"):
                stable_quiet = i + 1 < len(lines) and \
                    "no change point" in lines[i + 1]
        check("stable-family-quiet", stable_quiet)

        # determinism: same seed byte-identical; thread count invariant
        check("determinism-reruns", run(archive) == out)
        check("determinism-threads",
              run(archive, "--threads", "1") == run(archive, "--threads", "8"))
        check("determinism-trajectory",
              run(archive, "--trajectory") == traj)

        # structure: pair counts per selector, on the shifted family's two
        # cells (V=10 versions in every cell)
        v = VERSIONS
        expect = {"adjacent": 2 * (v - 1), "all": 2 * v * (v - 1) // 2,
                  "vs-best": 2 * (v - 1)}
        for mode, want in expect.items():
            got = pair_lines(run(archive, "--pairs", mode,
                                 "--metric", gen.SHIFTED_FAMILY),
                             gen.SHIFTED_FAMILY)
            check(f"pairs-{mode}", got == want, f"{got}/{want}")

        # diagnostics: a missing axis label names itself instead of "no
        # usable gauges"
        proc = harness.run_text([str(ANALYZE), str(archive), "--by", "host",
                                 "--no-emit"])
        check("missing-axis-diagnostic",
              "no series carried label 'host'" in proc.stderr)

    note(f"{'FAIL' if fails else 'PASS'}: "
         f"{len(fails)} failure(s)" if fails else "PASS: all properties hold")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
