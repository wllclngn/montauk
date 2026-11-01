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
import json
import sys
import tempfile
from pathlib import Path

import gen_synthetic_prom as gen
import harness

ANALYZE = harness.ANALYZE
note = harness.logger("pop")

VERSIONS = 10
BOUNDARY_A = f"1.{gen.SHIFT_AT - 1}.0"
BOUNDARY_B = f"1.{gen.SHIFT_AT}.0"


def run(archive: Path, *args: str) -> str:
    proc = harness.run_text([*ANALYZE, str(archive), "--by", "version",
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
    if harness.missing_bins(harness.MONTAUK):
        note(f"FAIL: missing {harness.MONTAUK} -- build first")
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
        proc = harness.run_text([*ANALYZE, str(archive), "--by", "host",
                                 "--no-emit"])
        check("missing-axis-diagnostic",
              "no series carried label 'host'" in proc.stderr)

        # diagnostics: a per-file-unique label fragments every cell to N=1; it
        # is named with the exact --drop-label that unfragments the run.
        frag = Path(td) / "frag"
        frag.mkdir()
        for i, sched in enumerate(["eevdf", "bpfland", "eevdf", "bpfland"], 1):
            (frag / f"run-2026070{i}-000000.prom").write_text(
                "# TYPE bench_latency_us gauge\n"
                f'bench_latency_us{{scheduler="{sched}",stamp="s{i:04d}"}} '
                f"{100 + i * 5}.0\n")
        fp = harness.run_text([*ANALYZE, str(frag), "--by", "scheduler",
                               "--no-emit"])
        check("fragmenting-label-named",
              "--drop-label stamp" in fp.stderr and
              "stamp' is unique per file" in fp.stderr)
        fp2 = harness.run_text([*ANALYZE, str(frag), "--by", "scheduler",
                                "--drop-label", "stamp", "--no-emit"])
        check("fragmenting-label-fix-works",
              " vs " in fp2.stdout and "[N=2" in fp2.stdout)

        # a label value renamed between releases: --alias-label maps it before
        # cells are keyed, so the renamed archive reads exactly as the one
        # written with the new value throughout, and without it the series splits.
        def tool_archive(name, old_until):
            d = Path(td) / name
            d.mkdir()
            for v in range(4):
                for run_i in range(3):
                    tool = "old" if v < old_until else "new"
                    (d / f"1.{v}.0-2026070{v + 1}-00000{run_i}.prom").write_text(
                        f'bench_info{{version="1.{v}.0"}} 1\n'
                        "# TYPE bench_latency_us gauge\n"
                        f'bench_latency_us{{tool="{tool}",scheduler="eevdf"}} '
                        f"{100 + v * 10 + run_i}.0\n")
            return d
        renamed, relabelled = tool_archive("renamed", 2), tool_archive("relabelled", 0)
        aliased = run(renamed, "--alias-label", "tool:old=new")
        check("alias-label-pairs-renamed-series",
              aliased.replace(str(renamed), "") == run(relabelled).replace(str(relabelled), ""))
        check("alias-label-unaliased-splits",
              run(renamed).replace(str(renamed), "") != run(relabelled).replace(str(relabelled), ""))
        conflict = harness.run_text([*ANALYZE, str(renamed), "--alias-label", "tool:old=new",
                                     "--alias-label", "tool:old=other", "--no-emit"])
        check("alias-label-conflict-refused", conflict.returncode == 2)

        # a cell only one arm carries prints that arm's N and values, and the
        # --json envelope carries the same typed result as the text.
        one = Path(td) / "onearm"
        one.mkdir()
        for i, (mode, ticks) in enumerate([("adaptive", 40), ("adaptive", 44), ("adaptive", 48)], 1):
            (one / f"run-2026070{i}-000000.prom").write_text(
                "# TYPE bench_regime_ticks gauge\n"
                f'bench_regime_ticks{{mode="{mode}",regime="light"}} {ticks}\n'
                "# TYPE bench_wake_us gauge\n"
                f'bench_wake_us{{mode="adaptive"}} {100 + i}\n'
                f'bench_wake_us{{mode="bpf"}} {200 + i}\n')
        def pop(*args):
            return harness.run_text([*ANALYZE, str(one), "--by", "mode", "--seed", "1729",
                                     "--no-emit", *args])
        text = pop().stdout
        check("one-arm-prints-its-values",
              "only adaptive [N=3]: mean 44 (40..48) -- no comparison" in text, text.strip()[:200])
        env = pop("--json")
        try:
            doc = json.loads(env.stdout)
            metrics = {m["metric"]: m["cells"] for m in doc["population"]["metrics"]}
            ticks = metrics["bench_regime_ticks"][0]
            wake = metrics["bench_wake_us"][0]
            ok = (env.returncode == 0 and not ticks["compared"]
                  and ticks["groups"] == [{"group": "adaptive", "n": 3, "mean": 44, "min": 40, "max": 48}]
                  and wake["compared"] and len(wake["pairs"]) == 1
                  and {g["group"]: g["mcb"] for g in wake["groups"]} == {"adaptive": "best", "bpf": "not-best"})
        except (ValueError, KeyError, IndexError):
            ok = False
        check("json-envelope-carries-the-cells", ok, env.stdout.strip()[:200])
        pairs_text = sum(1 for l in text.splitlines() if " vs " in l and "[N=" in l)
        check("json-and-text-agree-on-pairs",
              ok and pairs_text == sum(len(c["pairs"]) for cells in metrics.values() for c in cells))
        check("json-trajectory-refused", pop("--json", "--trajectory").returncode == 2)

        # --relative-to: each cell over its own capture's control cell, compared
        # on the ratio; the control compared raw; a capture with no control named.
        relx = Path(td) / "relative"
        relx.mkdir()
        for stamp, eevdf, mine in (("20261001-000000", 100.0, 50.0), ("20261002-000000", 200.0, 120.0)):
            (relx / f"run-{stamp}.prom").write_text(
                "# TYPE bench_p99_us gauge\n"
                f'bench_p99_us{{scheduler="EEVDF",cores="4"}} {eevdf}\n'
                f'bench_p99_us{{scheduler="mine",cores="4"}} {mine}\n'
                f'bench_p99_us{{scheduler="mine",cores="8"}} {mine}\n')
        (relx / "run-20261003-000000.prom").write_text(
            "# TYPE bench_p99_us gauge\n"
            'bench_p99_us{scheduler="mine",cores="4"} 70.0\n')
        def rel(*args):
            return harness.run_text([*ANALYZE, str(relx), "--by", "capture", "--seed", "1729",
                                     "--no-emit", "--relative-to", "scheduler=EEVDF", *args])
        rtext = rel().stdout
        check("relative-names-missing-control",
              "[commit=unknown cores=4 scheduler=mine version=unknown] no nonzero scheduler=EEVDF control in capture 20261003-000000 -- raw values"
              in rtext, rtext.strip()[:300])
        renv = rel("--json")
        try:
            rcells = {c["cell"]: c for m in json.loads(renv.stdout)["population"]["metrics"] for c in m["cells"]}
            r8, ctl = rcells["commit=unknown cores=8 scheduler=mine version=unknown"], rcells["commit=unknown cores=4 scheduler=EEVDF version=unknown"]
            rok = (r8["relation"] == "no-control" and ctl["relation"] == "control"
                   and rcells["commit=unknown cores=4 scheduler=mine version=unknown"]["no_control_captures"] == ["20261003-000000"])
        except (ValueError, KeyError):
            rok = False
        check("relative-states-in-envelope", rok, renv.stdout.strip()[:200])
        two = Path(td) / "relative-two"
        two.mkdir()
        for f in sorted(relx.glob("run-2026100[12]*.prom")):
            (two / f.name).write_text(f.read_text())
        renv2 = harness.run_text([*ANALYZE, str(two), "--by", "capture", "--seed", "1729", "--no-emit",
                                  "--relative-to", "scheduler=EEVDF", "--json"])
        try:
            c4 = {c["cell"]: c for m in json.loads(renv2.stdout)["population"]["metrics"]
                  for c in m["cells"]}["commit=unknown cores=4 scheduler=mine version=unknown"]
            ratios = [g["ratio"]["mean"] for g in c4["groups"]]
            rok2 = c4["relation"] == "relative" and ratios == [0.5, 0.6] and len(c4["pairs"]) == 1
        except (ValueError, KeyError):
            rok2 = False
        check("relative-ratio-per-capture", rok2, renv2.stdout.strip()[:200])
        check("relative-axis-refused",
              harness.run_text([*ANALYZE, str(relx), "--by", "scheduler", "--no-emit",
                                "--relative-to", "scheduler=EEVDF"]).returncode == 2)

    note(f"{'FAIL' if fails else 'PASS'}: "
         f"{len(fails)} failure(s)" if fails else "PASS: all properties hold")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
