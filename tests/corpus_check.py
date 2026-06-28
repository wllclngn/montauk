#!/usr/bin/env python3
"""Byte-identical output gate for the output-unification migration.

Regenerates the deterministic synthetic trace from source, runs the current
build's analyzer + decoder over it, and diffs their STDOUT against the frozen
goldens. stdout is the data contract; stderr (timing/rate, log lines) is not
part of the gate and is discarded. Any byte difference fails.

    tests/corpus_check.py            # check against goldens
    tests/corpus_check.py --update   # re-freeze goldens (only when output is
                                     # intended to change -- never during a
                                     # byte-identical migration step)
"""

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GEN_SRC = ROOT / "tests" / "gen_synthetic_trace.cpp"
FIXTURE = ROOT / "tests" / "fixtures" / "synthetic.mtk"
ANALYZE = ROOT / "build" / "montauk_analyze"
DECODE = ROOT / "build" / "montauk_trace_decode"

# label -> (binary, golden path)
SURFACES = {
    "reports": (ANALYZE, ROOT / "tests" / "fixtures" / "synthetic.reports.golden"),
    "decode": (DECODE, ROOT / "tests" / "fixtures" / "synthetic.decode.golden"),
}

SUBLIMATION = ROOT / "build" / "sublimation"
CLI_GOLDEN = ROOT / "tests" / "fixtures" / "synthetic.cli.golden"

# Deterministic CLI cases: each is (args, stdin). The output of every case is
# concatenated under a header into one blob, so the whole sublimation stdout
# surface is gated byte-identical -- the contract the awk/grep wrappers parse.
_NUMS = "5\n3\n8\n1\n9\n2\n7\n4\n6\n0\n3\n8\n"
_ROWS = "alpha 10 x\nbeta 20 y\ngamma 30 z\nalpha 40 w\n"
_FREQ = "a\nb\na\nc\na\nb\n"
CLI_CASES = [
    (["sort"], _NUMS),
    (["sort", "--desc"], _NUMS),
    (["quantile", "0.5"], _NUMS),
    (["quantile", "0.99", "--nearest"], _NUMS),
    (["select", "3"], _NUMS),
    (["searchsorted", "5"], _NUMS),
    (["sum"], _NUMS),
    (["mean"], _NUMS),
    (["min"], _NUMS),
    (["max"], _NUMS),
    (["count"], _NUMS),
    (["distinct"], _NUMS),
    (["stdev"], _NUMS),
    (["variance"], _NUMS),
    (["classify"], _NUMS),
    (["characterize"], _NUMS),
    (["rand"], _NUMS),
    (["grep", "a"], _ROWS),
    (["grep", "-n", "a"], _ROWS),
    (["grep", "-c", "a"], _ROWS),
    (["grep", "-v", "a"], _ROWS),
    (["contains", "beta"], _ROWS),
    (["field", "2"], _ROWS),
    (["field", "1,3"], _ROWS),
    (["where", "2 > 15"], _ROWS),
    (["tally"], _FREQ),
    (["tally", "--field", "1"], _ROWS),
    (["distinct"], _FREQ),
]


def note(msg: str) -> None:
    print(f"[corpus] {msg}")


def regenerate_fixture(tmp: Path) -> None:
    """Compile the generator from source and emit the fixture deterministically."""
    gen = tmp / "gen"
    build = subprocess.run(
        ["g++", "-std=c++23", "-I", "include", "-I", ".", str(GEN_SRC), "-o", str(gen)],
        cwd=ROOT, capture_output=True, text=True,
    )
    if build.returncode != 0:
        note("FAIL: generator did not compile")
        sys.stderr.write(build.stderr)
        sys.exit(1)
    FIXTURE.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run([str(gen), str(FIXTURE)], capture_output=True)


def run_stdout(binary: Path) -> str:
    """Run a tool over the fixture, returning stdout only (stderr discarded)."""
    proc = subprocess.run(
        [str(binary), str(FIXTURE)], capture_output=True, text=True,
    )
    return proc.stdout


def check_surface(label: str, update: bool) -> bool:
    binary, golden = SURFACES[label]
    if not binary.exists():
        note(f"FAIL: missing {binary.relative_to(ROOT)} (build first)")
        return False
    got = run_stdout(binary)

    if update:
        golden.write_text(got)
        note(f"updated {label} golden ({len(got)} bytes)")
        return True

    if not golden.exists():
        note(f"FAIL: {label} golden missing ({golden.relative_to(ROOT)})")
        return False

    want = golden.read_text()
    if got == want:
        note(f"PASS {label} ({got.count(chr(10))} lines)")
        return True

    note(f"FAIL {label} -- stdout diverged from golden:")
    import difflib
    diff = difflib.unified_diff(
        want.splitlines(keepends=True), got.splitlines(keepends=True),
        fromfile=f"{label}.golden", tofile=f"{label}.actual",
    )
    sys.stdout.writelines(list(diff)[:40])
    return False


def cli_blob() -> str:
    """Run every CLI case and concatenate stdout under a per-case header."""
    parts = []
    for argv, stdin in CLI_CASES:
        proc = subprocess.run([str(SUBLIMATION), *argv], input=stdin,
                              capture_output=True, text=True)
        parts.append(f"$ sublimation {' '.join(argv)}\n{proc.stdout}")
    return "".join(parts)


def check_cli(update: bool) -> bool:
    if not SUBLIMATION.exists():
        note(f"FAIL: missing {SUBLIMATION.relative_to(ROOT)} (build first)")
        return False
    got = cli_blob()
    if update:
        CLI_GOLDEN.write_text(got)
        note(f"updated cli golden ({len(got)} bytes)")
        return True
    if not CLI_GOLDEN.exists():
        note(f"FAIL: cli golden missing ({CLI_GOLDEN.relative_to(ROOT)})")
        return False
    if got == CLI_GOLDEN.read_text():
        note(f"PASS cli ({len(CLI_CASES)} cases)")
        return True
    note("FAIL cli -- stdout diverged from golden:")
    import difflib
    diff = difflib.unified_diff(
        CLI_GOLDEN.read_text().splitlines(keepends=True),
        got.splitlines(keepends=True), fromfile="cli.golden", tofile="cli.actual")
    sys.stdout.writelines(list(diff)[:40])
    return False


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--update", action="store_true",
                    help="re-freeze goldens instead of checking")
    args = ap.parse_args()

    with tempfile.TemporaryDirectory() as td:
        regenerate_fixture(Path(td))
        ok = all(check_surface(label, args.update) for label in SURFACES)
        ok = check_cli(args.update) and ok

    if args.update:
        return 0
    note("all surfaces byte-identical" if ok else "GATE FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
