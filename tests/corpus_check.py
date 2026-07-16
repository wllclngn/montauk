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

import harness
from harness import ROOT, MONTAUK_ANALYZE as ANALYZE, MONTAUK_TRACE_DECODE as DECODE, SUBLIMATION

GEN_SRC = ROOT / "tests" / "gen_synthetic_trace.cpp"
FIXTURE = ROOT / "tests" / "fixtures" / "synthetic.mtk"

# label -> (binary, golden path, extra args)
SURFACES = {
    "reports": (ANALYZE, ROOT / "tests" / "fixtures" / "synthetic.reports.golden", []),
    "decode": (DECODE, ROOT / "tests" / "fixtures" / "synthetic.decode.golden", []),
    "json": (ANALYZE, ROOT / "tests" / "fixtures" / "synthetic.json.golden", ["--json"]),
}

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
    (["search", "a"], _ROWS),
    (["search", "-n", "a"], _ROWS),
    (["search", "-c", "a"], _ROWS),
    (["search", "-v", "a"], _ROWS),
    (["search", "-F", "beta"], _ROWS),
    (["field", "2"], _ROWS),
    (["field", "1,3"], _ROWS),
    (["where", "2 > 15"], _ROWS),
    (["tally"], _FREQ),
    (["tally", "--field", "1"], _ROWS),
    (["distinct"], _FREQ),
    (["describe"], _NUMS),
    (["group", "1", "sum", "2"], _ROWS),
    (["group", "1", "count"], _ROWS),
    (["group", "1", "mean", "2"], _ROWS),
    (["outliers"], "1\n2\n3\n4\n5\n6\n7\n8\n9\n100\n"),
    (["histogram"], _NUMS),
    (["uniq"], "a\na\nb\nc\nc\n"),
    (["uniq", "-d"], "a\na\nb\nc\nc\n"),
    (["tac"], "1\n2\n3\n"),
    (["cut", "2-4"], "hello\nworld\n"),
    (["column"], _ROWS),
    (["paste", "-s"], "a\nb\nc\n"),
    (["intersect", "tests/fixtures/setb.txt"], "a\nb\nc\n"),
    (["subtract", "tests/fixtures/setb.txt"], "a\nb\nc\n"),
    (["union", "tests/fixtures/setb.txt"], "a\nb\nc\n"),
    (["join", "1", "tests/fixtures/joinb.txt"], "a 1\nb 2\nc 3\n"),
    (["replace", "foo", "X"], "foo bar foo\n"),
    (["replace", "[0-9]", "-"], "a1b2c3\n"),
    (["replace", "X+", "_"], "aXXbXXc\n"),
    (["locate", "sorted", "--window", "4", "--values"], "1\n2\n3\n4\n5\n6\n7\n8\n2\n9\n0\n5\n"),
    (["search", "-F", "foo"], "foo\nFOO\nFoo\nbar\n"),        # case-SENSITIVE default (search -F)
    (["search", "-F", "-i", "foo"], "foo\nFOO\nFoo\nbar\n"),  # -i folds ASCII case
    # v8.0.0 search coverage, the self-consistency half: not grep-comparable
    # byte-for-byte (--color's reset is \x1b[0m where grep also emits \x1b[K,
    # -S is a ripgrep-ism, --files-from and --line-buffered are sublimation's
    # own), so their stdout is frozen here instead. All deterministic in a
    # pipe: --color=always forces color off-TTY, --line-buffered only changes
    # drain timing, never bytes.
    (["search", "--color=always", "-n", "fo+"], "xfooy\nbar\nfoo\n"),
    (["search", "--color=always", "-o", "-e", "oba", "-e", "foo"], "foobar\n"),
    (["search", "--color=always", "-H", "-c", "alpha"], _ROWS),
    (["search", "--color=always", "-A", "1", "MATCH"], "one\nMATCH\ntwo\nthree\nMATCH\nfour\n"),
    (["search", "--color=never", "-n", "fo+"], "xfooy\nbar\n"),
    (["search", "--line-buffered", "alpha"], _ROWS),
    (["search", "-S", "alpha"], "ALPHA 1\nalpha 2\nbeta 3\n"),   # no uppercase in pattern -> folds
    (["search", "-S", "Alpha"], "ALPHA 1\nAlpha 2\nalpha 3\n"),  # uppercase -> stays exact
    (["search", "-w", "foo"], "foo bar\nfoobar\nx foo\n"),
    (["search", "-x", "-F", "beta"], "beta\nbetax\nbeta\n"),
    (["search", "-e", "alpha", "-e", "gamma"], _ROWS),
    (["search", "a", "--files-from", "-"], "tests/fixtures/joinb.txt\ntests/fixtures/setb.txt\n"),
]

note = harness.logger("corpus")


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


def run_stdout(binary: Path, args: list) -> str:
    """Run a tool over the fixture, returning stdout only (stderr discarded)."""
    return harness.run_text([str(binary), str(FIXTURE), *args]).stdout


def check_surface(label: str, update: bool) -> bool:
    binary, golden, args = SURFACES[label]
    if harness.missing_bins(binary):
        note(f"FAIL: missing {binary.relative_to(ROOT)} (build first)")
        return False
    got = run_stdout(binary, args)

    # The json surface must also be well-formed, not just byte-stable -- an agent
    # parses it. A malformed envelope fails the gate even if it matches a stale
    # golden.
    if label == "json":
        import json
        try:
            json.loads(got)
        except json.JSONDecodeError as e:
            note(f"FAIL: {label} is not valid JSON ({e})")
            return False
        # The envelope's trace.path field echoes FIXTURE's absolute path
        # verbatim -- correct application behavior (it names the file that was
        # analyzed), but ROOT differs by checkout location, so a golden that
        # freezes it verbatim can never match from a different clone/home dir.
        # Normalize it to a placeholder on both sides of the compare so the
        # golden stays portable; every other field still gates byte-exact.
        got = got.replace(str(FIXTURE), "<FIXTURE_PATH>")

    if update:
        # A refreeze canonizes whatever the binary printed. Show the diff it
        # is about to stamp as truth, so a regression cannot be frozen in
        # silently by one command.
        if golden.exists() and golden.read_text() != got:
            note(f"refreezing {label} -- diff being canonized:")
            harness.print_diff(label, golden.read_text(), got)
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
    harness.print_diff(label, want, got)
    return False


def cli_blob() -> str:
    """Run every CLI case and concatenate stdout under a per-case header."""
    parts = []
    for argv, stdin in CLI_CASES:
        # cwd=ROOT so relative fixture paths (set-ops/join FILE args) resolve.
        proc = harness.run_text([str(SUBLIMATION), *argv], input=stdin, cwd=ROOT)
        parts.append(f"$ sublimation {' '.join(argv)}\n{proc.stdout}")
    return "".join(parts)


def check_cli(update: bool) -> bool:
    if harness.missing_bins(SUBLIMATION):
        note(f"FAIL: missing {SUBLIMATION.relative_to(ROOT)} (build first)")
        return False
    got = cli_blob()
    if update:
        if CLI_GOLDEN.exists() and CLI_GOLDEN.read_text() != got:
            note("refreezing cli -- diff being canonized:")
            harness.print_diff("cli", CLI_GOLDEN.read_text(), got)
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
    harness.print_diff("cli", CLI_GOLDEN.read_text(), got)
    return False


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--update", action="store_true",
                    help="re-freeze ALL goldens instead of checking")
    ap.add_argument("--surface", choices=list(SURFACES) + ["cli"],
                    help="re-freeze only this surface's golden (implies update) -- "
                         "use when another surface is mid-change and must not be stamped")
    args = ap.parse_args()

    with tempfile.TemporaryDirectory() as td:
        regenerate_fixture(Path(td))
        if args.surface:  # per-surface freeze, leaving the others untouched
            if args.surface == "cli":
                CLI_GOLDEN.write_text(cli_blob())
                note(f"updated cli golden ({len(CLI_CASES)} cases)")
            else:
                check_surface(args.surface, update=True)
            return 0
        ok = all(check_surface(label, args.update) for label in SURFACES)
        ok = check_cli(args.update) and ok

    if args.update:
        return 0
    note("all surfaces byte-identical" if ok else "GATE FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
