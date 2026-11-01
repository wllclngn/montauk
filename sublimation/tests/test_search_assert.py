#!/usr/bin/env python3
"""search refuses the zero-width assertions it cannot carry.

\\b \\B \\< \\> are assertions, and the regex face has no zero-width position:
Read as the escaped byte, `\\bSTEAM\\b` matched nothing and exited 1, a false
clean for a check carried over from grep -E. Each is refused at status 2 with
the assertion named and -w offered. A backslash inside a bracket is a member,
an escaped backslash before `b` is a literal, and neither is refused; -w still
finds the whole word.
"""
import subprocess
import sys
from pathlib import Path

# The binary under test is named by the caller (tests/run.py passes montauk's
# build/sublimation; a standalone sublimation build passes its own).
SUB = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else None

TEXT = b"a STEAM b\nSTEAMY\nx\\b\nbx\n"

fails = 0


def note(m):
    print(f"[search-assert] {m}", flush=True)


def fail(m):
    global fails
    fails += 1
    note(f"FAIL: {m}")


def expect(label, args, rc, out, err_has=None):
    r = subprocess.run([str(SUB), *args], input=TEXT, capture_output=True)
    if r.returncode != rc or r.stdout != out or (err_has and err_has not in r.stderr):
        fail(f"{label}: rc {r.returncode} stdout {r.stdout[:60]!r} stderr {r.stderr[:100]!r}")


def main():
    if SUB is None or not SUB.exists():
        note("usage: test_search_assert.py PATH/TO/sublimation")
        return 2

    for pat in (r"\bSTEAM\b", r"\BTEAM", r"\<STEAM", r"STEAM\>", r"x|\bSTEAM"):
        named = pat[pat.index("\\"):][:2].encode()
        expect(pat, ["search", pat], 2, b"", b"uses '" + named + b"'")
        expect(pat + " names -w", ["search", pat], 2, b"", b"use -w")
    expect("-e carries the refusal", ["search", "-e", "x", "-e", r"\bSTEAM"], 2, b"", b"uses '\\b'")
    note("each assertion is refused at status 2, named, with -w offered")

    expect("bracket member", ["search", r"[\b]x"], 0, b"bx\n")
    expect("escaped backslash", ["search", r"\\b"], 0, b"x\\b\n")
    expect("-F takes it literally", ["search", "-F", r"\b"], 0, b"x\\b\n")
    expect("-w finds the whole word", ["search", "-w", "STEAM"], 0, b"a STEAM b\n")
    note("a bracket member, an escaped backslash and -F are untouched; -w finds the word")

    if fails:
        note(f"GATE FAILED: {fails} check(s)")
        return 1
    note("GATE PASSED: no zero-width assertion reads as a literal that never matches")
    return 0


if __name__ == "__main__":
    sys.exit(main())
