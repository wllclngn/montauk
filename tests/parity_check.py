#!/usr/bin/env python3
"""sublimation <-> real-tool byte-parity gate.

Each sublimation verb whose purpose is to replace a classic tool on a pipe must
produce byte-identical output to that tool. This runs every such idiom through
`build/sublimation` and the real tool on the same input and fails on any
divergence -- the regression guard that keeps the ~/.bashrc wrapper routes safe
(a divergence there is a silent misfire). Cases whose real tool is not installed
are skipped, not failed.

This is the montauk-side question (does the engine match the tool). The bash
wrappers themselves live in the dotfiles, not montauk.

Run:  python3 tests/parity_check.py   (or via tests/run.py)
"""
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SUB = ROOT / "build" / "sublimation"

ROWS = "alpha 10 x\nbeta 20 y\ngamma 30 z\nalpha 40 w\n"
NUMS = "5\n3\n8\n1\n9\n2\n7\n4\n6\n0\n"
WORDS = "foo\nbar\nfoobar\nbaz\nFOO\nFoo\n"
ADJ = "a\na\nb\nc\nc\nc\nd\n"
KV = "a 10\nb 20\na 30\nc 5\nb 15\n"

# name, sublimation argv, real-tool shell cmd, input. Every one MUST be byte-equal.
CASES = [
    ("field $2",           ["field", "2"],                  "awk '{print $2}'",        ROWS),
    ("field $1,$3",        ["field", "1,3"],                "awk '{print $1,$3}'",     ROWS),
    ("field -F:",          ["field", "1", "--delim", ":"],  "awk -F: '{print $1}'",    "a:b:c\nd:e:f\n"),
    ("sort -n",            ["sort"],                        "sort -n",                 NUMS),
    ("sort -rn",           ["sort", "--desc"],              "sort -rn",                NUMS),
    ("count == wc -l",     ["count"],                       "wc -l",                   NUMS),
    ("grep regex",         ["grep", "foo"],                 "grep -E 'foo'",           WORDS),
    ("grep -v",            ["grep", "-v", "foo"],           "grep -E -v 'foo'",        WORDS),
    ("contains == grep -F",["contains", "foo"],             "grep -F 'foo'",           WORDS),
    ("contains -i",        ["contains", "-i", "foo"],       "grep -F -i 'foo'",        WORDS),
    ("uniq",               ["uniq"],                        "uniq",                    ADJ),
    ("uniq -d",            ["uniq", "-d"],                  "uniq -d",                 ADJ),
    ("uniq -u",            ["uniq", "-u"],                  "uniq -u",                 ADJ),
    ("tac",                ["tac"],                         "tac",                     NUMS),
    ("column -t",          ["column"],                      "column -t",               ROWS),
    ("group sum",          ["group", "1", "sum", "2"],      "datamash -g 1 sum 2",     KV),
]


def main():
    if not SUB.exists():
        print(f"[parity] sublimation not built at {SUB} -- build sublimation_cli first")
        return 1
    fails, skips, oks = [], [], []
    for name, argv, real_cmd, inp in CASES:
        tool = real_cmd.split()[0]
        if shutil.which(tool) is None:
            skips.append(name)
            continue
        so = subprocess.run([str(SUB), *argv], input=inp, capture_output=True, text=True).stdout
        ro = subprocess.run(["bash", "-c", real_cmd], input=inp, capture_output=True, text=True).stdout
        if so == ro:
            oks.append(name)
        else:
            fails.append(name)
            print(f"[parity] FAIL {name}")
            print(f"           sublimation: {so!r}")
            print(f"           {tool:<11}: {ro!r}")
    print(f"[parity] {len(oks)} match, {len(fails)} diverged, {len(skips)} skipped"
          + (f" (absent: {', '.join(skips)})" if skips else ""))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
