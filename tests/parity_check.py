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
import shlex
import shutil
import sys

import harness
from harness import SUBLIMATION as SUB

ROWS = "alpha 10 x\nbeta 20 y\ngamma 30 z\nalpha 40 w\n"
NUMS = "5\n3\n8\n1\n9\n2\n7\n4\n6\n0\n"
WORDS = "foo\nbar\nfoobar\nbaz\nFOO\nFoo\n"
ADJ = "a\na\nb\nc\nc\nc\nd\n"
KV = "a 10\nb 20\na 30\nc 5\nb 15\n"
CTX = "one\ntwo\nMATCH1\nfour\nfive\nsix\nseven\nMATCH2\nnine\nten\n"

JOINB = str(harness.ROOT / "tests" / "fixtures" / "joinb.txt")
JOINB_COMMA = str(harness.ROOT / "tests" / "fixtures" / "joinb_comma.txt")

# column's per-column width array and per-line token array used to cap at 256
# entries and truncate a scratch buffer at 4096 bytes; both are now
# realloc-grown with no fixed ceiling. These two fixtures exceed both old caps
# and must still byte-match real column -t.
COLUMN_WIDE = "\n".join(" ".join(str(i) for i in range(300)) for _ in range(3)) + "\n"
COLUMN_LONG_LINE = ("a 1 " + ("x" * 5000) + " b 2\n") * 2

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
    ("column -t >256 cols",["column"],                      "column -t",               COLUMN_WIDE),
    ("column -t >4096B line",["column"],                    "column -t",               COLUMN_LONG_LINE),
    ("group sum",          ["group", "1", "sum", "2"],      "datamash -g 1 sum 2",     KV),
    ("head",               ["head", "3"],                   "head -3",                 NUMS),
    ("tail",               ["tail", "3"],                   "tail -3",                 NUMS),
    ("count --words",      ["count", "--words"],            "wc -w",                   WORDS),
    ("count --bytes",      ["count", "--bytes"],            "wc -c",                   WORDS),
    ("uniq -i",            ["uniq", "-i"],                  "uniq -i",                 WORDS),
    ("join",               ["join", "1", JOINB],            f"join - {shlex.quote(JOINB)}",         "a 1\nb 2\nc 3\n"),
    ("join --delim ,",     ["join", "2", JOINB_COMMA, "--delim", ","],
                                                              f"join -t, -j 2 - {shlex.quote(JOINB_COMMA)}",
                                                                                        "x,a,1\ny,b,2\n"),
    ("grep -A1 -B1",       ["grep", "MATCH", "-A", "1", "-B", "1"],
                                                              "grep -E MATCH -A 1 -B 1", CTX),
    ("contains -A1 -B1",   ["contains", "MATCH", "-A", "1", "-B", "1"],
                                                              "grep -F MATCH -A 1 -B 1", CTX),
    # Anchors must stay absolute across the per-line continuation scan: ^ fires
    # once per line start, $ once per line end, never again after a restart.
    ("replace ^ prefix",   ["replace", "^", "P "],           "sed 's/^/P /g'",          WORDS),
    ("replace $ suffix",   ["replace", "$", " S"],           "sed 's/$/ S/g'",          WORDS),
    ("replace ^tok",       ["replace", "^foo", "X"],         "sed -E 's/^foo/X/g'",     WORDS),
    ("replace tok$",       ["replace", "o$", "O"],           "sed -E 's/o$/O/g'",       WORDS),
    ("replace unanchored", ["replace", "o", "0"],            "sed 's/o/0/g'",           WORDS),
    ("grep -o ^anchor",    ["grep", "-o", "^[a-z]+"],        "grep -E -o '^[a-z]+'",    WORDS),
    ("grep -o anchor$",    ["grep", "-o", "[a-z]+$"],        "grep -E -o '[a-z]+$'",    WORDS),
]

note = harness.logger("parity")


def main():
    if harness.missing_bins(SUB):
        note(f"sublimation not built at {SUB} -- build sublimation_cli first")
        return 1
    fails, skips, oks = [], [], []
    for name, argv, real_cmd, inp in CASES:
        tool = real_cmd.split()[0]
        if shutil.which(tool) is None:
            skips.append(name)
            continue
        so = harness.run_text([str(SUB), *argv], input=inp).stdout
        ro = harness.run_text(["bash", "-c", real_cmd], input=inp).stdout
        if so == ro:
            oks.append(name)
        else:
            fails.append(name)
            note(f"FAIL {name}")
            print(f"           sublimation: {so!r}")
            print(f"           {tool:<11}: {ro!r}")
    note(f"{len(oks)} match, {len(fails)} diverged, {len(skips)} skipped"
         + (f" (absent: {', '.join(skips)})" if skips else ""))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
