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
import tempfile
from pathlib import Path

import harness
from harness import SUBLIMATION as SUB

ROWS = "alpha 10 x\nbeta 20 y\ngamma 30 z\nalpha 40 w\n"
NUMS = "5\n3\n8\n1\n9\n2\n7\n4\n6\n0\n"
WORDS = "foo\nbar\nfoobar\nbaz\nFOO\nFoo\n"
# -w's hard cases: 'a-|a' on "a-b" only matches as the SHORTER word "a"
# (grep admits any match length at a start, not just the longest), foobar
# must not match foo, aab must not match a+.
WMIX = "a-b\nfoo-bar\nfoobar\nan a here\naab\n"
ADJ = "a\na\nb\nc\nc\nc\nd\n"
KV = "a 10\nb 20\na 30\nc 5\nb 15\n"
CTX = "one\ntwo\nMATCH1\nfour\nfive\nsix\nseven\nMATCH2\nnine\nten\n"
# Duplicate keys on purpose: rows b/c share key 2 and a/d share key 1, so any
# instability in the keyed sort (now sublimation_pack_sort_f64, not qsort)
# shows up as a tie-order flip against coreutils' stable sort -s.
KEYED = "b 2 y\na 1 x\nc 2 z\nd 1 w\n"

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
    ("sort --keyed",       ["sort", "--keyed", "--field", "2"],
                                                             "sort -t' ' -k2,2n -s",   KEYED),
    ("sort --keyed --desc",["sort", "--keyed", "--field", "2", "--desc"],
                                                             "sort -t' ' -k2,2nr -s",  KEYED),
    ("count == wc -l",     ["count"],                       "wc -l",                   NUMS),
    ("search regex",       ["search", "foo"],                 "grep -E 'foo'",           WORDS),
    ("search -v",          ["search", "-v", "foo"],           "grep -E -v 'foo'",        WORDS),
    ("search -F",          ["search", "-F", "foo"],             "grep -F 'foo'",           WORDS),
    ("search -F -i",       ["search", "-F", "-i", "foo"],       "grep -F -i 'foo'",        WORDS),
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
    ("search -A1 -B1",     ["search", "MATCH", "-A", "1", "-B", "1"],
                                                              "grep -E MATCH -A 1 -B 1", CTX),
    ("search -F -A1 -B1",  ["search", "-F", "MATCH", "-A", "1", "-B", "1"],
                                                              "grep -F MATCH -A 1 -B 1", CTX),
    # Anchors must stay absolute across the per-line continuation scan: ^ fires
    # once per line start, $ once per line end, never again after a restart.
    ("replace ^ prefix",   ["replace", "^", "P "],           "sed 's/^/P /g'",          WORDS),
    ("replace $ suffix",   ["replace", "$", " S"],           "sed 's/$/ S/g'",          WORDS),
    ("replace ^tok",       ["replace", "^foo", "X"],         "sed -E 's/^foo/X/g'",     WORDS),
    ("replace tok$",       ["replace", "o$", "O"],           "sed -E 's/o$/O/g'",       WORDS),
    ("replace unanchored", ["replace", "o", "0"],            "sed 's/o/0/g'",           WORDS),
    ("search -o ^anchor",  ["search", "-o", "^[a-z]+"],        "grep -E -o '^[a-z]+'",    WORDS),
    ("search -o anchor$",  ["search", "-o", "[a-z]+$"],        "grep -E -o '[a-z]+$'",    WORDS),
    # v8.0.0 search coverage batch, stdin half. The real tool is named as
    # /usr/bin/grep explicitly: bash -c already bypasses any interactive grep
    # wrapper function, but the ugrep-style wrappers on this box make the
    # explicit path the only unambiguous oracle.
    ("search -w -F",       ["search", "-w", "-F", "foo"],        "/usr/bin/grep -w -F foo",        WMIX),
    ("search -w regex",    ["search", "-w", "a-|a"],             "/usr/bin/grep -w -E 'a-|a'",     WMIX),
    ("search -w -o",       ["search", "-w", "-o", "a-|a"],       "/usr/bin/grep -w -o -E 'a-|a'",  WMIX),
    ("search -w -v",       ["search", "-w", "-v", "-F", "foo"],  "/usr/bin/grep -w -v -F foo",     WMIX),
    ("search -x -F",       ["search", "-x", "-F", "foo"],        "/usr/bin/grep -x -F foo",        WORDS),
    ("search -x regex",    ["search", "-x", "fo+"],              "/usr/bin/grep -x -E 'fo+'",      WORDS),
    ("search -x -v",       ["search", "-x", "-v", "-F", "foo"],  "/usr/bin/grep -x -v -F foo",     WORDS),
    ("search -x -o",       ["search", "-x", "-o", "fo+"],        "/usr/bin/grep -x -o -E 'fo+'",   WORDS),
    ("search -e -e",       ["search", "-e", "foo", "-e", "bar"], "/usr/bin/grep -e foo -e bar",    WORDS),
    ("search -o -e -e",    ["search", "-o", "-e", "oba", "-e", "foo"],
                                                                 "/usr/bin/grep -o -e oba -e foo", "foobar\nzabc\n"),
    ("search -c -e -e",    ["search", "-c", "-e", "foo", "-e", "bar"],
                                                                 "/usr/bin/grep -c -e foo -e bar", WORDS),
    ("search -e ''",       ["search", "-e", ""],                 "/usr/bin/grep -e ''",            WORDS),
    ("search -H stdin",    ["search", "-H", "foo"],              "/usr/bin/grep -H foo",           WORDS),
]

# The file-mode half: these idioms are ABOUT named files (per-file counts,
# -l/-L listings, filename prefixes, binary classification), so each case
# materializes its inputs in a tempdir and substitutes {name} path
# placeholders on both sides. {missing} is never created -- that IS the
# unreadable-FILE case.
SEARCH_FILES = {
    "pa": "foo\nbar\nfoobar\n",
    "pb": "baz\nfoo again\nqux\n",
    "pn": "nothing here\n",
    "pbin": "foo\x00bar\nfoo again\n",   # NUL in the first chunk -> binary
    "ppats": "foo\nqux\n",
}
FILE_CASES = [
    ("search -l",           ["search", "-l", "foo", "{pa}", "{pb}", "{pn}"],
                            "/usr/bin/grep -l foo {pa} {pb} {pn}"),
    ("search -L",           ["search", "-L", "foo", "{pa}", "{pb}", "{pn}"],
                            "/usr/bin/grep -L foo {pa} {pb} {pn}"),
    ("search -c per file",  ["search", "-c", "foo", "{pa}", "{pb}", "{pn}"],
                            "/usr/bin/grep -c foo {pa} {pb} {pn}"),
    ("search -H one file",  ["search", "-H", "foo", "{pa}"],
                            "/usr/bin/grep -H foo {pa}"),
    ("search -h two files", ["search", "-h", "foo", "{pa}", "{pb}"],
                            "/usr/bin/grep -h foo {pa} {pb}"),
    ("search -f",           ["search", "-f", "{ppats}", "{pa}", "{pb}"],
                            "/usr/bin/grep -f {ppats} {pa} {pb}"),
    ("search -f + -e",      ["search", "-f", "{ppats}", "-e", "bar", "{pa}"],
                            "/usr/bin/grep -f {ppats} -e bar {pa}"),
    ("search binary",       ["search", "foo", "{pbin}"],
                            "/usr/bin/grep foo {pbin}"),
    ("search binary -a",    ["search", "-a", "foo", "{pbin}"],
                            "/usr/bin/grep -a foo {pbin}"),
    ("search binary -c",    ["search", "-c", "foo", "{pbin}"],
                            "/usr/bin/grep -c foo {pbin}"),
    ("search binary -l",    ["search", "-l", "foo", "{pbin}"],
                            "/usr/bin/grep -l foo {pbin}"),
    ("search binary -I -L", ["search", "-I", "-L", "foo", "{pbin}"],
                            "/usr/bin/grep -I -L foo {pbin}"),
    ("search -m per file",  ["search", "-m", "1", "foo", "{pa}", "{pb}"],
                            "/usr/bin/grep -m 1 foo {pa} {pb}"),
    ("search ctx files",    ["search", "-A", "1", "-B", "1", "-n", "foo", "{pa}", "{pb}"],
                            "/usr/bin/grep -A 1 -B 1 -n foo {pa} {pb}"),
    ("search -s stdout",    ["search", "-s", "foo", "{pa}", "{missing}"],
                            "/usr/bin/grep -s foo {pa} {missing}"),
]

# Exit-code parity: the stdout tables above never see return codes, and
# grep's error contract is exactly what the v8.0.0 batch implements -- 2 on
# an unreadable FILE even when other files matched, 0 for -q with a match
# despite the error, -s silencing the message but never the status, -L's
# listing NOT counting as success. Each case must return the same code AND
# the same stdout as /usr/bin/grep.
EXIT_CASES = [
    ("exit 2: unreadable + match",        ["search", "foo", "{pa}", "{missing}"]),
    ("exit 2: -s keeps the status",       ["search", "-s", "foo", "{pa}", "{missing}"]),
    ("exit 0: -q match outranks error",   ["search", "-q", "foo", "{pa}", "{missing}"]),
    ("exit 2: -q without a match",        ["search", "-q", "zzz", "{pa}", "{missing}"]),
    ("exit 1: no match, no error",        ["search", "zzz", "{pa}"]),
    ("exit 1: -L listing is not success", ["search", "-L", "zzz", "{pa}"]),
    ("exit 0: -L nothing listed",         ["search", "-L", "foo", "{pa}"]),
    ("exit 0: -l match",                  ["search", "-l", "foo", "{pa}"]),
    ("exit 0: binary match",              ["search", "foo", "{pbin}"]),
    ("exit 1: binary -I",                 ["search", "-I", "foo", "{pbin}"]),
]

note = harness.logger("parity")


def materialize(tmp):
    """Write the search file fixtures into tmp; returns {name: path-string}."""
    paths = {}
    for name, content in SEARCH_FILES.items():
        p = tmp / f"{name}.txt"
        p.write_bytes(content.encode())
        paths[name] = str(p)
    paths["missing"] = str(tmp / "missing.txt")   # deliberately never created
    return paths


def check_exit_codes(paths, fails, oks):
    """search vs /usr/bin/grep, return code AND stdout compared."""
    for name, sub_argv in EXIT_CASES:
        argv = [a.format(**paths) for a in sub_argv]
        sp = harness.run_text([str(SUB), *argv], input="")
        rp = harness.run_text(["/usr/bin/grep", *argv[1:]], input="")
        if (sp.returncode, sp.stdout) == (rp.returncode, rp.stdout):
            oks.append(name)
        else:
            fails.append(name)
            note(f"FAIL {name}")
            print(f"           sublimation: rc={sp.returncode} {sp.stdout!r}")
            print(f"           grep       : rc={rp.returncode} {rp.stdout!r}")


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
    with tempfile.TemporaryDirectory() as td:
        paths = materialize(Path(td))
        for name, argv, real_cmd in FILE_CASES:
            argv = [a.format(**paths) for a in argv]
            so = harness.run_text([str(SUB), *argv], input="").stdout
            ro = harness.run_text(["bash", "-c", real_cmd.format(**paths)], input="").stdout
            if so == ro:
                oks.append(name)
            else:
                fails.append(name)
                note(f"FAIL {name}")
                print(f"           sublimation: {so!r}")
                print(f"           grep       : {ro!r}")
        check_exit_codes(paths, fails, oks)
    note(f"{len(oks)} match, {len(fails)} diverged, {len(skips)} skipped"
         + (f" (absent: {', '.join(skips)})" if skips else ""))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
