#!/usr/bin/env python3
"""Fixture generator and crash/well-formedness gate for the analyzer + CLI.

Regenerates the deterministic synthetic trace from source, then checks the
surfaces that can actually be WRONG rather than merely DIFFERENT: the JSON
envelope must parse, every deterministic CLI case must exit clean, and
tally/distinct must survive the StrMap grow boundaries.

    tests/corpus_check.py            # run the gate

THE BYTE-IDENTICAL GOLDENS ARE GONE (v8.13.0) AND ARE NOT COMING BACK. Eight
frozen stdout blobs gated the analyzer, decoder, JSON and CLI surfaces, and in
practice a golden only ever fired when output changed ON PURPOSE -- two of them
had been failing since v8.9.0 and were carried as known-red, which is the state
in which a gate has stopped being a gate. The one that failed most recently did
so because a per-CPU self-kick split was ADDED to the kicks report, i.e. the gate
reported a feature as a regression and the real defect it might have caught was
invisible underneath. A frozen blob cannot tell an intended line from a broken
number, so it taxes every deliberate change and catches none of the accidental
ones. What survives here are the assertions with a failure mode behind them --
malformed JSON an agent cannot parse, a nonzero exit, a SIGSEGV at a rehash --
plus parity_check.py, which compares text/JSON/prom against EACH OTHER and so
needs no frozen reference at all.
"""

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import harness
from harness import ROOT, ANALYZE, DECODE, SUBLIMATION

GEN_SRC = ROOT / "tests" / "gen_synthetic_trace.cpp"
FIXTURE = ROOT / "tests" / "fixtures" / "synthetic.mtk"

_NUMS = "5\n3\n8\n1\n9\n2\n7\n4\n6\n0\n3\n8\n"
_ROWS = "alpha 10 x\nbeta 20 y\ngamma 30 z\nalpha 40 w\n"
_FREQ = "a\nb\na\nc\na\nb\n"
_LONG_ALT = ("SUBLIMATION_SEARCH_|sublimation_search_compile|"
             "sublimation_search_find_from|typedef struct")
_ALT_IN = ("#define SUBLIMATION_SEARCH_MAX_POS 64\n"
           "void sublimation_search_compile(sublimation_search *out);\n"
           "long sublimation_search_find_from(const sublimation_search *s);\n"
           "typedef struct { uint64_t key; } slot;\n"
           "static inline unsigned char fold(unsigned char c);\n")
_POSIX_IN = "abc\n123\nA1_\n  \t\n!@#\nDEADbeef\nxyz 9\n"

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
    # The rest of the datamash vocabulary. parity_check.py compares these
    # against datamash itself, which is the stronger check -- but it can only
    # run where datamash is INSTALLED, and `group sum` sat SKIPPED there long
    # enough to read as covered while being wrong. Freezing the bytes here means
    # the ops are gated on every box, oracle present or not.
    (["group", "1", "min", "2"], _ROWS),
    (["group", "1", "max", "2"], _ROWS),
    (["group", "1", "median", "2"], _ROWS),
    (["group", "1", "sstdev", "2"], _ROWS),
    (["group", "1", "pstdev", "2"], _ROWS),
    (["group", "1", "first", "2"], _ROWS),
    (["group", "1", "last", "2"], _ROWS),
    (["group", "1", "mode", "2"], _ROWS),
    (["group", "1", "antimode", "2"], _ROWS),
    (["group", "1", "unique", "2"], _ROWS),
    (["group", "1", "collapse", "2"], _ROWS),
    (["group", "1", "countunique", "2"], _ROWS),
    # sstdev of a ONE-element group is undefined, not zero. beta/gamma are
    # singletons in _ROWS, so this case pins the nan rather than leaving the
    # distinction to a comment.
    (["group", "1", "sstdev", "2"], "solo 7\n"),
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
    # v8.5.0 CLI completeness batch: tr, comm, positional paste, sort --keyed
    # multi-key, and the newline-separated bare-PATTERNS OR (grep's own
    # documented "one or more patterns separated by newline characters" rule).
    (["tr", "a-z", "A-Z"], "hello world\n"),
    (["tr", "-d", "0-9"], "a1b2c3\n"),
    (["comm", "tests/fixtures/setb.txt"], "a\nb\nc\n"),
    (["paste", "tests/fixtures/setb.txt", "tests/fixtures/joinb.txt"], ""),
    (["sort", "--keyed", "--field", "2,3"], "a 30 9\nb 30 1\nc 30 5\n"),
    (["search", "-F", "alpha\ngamma"], _ROWS),
    # Over-long top-level alternation. The regex face is a 64-position bitset
    # summed across | branches, so this whole pattern cannot compile; it is
    # split on its top-level | into exactly the pattern set repeated -e builds.
    # The two cases below MUST produce identical output -- that equality is the
    # gate, and it is what stops the "split it across -e by hand" workaround
    # from coming back.
    (["search", "-c", _LONG_ALT], _ALT_IN),
    (["search", "-c", "-e", "SUBLIMATION_SEARCH_", "-e", "sublimation_search_compile",
      "-e", "sublimation_search_find_from", "-e", "typedef struct"], _ALT_IN),
    (["search", "-n", _LONG_ALT], _ALT_IN),
    # A | that is NOT top-level must never split: grouped, bracketed, escaped.
    (["search", "(cat|dog)x"], "catx\ndogx\ncat\ndogy\n"),
    (["search", "[a|b]x"], "ax\nbx\n|x\ncx\n"),
    (["search", "a\\|b"], "a|b\nab\na\n"),
    # v8.6.0: POSIX's leading-']' rule, which none of the five hand-rolled
    # bracket scanners implemented -- so []] (the ordinary grep idiom for a
    # literal ']') matched nothing at all. One class_span now defines a bracket
    # expression for the matcher, the prefilter, the literal extractor and the
    # alternation splitter alike. The ']' also stays a range endpoint, which is
    # what grep does under LC_ALL=C, the byte-order oracle this engine answers to.
    (["search", "[]]"], "a]b\ncat\n"),
    (["search", "[]|]"], "a]b\nX|Y\nq\n"),
    (["search", "[^]a]"], "a]b\nX|Y\n]]]\n"),
    (["search", "[]-a]"], "a]b\ncat\n^x\nz-w\n"),
    # A top-level | hidden behind a leading-']' class must still not split.
    (["search", "-c", "[]|]x"], "]x\n|x\ncx\n"),
    # v8.6.0: the perl-style shorthand byte sets. Scope was MEASURED against
    # grep -E under LC_ALL=C, not assumed: GNU ERE has \w \W \s \S, does NOT
    # have \d (it matches a literal 'd'), and treats a backslash inside brackets
    # as a literal member so [\w] is the set {backslash, w}. All three of those
    # facts are pinned below, because implementing \d would have created a NEW
    # divergence from the oracle in the opposite direction.
    (["search", "-c", r"\w"], "abc\n x \nA-B\n"),
    (["search", "-c", r"\W"], "abc\n x \nA-B\n"),
    (["search", "-c", r"\s"], "abc\n x \nA-B\n"),
    (["search", "-c", r"\S"], "abc\n x \nA-B\n"),
    (["search", "-c", r"a\wc"], "abc\naxc\na c\n"),
    (["search", "-c", r"\S\s\S"], "a b\nab\n a\n"),
    # \d is a literal 'd' here, as in grep -E.
    (["search", "-c", r"\d"], "123\nd9\nabc\n"),
    # Inside brackets the backslash is a member, not an escape.
    (["search", "-c", r"[\w]"], "w\n\\\nabc\n"),
    # v8.10.0: --lines, the absolute window. The one sed form (`sed -n 'A,Bp'`)
    # sublimation had no answer for, so it kept surviving the shell wrapper's
    # routing. Pinned across all four spellings plus composition, because the
    # window has to apply BEFORE every other flag sees a line.
    (["search", "--lines", "2,4"], "a\nb\nc\nd\ne\nf\ng\n"),
    (["search", "--lines", ",3"], "a\nb\nc\nd\ne\n"),
    (["search", "--lines", "4,"], "a\nb\nc\nd\ne\n"),
    (["search", "--lines", "3"], "a\nb\nc\nd\ne\n"),
    (["search", "-n", "--lines", "2,6", "-e", "[bdf]"], "a\nb\nc\nd\ne\nf\ng\n"),
    (["search", "--lines", "2,5", "-c", "-e", "."], "a\nb\nc\nd\ne\nf\n"),
    (["search", "--lines", "2,4", "-v", "-e", "c"], "a\nb\nc\nd\ne\n"),
    # A range past EOF selects nothing and must say so with grep's exit 1, not
    # succeed silently.
    (["search", "--lines", "99,200"], "a\nb\nc\n"),
    # v8.10.0: replace's escape language, which used to change meaning based on
    # distant context -- `\\` was a literal backslash only when a \1 appeared
    # elsewhere in the SAME replacement, and two raw characters otherwise.
    (["replace", "x", "a\\\\b"], "x\n"),
    (["replace", "(x)", "a\\\\b\\1"], "x\n"),
    (["replace", "([a-z]+)=([a-z]+)", "\\2:\\1"], "foo=bar\n"),
    (["replace", "b", "[\\0]"], "abc\n"),
    (["replace", "x", "<\\3>"], "x\n"),
    # v8.10.0: POSIX character classes inside a bracket expression. These used to
    # match NOTHING -- class_span read "[[:alpha:]]" as the literal member set
    # {'[', ':', 'a', 'l', 'p', 'h'} and stopped at the first ']', a silently
    # wrong answer rather than a refusal. Every case below was verified against
    # `grep -E` before freezing, membership being ASCII/LC_ALL=C, the same basis
    # \w and \s already use.
    (["search", "[[:alpha:]]"], _POSIX_IN),
    (["search", "[[:digit:]]"], _POSIX_IN),
    (["search", "[[:alnum:]]"], _POSIX_IN),
    (["search", "[[:upper:]]"], _POSIX_IN),
    (["search", "[[:lower:]]"], _POSIX_IN),
    (["search", "[[:space:]]"], _POSIX_IN),
    (["search", "[[:blank:]]"], _POSIX_IN),
    (["search", "[[:punct:]]"], _POSIX_IN),
    (["search", "[[:print:]]"], _POSIX_IN),
    (["search", "[[:graph:]]"], _POSIX_IN),
    (["search", "[[:cntrl:]]"], _POSIX_IN),
    (["search", "[[:xdigit:]]"], _POSIX_IN),
    # Composition: quantified, negated, mixed with an ordinary range, and paired.
    (["search", "-o", "[[:alpha:]]+"], _POSIX_IN),
    (["search", "[^[:digit:]]"], _POSIX_IN),
    (["search", "[[:alpha:]0-9]"], _POSIX_IN),
    (["search", "-o", "[[:upper:]][[:lower:]]"], _POSIX_IN),
    # \w is documented as [[:alnum:]_]; the two spellings must agree exactly.
    (["search", "-o", "[[:alnum:]_]+"], _POSIX_IN),
    (["search", "-o", "\\w+"], _POSIX_IN),
    # v8.10.0: -i folding for the pairs a single byte-set cannot express. These
    # need an ALTERNATION per character -- the two UTF-8 encodings differ before
    # the last byte, or in length -- which is why the field engine had to learn a
    # second width first. Every case here was verified against `grep -i`.
    (["search", "-i", "-c", "\u0130"], "x\u0130y\nx\u0069y\nzz\n"),
    (["search", "-i", "-o", "\u03a3"], "a\u03a3b\na\u03c3b\n"),
    (["search", "-i", "-c", "\u1e9e"], "x\u1e9ey\nx\u00dfy\nzz\n"),
    # A three-member class: capital phi, small phi, phi symbol. A pair table can
    # only relate two of them, and answered grep with 1 where it wanted 2.
    (["search", "-i", "-c", "\u03a6"], "a\u03a6b\na\u03c6b\na\u03d5b\nzz\n"),
    (["search", "-i", "-c", "\u03d5"], "a\u03a6b\na\u03c6b\na\u03d5b\nzz\n"),
    # NOT folded, and that is the point: these share a towlower but differ in
    # towupper, and grep does not fold them either.
    (["search", "-i", "-c", "\u212a"], "aKb\nakb\na\u212ab\n"),
    (["search", "-i", "-c", "\u0398"], "a\u0398b\na\u03b8b\na\u03f4b\n"),
    # The cheap last-byte path must still work, and quantifiers over a folded
    # alternation atom must too.
    (["search", "-i", "-c", "\u00e9"], "x\u00c9y\nx\u00e9y\nzz\n"),
    (["search", "-i", "-o", "\u03a3+"], "a\u03c3\u03a3b\n"),
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


def run_stdout(cmd: list, args: list) -> str:
    """Run a tool over the fixture, returning stdout only (stderr discarded).

    `cmd` is an ARGV PREFIX (`[montauk, --analyze]`), not a path: the analyzer
    and decoder are modes of montauk rather than binaries of their own.
    TZ is pinned to UTC: the summary report renders the capture's fixed epoch
    as wall-clock text, and the product keeps local time for humans while the
    gate stays hermetic."""
    env = {**os.environ, "TZ": "UTC"}
    return harness.run_text([*cmd, str(FIXTURE), *args], env=env).stdout


# tally and distinct share the CLI's one StrMap, which doubles at 50% load. Both
# used to write through the freed table once a grow happened mid-scan, because
# `m.nums[smap_intern(...)]++` leaves the base pointer and the index unsequenced:
# the compiler may load nums BEFORE the call, and the call can free it.
#
# This cannot be a golden case -- a golden freezes bytes, and the crash was a
# SIGSEGV, which produces no bytes to freeze. It also cannot sample one size: the
# earliest grows land in a block that is still mapped, so nothing visible breaks
# until a later one. Walk ACROSS several boundaries and check the row count.
GROW_SIZES = (510, 511, 512, 1022, 1023, 1024, 1025, 2047, 2048, 4095, 4096, 8192)


def check_grow_boundary() -> bool:
    if harness.missing_bins(SUBLIMATION):
        note(f"FAIL: missing {SUBLIMATION.relative_to(ROOT)} (build first)")
        return False
    bad = []
    for n in GROW_SIZES:
        data = "".join(f"{i}\n" for i in range(n))
        t = harness.run_text([str(SUBLIMATION), "tally"], input=data, cwd=ROOT)
        d = harness.run_text([str(SUBLIMATION), "distinct"], input=data, cwd=ROOT)
        rows = sum(1 for line in t.stdout.split("\n") if line.strip())
        if t.returncode != 0 or rows != n:
            bad.append(f"tally n={n} rc={t.returncode} rows={rows}")
        if d.returncode != 0 or d.stdout.strip() != str(n):
            bad.append(f"distinct n={n} rc={d.returncode} out={d.stdout.strip()!r}")
    if bad:
        note("FAIL grow-boundary -- tally/distinct diverged:")
        for b in bad:
            note(f"  {b}")
        return False
    note(f"PASS grow-boundary ({len(GROW_SIZES)} sizes, "
         f"{GROW_SIZES[0]}..{GROW_SIZES[-1]})")
    return True


# tally breaks ties by the key alone, in descending byte order, so its output is
# a function of the multiset of lines and serpent can fold partial tallies into
# the sequential answer. The order is held to the pipeline the help names, and
# the line format (unpadded count, one space, the key as read) is frozen because
# serpent rebuilds it; a key with leading spaces has to survive it.
TALLY_KEYS = ("b", "a", "B", "  lead", "lead", "x y", "a ", "", "z") + tuple(f"u{i}" for i in range(40))


def check_tally_ties() -> bool:
    import random
    rng = random.Random(20261004)
    lines = [rng.choice(TALLY_KEYS[:9]) for _ in range(300)] + list(TALLY_KEYS[9:])
    outs = set()
    for _ in range(5):
        rng.shuffle(lines)
        data = "\n".join(lines) + "\n"
        outs.add(harness.run_text([str(SUBLIMATION), "tally"], input=data, cwd=ROOT).stdout)
    gnu = subprocess.run("LC_ALL=C /usr/bin/sort | /usr/bin/uniq -c | LC_ALL=C /usr/bin/sort -rn",
                         shell=True, input=data, capture_output=True, text=True).stdout
    # uniq -c right-aligns the count; tally does not. Same order, tally's format.
    want = [" ".join(ln.lstrip().split(" ", 1)) if " " in ln.lstrip() else ln.lstrip() + " "
            for ln in gnu.split("\n") if ln]
    got = next(iter(outs)).split("\n")[:-1]
    if len(outs) != 1 or got != want:
        diff = next(((g, w) for g, w in zip(got, want) if g != w), (len(got), len(want)))
        note(f"FAIL tally-ties -- {len(outs)} distinct output(s) over 5 shuffles; "
             f"first divergence from the pipeline (got, want): {diff!r}")
        return False
    note("PASS tally-ties (5 shuffles identical, order and format match the pipeline)")
    return True


def check_json_wellformed() -> bool:
    """The envelope must PARSE. An agent consumes it, so malformed JSON is a real
    defect."""
    exe = Path(ANALYZE[0])
    if harness.missing_bins(exe):
        note(f"FAIL: missing {exe.relative_to(ROOT)} (build first)")
        return False
    got = run_stdout(ANALYZE, ["--json"])
    import json
    try:
        json.loads(got)
    except json.JSONDecodeError as e:
        note(f"FAIL json -- envelope does not parse ({e})")
        return False
    note(f"PASS json ({len(got)} bytes, parses)")
    return True


def check_surfaces_run() -> bool:
    """Analyzer and decoder must complete over the fixture. Not a byte compare --
    a nonzero exit or a crash is the failure this catches."""
    ok = True
    for label, cmd, args in (("reports", ANALYZE, []), ("decode", DECODE, [])):
        exe = Path(cmd[0])
        if harness.missing_bins(exe):
            note(f"FAIL: missing {exe.relative_to(ROOT)} (build first)")
            ok = False
            continue
        env = {**os.environ, "TZ": "UTC"}
        proc = harness.run_text([*cmd, str(FIXTURE), *args], env=env)
        if proc.returncode != 0 or not proc.stdout.strip():
            note(f"FAIL {label} -- rc={proc.returncode}, {len(proc.stdout)} bytes")
            ok = False
        else:
            note(f"PASS {label} ({proc.stdout.count(chr(10))} lines)")
    return ok


def check_cli_runs() -> bool:
    """Every deterministic CLI case must exit clean. The cases were written to be
    diffed; they are kept because they are broad COVERAGE of the CLI surface, and
    a crash or usage error in any of them is a defect with or without a golden."""
    if harness.missing_bins(SUBLIMATION):
        note(f"FAIL: missing {SUBLIMATION.relative_to(ROOT)} (build first)")
        return False
    bad = []
    for argv, stdin in CLI_CASES:
        proc = harness.run_text([str(SUBLIMATION), *argv], input=stdin, cwd=ROOT)
        # Exit 1 is "nothing matched", a legitimate outcome for search/where.
        # 2 is usage/pattern/IO error, and anything else is a signal.
        if proc.returncode not in (0, 1):
            shown = " ".join(a.replace("\n", "\\n") for a in argv)
            bad.append(f"sublimation {shown} -> rc={proc.returncode}")
    if bad:
        note("FAIL cli -- case(s) did not exit cleanly:")
        for b in bad:
            note(f"  {b}")
        return False
    note(f"PASS cli ({len(CLI_CASES)} cases exit clean)")
    return True


def main() -> int:
    argparse.ArgumentParser(description=__doc__).parse_args()
    with tempfile.TemporaryDirectory() as td:
        regenerate_fixture(Path(td))
        ok = check_surfaces_run()
        ok = check_json_wellformed() and ok
        ok = check_cli_runs() and ok
        ok = check_grow_boundary() and ok
        ok = check_tally_ties() and ok
    note("all surfaces healthy" if ok else "GATE FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
