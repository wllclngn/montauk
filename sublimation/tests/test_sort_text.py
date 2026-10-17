#!/usr/bin/env python3
"""sort on text, held to the whole line and the exit-status contract.

A stream of bare numbers orders numerically as it always has. Any other stream
orders as whole lines in byte order, as LC_ALL=C sort does, and no line is ever
cut to its leading parse. -n forces the numeric order and refuses the first
line that is not a bare number, status 2. --keyed with no --field keys on the
whole line. Each shape here reproduced before the change: the dated listing
came back as `2026` three times under status 0, the word list was refused, and
--keyed kept input order because every line parsed to the key 2026.
"""
import random
import subprocess
import sys
from pathlib import Path

# The binary under test is named by the caller (tests/run.py passes montauk's
# build/sublimation; a standalone sublimation build passes its own).
SUB = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else None

DATED = b"2026-10-15_20:21 41530 ./ROADMAP.md\n2026-10-14_09:00 100 ./a\n2026-10-16_01:02 7 ./b\n"

fails = 0


def note(m):
    print(f"[sort-text] {m}", flush=True)


def fail(m):
    global fails
    fails += 1
    note(f"FAIL: {m}")


def sub(args, stdin):
    r = subprocess.run([str(SUB), *args], input=stdin, capture_output=True)
    return r.returncode, r.stdout, r.stderr


def lex(blob, desc=False):
    lines = blob.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    return b"".join(x + b"\n" for x in sorted(lines, reverse=desc))


def expect(label, args, stdin, rc, out, err_has=None):
    got_rc, got_out, got_err = sub(args, stdin)
    if got_rc != rc or got_out != out or (err_has and err_has not in got_err):
        fail(f"{label}: rc {got_rc} stdout {got_out[:60]!r} stderr {got_err[:80]!r}")


def main():
    if SUB is None or not SUB.exists():
        note("usage: test_sort_text.py PATH/TO/sublimation")
        return 2

    # THE THREE REPRODUCTIONS, each now the whole line.
    expect("dated listing", ["sort"], DATED, 0, lex(DATED))
    expect("dated listing --desc", ["sort", "--desc"], DATED, 0, lex(DATED, True))
    expect("words", ["sort"], b"pear\napple\nmango\n", 0, b"apple\nmango\npear\n")
    expect("keyed whole line", ["sort", "--keyed"], DATED, 0, lex(DATED))
    expect("keyed whole line is the line, not its leading number",
           ["sort", "--keyed"], b"10 b\n9 a\n", 0, b"10 b\n9 a\n")
    note("the three reproductions order as whole lines, status 0")

    # NEVER TRUNCATED: a number with a suffix is text.
    expect("suffixed numbers", ["sort"], b"12ms\n9ms\n", 0, b"12ms\n9ms\n")
    expect("mixed stream", ["sort"], b"3\nx\n1\n", 0, b"1\n3\nx\n")
    expect("--field text column", ["sort", "--field", "2"], b"a x\nb w\n", 0, b"w\nx\n")
    note("a line that is not a bare number is never cut to a leading parse")

    # NUMERIC STREAMS ARE UNCHANGED, blanks and whitespace included.
    expect("numbers", ["sort"], b"3\n1\n2\n", 0, b"1\n2\n3\n")
    expect("padded numbers", ["sort"], b"  3.5  \n-2\n1e1\n", 0, b"-2\n3.5\n10\n")
    expect("blank line skipped", ["sort"], b"3\n\n1\n", 0, b"1\n3\n", b"skipped 1")
    expect("--field numeric column", ["sort", "--field", "2"], b"a 10\nb 9\n", 0, b"9\n10\n")
    expect("keyed numeric lines", ["sort", "--keyed"], b"10\n9\n", 0, b"9\n10\n")
    expect("keyed --desc", ["sort", "--keyed", "--desc"], b"10\n9\n", 0, b"10\n9\n")
    expect("keyed --human keys on the first column", ["sort", "--keyed", "--human"],
           b"4.0K\t./x\n16M\t./y\n512\t./z\n", 0, b"512\t./z\n4.0K\t./x\n16M\t./y\n")
    expect("keyed -k 2 -t ,", ["sort", "-k", "2", "-t", ","], b"a,2\nb,1\n", 0, b"b,1\na,2\n")
    note("numeric streams order as before, with and without a key")

    # THE EXIT CONTRACT: -n refuses text at 2, records carry values only,
    # nothing produced is 1.
    expect("-n refuses text", ["sort", "-n"], b"12ms\n9ms\n", 2, b"", b"'12ms' is not a number")
    expect("-n on numbers", ["sort", "-rn"], b"3\n1\n", 0, b"3\n1\n")
    expect("--records-out on text", ["sort", "--records-out"], b"x\n", 2, b"", b"carries a value")
    expect("empty stdin", ["sort"], b"", 1, b"")
    note("-n refuses a text line at 2; --records-out on text is 2; empty is 1")

    # BYTE ORDER, against Python's sort of the same bytes, over random text
    # with bytes above ASCII, shared prefixes and a few bare numbers mixed in.
    rng = random.Random(7)
    alphabet = [bytes([b]) for b in list(range(0x20, 0x7f)) + [0xc3, 0xa9, 0xe2, 0x80]]
    for trial in range(20):
        lines = []
        for _ in range(rng.randint(1, 400)):
            n = rng.randint(0, 24)
            lines.append(b"".join(rng.choice(alphabet) for _ in range(n)))
        if rng.random() < 0.5:
            lines.append(str(rng.randint(-1000, 1000)).encode())
        blob = b"".join(x + b"\n" for x in lines)
        if all(x.strip() == b"" or is_number(x) for x in lines):
            continue
        rc, out, _ = sub(["sort"], blob)
        if rc != 0 or out != lex(blob):
            fail(f"byte order trial {trial}: rc {rc}")
            break
        rc, out, _ = sub(["sort", "--desc"], blob)
        if rc != 0 or out != lex(blob, True):
            fail(f"byte order --desc trial {trial}: rc {rc}")
            break
    note("byte order matches a sort of the same bytes over 20 random streams")

    if fails:
        note(f"GATE FAILED: {fails} check(s)")
        return 1
    note("GATE PASSED: sort orders text as whole lines and numbers as numbers, "
         "and never emits a truncated line")
    return 0


def is_number(x):
    try:
        float(x)
        return True
    except ValueError:
        return False


if __name__ == "__main__":
    sys.exit(main())
