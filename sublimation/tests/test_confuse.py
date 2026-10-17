#!/usr/bin/env python3
"""search --confuse, held to the rule it documents.

A confusion class makes substitutions among its members free: Every member is
rewritten to the class's shortest member (the first, on a tie), longest member
first and left to right, in the pattern and in the text, and mismatches are
counted between the two rewritten forms. A window starts only where a
rewritten unit does, and a span ends where the unit it ends in does. The
oracle here is that rule in Python, run over random classes (members of one
and two bytes, the two-byte ſ among them), texts and patterns, on the literal
face and the fuzzy face at k = 1 and 2, under -c, -o and -x and with -i. Fixed
cases pin the 1666 example it was asked for and the refusals.
"""
import random
import subprocess
import sys
from pathlib import Path

SUB = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else None
fails = 0


def note(m):
    print(f"[confuse] {m}", flush=True)


def check(ok, what):
    global fails
    if not ok:
        fails += 1
        if fails <= 12:
            note(f"FAIL {what}")


def parse(spec):
    classes, cur, member, i = [[]], None, bytearray(), 0
    raw = spec.encode()
    while i <= len(raw):
        c = raw[i:i + 1]
        if c in (b"", b",", b"="):
            classes[-1].append(bytes(member))
            member = bytearray()
            if c == b",":
                classes.append([])
            i += 1
            if c == b"":
                break
            continue
        if c == b"\\" and i + 1 < len(raw):
            i += 1
        member += raw[i:i + 1]
        i += 1
    members = []
    for cls in classes:
        rep = min(range(len(cls)), key=lambda j: (len(cls[j]), j))
        for m in cls:
            members.append((m, cls[rep]))
    return members


def fold(b, icase):
    return bytes(x + 32 if icase and 65 <= x <= 90 else x for x in b)


def rewrite(text, members, icase):
    out, unit, starts, i = bytearray(), [], [], 0
    while i < len(text):
        best = None
        for m, rep in members:
            if (best is None or len(m) > len(best[0])) and \
                    fold(text[i:i + len(m)], icase) == fold(m, icase):
                best = (m, rep)
        if best:
            for q, ch in enumerate(best[1]):
                out.append(ch); unit.append(q == 0); starts.append(i)
            i += len(best[0])
        else:
            out.append(text[i]); unit.append(True); starts.append(i); i += 1
    starts.append(len(text))
    return bytes(out), unit, starts


def within(a, b, k, icase):
    return sum(x != y for x, y in zip(fold(a, icase), fold(b, icase))) <= k


def find(line, frm, pat, members, k, icase):
    rw, unit, starts = rewrite(line[frm:], members, icase)
    m = len(pat)
    for i in range(len(rw) - m + 1):
        if unit[i] and within(rw[i:i + m], pat, k, icase):
            ce = i + m
            while ce < len(rw) and not unit[ce]:
                ce += 1
            return frm + starts[i], frm + starts[ce]
    return None


def oracle(lines, pattern, spec, k, icase, mode):
    members = parse(spec)
    pat = rewrite(pattern, members, icase)[0]
    out = []
    for line in lines:
        if mode == "-x":
            rw = rewrite(line, members, icase)[0]
            if len(rw) == len(pat) and within(rw, pat, k, icase):
                out.append(line)
        elif mode == "-c":
            if find(line, 0, pat, members, k, icase):
                out.append(line)
        else:
            off = 0
            while off <= len(line):
                r = find(line, off, pat, members, k, icase)
                if not r:
                    break
                out.append(line[r[0]:r[1]])
                off = r[1]
    if mode == "-c":
        return b"%d\n" % len(out)
    return b"".join(x + b"\n" for x in out)


def run(args, data):
    return subprocess.run([str(SUB), "search", *args], input=data, capture_output=True)


ALPHA = ["a", "b", "c", "f", "ſ", "n", "u", "r", "m", "e", "A", "F"]
MEMBERS = ["a", "b", "c", "f", "ſ", "n", "u", "rn", "m", "e", "ii"]


def rand_spec(rng):
    pool = rng.sample(MEMBERS, rng.randint(2, 6))
    classes, i = [], 0
    while len(pool) - i >= 2:
        size = rng.randint(2, min(3, len(pool) - i))
        classes.append("=".join(pool[i:i + size])); i += size
    return ",".join(classes)


def main() -> int:
    if SUB is None or not SUB.is_file():
        note("DECLINED: usage: test_confuse.py PATH/TO/sublimation")
        return 2
    rng = random.Random(1666)
    checks = 0
    for i in range(300):
        spec = rand_spec(rng)
        lines = ["".join(rng.choice(ALPHA) for _ in range(rng.randint(0, 24))).encode()
                 for _ in range(12)]
        pattern = "".join(rng.choice(ALPHA) for _ in range(rng.randint(1, 5))).encode()
        data = b"".join(x + b"\n" for x in lines)
        for face, k in (("-F", 0), ("-k", 1), ("-k", 2)):
            for icase in (False, True):
                for mode in ("-c", "-o", "-x"):
                    args = [mode, "--confuse", spec]
                    args += ["-F"] if face == "-F" else ["-k", str(k)]
                    if icase:
                        args.append("-i")
                    args += ["-e", pattern.decode()]
                    r = run(args, data)
                    want = oracle(lines, pattern, spec, k, icase, mode)
                    got = r.stdout if r.returncode in (0, 1) else None
                    checks += 1
                    check(got == want, f"#{i} {' '.join(args)}: {got!r} vs {want!r}")

    text = "medicina Ficino\nFiſino writes\nnothing here\n".encode()
    r = run(["-o", "-F", "--confuse", "c=ſ", "Ficin"], text)
    check(r.stdout == "Ficin\nFiſin\n".encode(), f"1666 Ficin/Fiſin: {r.stdout!r}")
    check(b"dicin" not in r.stdout, "-F with classes still matched dicin")
    r = run(["-o", "-k", "1", "--confuse", "rn=m", "modem"], b"modern\nmodem\nmodal\nmodemx\n")
    check(r.stdout == b"modern\nmodem\nmodem\n", f"rn=m under -k 1: {r.stdout!r}")
    r = run(["-o", "-F", "--confuse", "rn=m", "modem"], b"modern\nmodem\nmodal\n")
    check(r.stdout == b"modern\nmodem\n", f"rn=m under -F: {r.stdout!r}")
    r = run(["-c", "-F", "--confuse", r"\,=;", "a,b"], b"a;b\na,b\nab\n")
    check(r.stdout == b"2\n", f"escaped ',' member: {r.stdout!r}")
    for bad in ("f", "f=", "=f", "a=b,b=c", "a=b,,c=d", ""):
        r = run(["-F", "--confuse", bad, "x"], b"x\n")
        check(r.returncode == 2 and b"not a class list" in r.stderr, f"spec {bad!r} not refused")
    r = run(["--confuse", "f=ſ", "x"], b"x\n")
    check(r.returncode == 2 and b"give -F or -k N" in r.stderr, "regex face not refused")
    checks += 11

    if fails:
        note(f"GATE FAILED: {fails} of {checks} checks")
        return 1
    note(f"{checks} checks hold: 300 random class sets, texts and patterns against the "
         f"rewrite rule on -F and -k 1/2, under -c -o -x and -i, and the fixed cases")
    return 0


if __name__ == "__main__":
    sys.exit(main())
