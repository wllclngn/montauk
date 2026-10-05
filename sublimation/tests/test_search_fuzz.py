#!/usr/bin/env python3
"""Differential fuzz of the regex face, every public entry point held to an oracle.

test_search_match.py proves the COUNTER over hand-written cases. This proves the
API over generated ones -- the shapes nobody thought to write down, which is
where every defect in the code around the field engine was found.

Oracles, per generated (pattern, text):
  count     distinct match-END positions (the header's definition)
  find      leftmost start, LONGEST end (the whole-match rule)
  full      whole-input match
  spans     the CLI walk the header defines: leftmost-longest, advance past the
            end, step one byte on a zero-width match and record nothing
  captures  Python re over the match span in its line: Perl subgroup rules,
            which is the semantics the header states (POSIX's differ on
            repeated and nested groups; see sublimation_search_captures_at)
  -x / -w   /usr/bin/grep -E, which the header claims selection parity with

Passes: the narrow field (<= 64 positions), the same under ICASE, and the wide
field (65-128 positions), which nothing else compiles except by accident. Fixed
pins after the generator hold the shapes that were found by hand.
"""
import random
import re
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from multiprocessing import Pool, TimeoutError as PoolTimeout
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import test_search_match as tsm  # noqa: E402  (shares the library build)

PROBE = tsm.BUILD / "search_probe"
GREP = shutil.which("grep")
SHOW = 12
# Python's re is a backtracker, so a generated pattern can be exponential for
# the ORACLE -- one took 327s. A case past this budget is reported as skipped,
# never as passed, and the pool worker running it is killed.
ORACLE_BUDGET_S = 10
TOO_LONG = 2   # SUBLIMATION_SEARCH_ERR_TOO_LONG


def note(msg):
    print(f"[fuzz] {msg}", flush=True)


def build_probe() -> bool:
    if not tsm.build_lib():
        return False
    cc = shutil.which("gcc") or shutil.which("cc") or shutil.which("clang")
    r = subprocess.run([cc, "-std=c2x", "-O2", "-Wall", "-Wextra",
                        "-I", str(tsm.SRC_DIR / "include"), "-I", str(tsm.SRC_DIR),
                        str(HERE / "search_probe.c"), str(tsm.LIB), "-lm",
                        "-o", str(PROBE)], capture_output=True, text=True)
    if r.returncode != 0 or r.stderr.strip():
        note("FAIL: build search_probe")
        sys.stdout.write(r.stderr)
        return False
    return True


class Gen:
    """ERE subset both the field engine and Python re agree on the meaning of."""

    def __init__(self, seed, alpha="abc"):
        self.r = random.Random(seed)
        self.alpha = alpha

    def atom(self, d):
        r = self.r.random()
        if d > 0 and r < 0.15:
            return "(" + self.alt(d - 1) + ")"
        if r < 0.30:
            return "."
        if r < 0.45:
            cs = "".join(sorted(self.r.sample("abc", self.r.randint(1, 3))))
            return ("[^" if self.r.random() < 0.3 else "[") + cs + "]"
        return self.r.choice("abc")

    def piece(self, d):
        a, r = self.atom(d), self.r.random()
        if r < 0.15:
            return a + "*"
        if r < 0.27:
            return a + "+"
        if r < 0.37:
            return a + "?"
        if r < 0.45:
            lo = self.r.randint(0, 3)
            hi = lo + self.r.randint(0, 2)
            return a + ("{%d}" % lo if self.r.random() < 0.4 else "{%d,%d}" % (lo, hi))
        return a

    def concat(self, d):
        return "".join(self.piece(d) for _ in range(self.r.randint(1, 4)))

    def alt(self, d):
        parts = [self.concat(d)]
        while self.r.random() < 0.25:
            parts.append(self.concat(d))
        return "|".join(parts)

    def pattern(self):
        p = self.alt(2)
        if self.r.random() < 0.15:
            p = "^" + p
        if self.r.random() < 0.15:
            p += "$"
        return p

    def text(self, lo=0, hi=24):
        return "".join(self.r.choice(self.alpha) for _ in range(self.r.randint(lo, hi)))

    def wide(self):
        """65-128 positions, few quantifiers (so Python's backtracker stays
        linear), with a text built to contain an instance most of the time --
        a random text against a 100-atom pattern only ever tests the miss."""
        toks, inst = [], []
        for _ in range(self.r.randint(70, 120)):
            r = self.r.random()
            if r < 0.6:
                c = self.r.choice("abc")
                tok, pick = c, lambda c=c: c
            elif r < 0.85:
                cs = "".join(sorted(self.r.sample("abc", 2)))
                tok, pick = "[" + cs + "]", lambda cs=cs: self.r.choice(cs)
            else:
                tok, pick = ".", lambda: self.r.choice("abc")
            q = self.r.random()
            if q < 0.08:
                toks.append(tok + "?")
                inst += [pick() for _ in range(self.r.randint(0, 1))]
            elif q < 0.12:
                toks.append(tok + "+")
                inst += [pick() for _ in range(self.r.randint(1, 2))]
            else:
                toks.append(tok)
                inst.append(pick())
        body = "".join(inst)
        if self.r.random() < 0.3 and body:
            i = self.r.randrange(len(body))
            body = body[:i] + self.r.choice("abc ") + body[i + 1:]
        return "".join(toks), self.text(0, 6) + body + self.text(0, 6)


def ends_from(p, t, flags):
    """For every start s, the set of ends e such that some match spans [s, e).

    ERE anchors mean the TEXT's edges wherever they appear, which is what
    Python's ^ and $ mean too -- as long as the string is never sliced. So the
    end is pinned with a lookahead on the exact remaining suffix instead: (?=
    SUFFIX\\Z) holds at one offset only."""
    M = set()
    if "^" not in p and "$" not in p:
        # No assertion to misplace, so slicing is exact and one compile serves.
        rx = re.compile(p, flags)
        for s in range(len(t) + 1):
            for en in range(s, len(t) + 1):
                if rx.fullmatch(t, s, en):
                    M.add((s, en))
        return M
    for en in range(len(t) + 1):
        rx = re.compile(f"(?:{p})(?={re.escape(t[en:])}\\Z)", flags)
        for s in range(en + 1):
            if rx.match(t, s):
                M.add((s, en))
    return M


def oracle(p, t, flags):
    M = ends_from(p, t, flags)
    count = len({en for _, en in M})
    find = (-1, -1)
    if M:
        s0 = min(s for s, _ in M)
        find = (s0, max(en for s, en in M if s == s0))
    full = 1 if re.compile(p, flags).fullmatch(t) else 0
    spans, off = [], 0
    while off <= len(t):
        cand = [(s, en) for s, en in M if s >= off]
        if not cand:
            break
        s0 = min(s for s, _ in cand)
        en0 = max(en for s, en in cand if s == s0)
        if en0 == s0:
            off = s0 + 1
            continue
        spans.append((s0, en0))
        off = en0
    caps = None
    ngroups = re.compile(p, flags).groups
    if ngroups and find[0] >= 0:
        rx = re.compile(f"(?:{p})(?={re.escape(t[find[1]:])}\\Z)", flags)
        m = rx.match(t, find[0])
        caps = [(-1, -1) if m.start(i) < 0 else (m.start(i), m.end(i))
                for i in range(1, ngroups + 1)]
    return count, find, full, spans, caps


def oracle_all(cases, flags):
    """oracle() over every case in a process pool; None marks a skipped case."""
    out = [None] * len(cases)
    i = 0
    while i < len(cases):
        with Pool(8) as pool:
            jobs = [(k, pool.apply_async(oracle, (p, t, flags)))
                    for k, (p, t) in enumerate(cases[i:], i)]
            for k, job in jobs:
                try:
                    out[k] = job.get(timeout=ORACLE_BUDGET_S)
                except PoolTimeout:
                    i = k + 1
                    break
            else:
                i = len(cases)
    return out


def parse(line):
    head, cpart, spart, xw = line.split(" | ")
    h = head.split()
    c = cpart.split()
    s = list(map(int, spart.split()[1:]))
    x = xw.split()
    caps = None
    if c[1] == "1":
        v = list(map(int, c[3:]))
        caps = [(v[i], v[i + 1]) for i in range(0, len(v), 2)]
    return {"npos": int(h[1]), "count": int(h[2]), "find": (int(h[3]), int(h[4])),
            "full": int(h[5]), "cap_ok": c[1], "caps": caps,
            "spans": [(s[1 + 2 * i], s[2 + 2 * i]) for i in range(s[0])],
            "x": int(x[1]), "w": int(x[3])}


def grep_selects(p, t, icase, mode):
    args = [GREP, "-q", "-E", mode] + (["-i"] if icase else []) + ["--", p]
    r = subprocess.run(args, input=t.encode() + b"\n", capture_output=True,
                       env={"LC_ALL": "C"})
    return {0: 1, 1: 0}.get(r.returncode)


def run_pass(name, cases, icase, fails, want_wide=False):
    face = "regexi" if icase else "regex"
    inp = "".join(f"{face} {p.encode().hex() or '-'} {t.encode().hex() or '-'}\n"
                  for p, t in cases)
    r = subprocess.run([str(PROBE)], input=inp.encode(), capture_output=True)
    out = r.stdout.decode().splitlines()
    if r.returncode != 0 or len(out) != len(cases):
        fails.append((name, "probe", "", "", f"exit {r.returncode}, {len(out)}/{len(cases)} lines"))
        return
    flags = re.IGNORECASE if icase else 0
    with ThreadPoolExecutor(8) as ex:
        greps = list(ex.map(lambda pt: (grep_selects(pt[0], pt[1], icase, "-x"),
                                        grep_selects(pt[0], pt[1], icase, "-w")), cases))
    wide = skipped = over = 0
    for (p, t), line, (gx, gw), want in zip(cases, out, greps, oracle_all(cases, flags)):
        if line.startswith("0 "):
            # Over the position budget is the documented limit, reported by its
            # own code; anything else refused a pattern the grammar allows.
            if line.split()[1] == str(TOO_LONG):
                over += 1
            else:
                fails.append((name, "refused", p, t, line))
            continue
        got = parse(line)
        if want_wide and 64 < got["npos"] <= 128:
            wide += 1
        if gx is not None and got["x"] != gx:
            fails.append((name, "-x", p, t, f"got {got['x']} grep {gx}"))
        if gw is not None and got["w"] != gw:
            fails.append((name, "-w", p, t, f"got {got['w']} grep {gw}"))
        if want is None:
            skipped += 1
            continue
        count, find, full, spans, caps = want
        for key, exp in (("count", count), ("find", find), ("full", full), ("spans", spans)):
            if got[key] != exp:
                fails.append((name, key, p, t, f"got {got[key]} want {exp}"))
        if caps is not None and got["find"] == find:
            if got["cap_ok"] != "1":
                fails.append((name, "captures", p, t, f"failed closed, want {caps}"))
            elif got["caps"] != caps:
                fails.append((name, "captures", p, t, f"got {got['caps']} want {caps}"))
    if want_wide and wide < len(cases) * 0.8:
        fails.append((name, "wide", "", "", f"only {wide}/{len(cases)} cases reached 65-128 positions"))
    note(f"{name}: {len(cases)} cases" + (f", {wide} in the wide field" if want_wide else "")
         + (f", {over} over the position budget" if over else "")
         + (f", {skipped} SKIPPED (oracle over {ORACLE_BUDGET_S}s)" if skipped else ""))


# Shapes found by hand, held as regression pins. Each runs in its own probe
# process so a crash fails one pin instead of the batch.
PINS = [
    ("anchored capture, leading ^", "^(ab)", "abab"),
    ("anchored capture, trailing $", "(ab)$", "abab"),
    ("anchored nullable, ^c*", "^c*", "aba"),
    ("anchored nullable, c?$", "c?$", " cbac b"),
    ("capture depth 100k", "(a*)", "a" * 100_000),
]


def run_pins(fails):
    for name, p, t in PINS:
        inp = f"regex {p.encode().hex()} {t.encode().hex()}\n".encode()
        r = subprocess.run([str(PROBE)], input=inp, capture_output=True)
        if r.returncode != 0:
            fails.append(("pin", name, p, t[:24], f"probe died (exit {r.returncode})"))
            continue
        got = parse(r.stdout.decode().strip())
        count, find, full, spans, caps = oracle(p, t, 0) if len(t) < 64 else (None,) * 5
        if len(t) >= 64:   # the depth pin: one group spanning the whole input
            caps, find = [(0, len(t))], (0, len(t))
        if count is not None and (got["count"], got["find"]) != (count, find):
            fails.append(("pin", name, p, t, f"count/find {got['count']}/{got['find']} "
                                              f"want {count}/{find}"))
        if caps is not None and (got["cap_ok"] != "1" or got["caps"] != caps):
            fails.append(("pin", name, p, t[:24], f"captures {got['cap_ok']} {got['caps']} want {caps}"))
    note(f"pins: {len(PINS)}")


def main() -> int:
    if not GREP:
        note("FAIL: no grep for the -w/-x oracle")
        return 1
    if not build_probe():
        return 1
    fails = []
    for seed in (1, 2, 3):
        g = Gen(seed, "abc ")
        run_pass(f"narrow seed {seed}", [(g.pattern(), g.text()) for _ in range(400)],
                 False, fails)
    g = Gen(4, "abcABC ")
    run_pass("icase seed 4", [(g.pattern(), g.text()) for _ in range(400)], True, fails)
    g = Gen(5, "abc ")
    run_pass("wide seed 5", [g.wide() for _ in range(150)], False, fails, want_wide=True)
    run_pins(fails)

    by_kind = {}
    for f in fails:
        by_kind[f[1]] = by_kind.get(f[1], 0) + 1
    for name, kind, p, t, detail in fails[:SHOW]:
        note(f"  [{name}] {kind}: pat={p!r} text={t!r} -> {detail}")
    if fails:
        note(f"FAIL: {len(fails)} divergence(s) " +
             ", ".join(f"{k}={v}" for k, v in by_kind.items()))
        return 1
    note("PASS: every entry point agrees with its oracle")
    return 0


if __name__ == "__main__":
    sys.exit(main())
