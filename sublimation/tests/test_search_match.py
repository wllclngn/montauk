#!/usr/bin/env python3
"""Byte-parity gate for the shipped sublimation_search API (text/match.c).

Builds libsublimation from the in-tree sources and the C harness test_search_match.c
(which touches ONLY the public sublimation_search API), then proves every count the
new API reports is byte-identical to an independent Python reference:

  exact/literal  -> overlapping_count   (all occurrences, overlaps included)
  regex          -> end_positions       (Python re, match-end count, ^/$ text-anchored)
  fuzzy          -> kmismatch_count      (brute Hamming <= k)

The corpora and cases are reused from test_search_research.py. find/find_from/
full_match are exercised for self-consistency. Any divergence fails loudly.
"""
import importlib.util
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SUB_ROOT = HERE.parent
SRC_DIR = SUB_ROOT / "src"
RESEARCH = HERE / "search" / "test_search_research.py"
BUILD = HERE / "_match_build"
LIB = BUILD / "libsublimation.a"
CBIN = BUILD / "test_search_match"


def note(msg):
    print(f"[match] {msg}", flush=True)


# Reuse the research corpora + reference generator verbatim.
_spec = importlib.util.spec_from_file_location("search_research_ref", RESEARCH)
_ref = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_ref)
gen_corpora = _ref.gen_corpora
overlapping_count = _ref.overlapping_count


def end_positions(pattern, text):
    # Text-anchor semantics matching the C engine (verbatim from the research test).
    astart = pattern.startswith("^")
    aend = pattern.endswith("$")
    core = pattern[1:] if astart else pattern
    core = core[:-1] if aend else core
    rx = re.compile(core)
    c = 0
    for ep in range(len(text) + 1):
        for sp in range(ep + 1):
            if astart and sp != 0:
                continue
            if aend and ep != len(text):
                continue
            if rx.fullmatch(text[sp:ep].decode("latin1")):
                c += 1
                break
    return c


def kmismatch_count(text, pat, k):
    m = len(pat)
    c = 0
    for i in range(len(text) - m + 1):
        mis = sum(1 for j in range(m) if text[i + j] != pat[j])
        if mis <= k:
            c += 1
    return c


def build_lib() -> bool:
    cc = shutil.which("gcc") or shutil.which("cc") or shutil.which("clang")
    if not cc:
        note("FAIL: no C compiler")
        return False
    BUILD.mkdir(exist_ok=True)
    srcs = sorted(str(p) for p in SRC_DIR.rglob("*.c"))
    base = [cc, "-std=c2x", "-O2", "-march=native", "-fPIC",
            "-I", str(SRC_DIR / "include"), "-I", str(SRC_DIR)]
    objs = []
    match_warned = False
    for s in srcs:
        obj = BUILD / (Path(s).stem + ".o")
        extra = ["-Wall", "-Wextra"] if Path(s).name == "match.c" else []
        r = subprocess.run(base + extra + ["-c", s, "-o", str(obj)],
                           capture_output=True, text=True)
        if r.returncode != 0:
            note(f"FAIL: compile {Path(s).name}")
            sys.stdout.write(r.stderr)
            return False
        if Path(s).name == "match.c" and r.stderr.strip():
            note("FAIL: match.c emitted warnings (zero-warning gate):")
            sys.stdout.write(r.stderr)
            match_warned = True
        objs.append(str(obj))
    if match_warned:
        return False
    subprocess.run(["ar", "rcs", str(LIB)] + objs, check=True)
    r = subprocess.run([cc, "-std=c2x", "-O2", "-march=native",
                        "-I", str(SRC_DIR / "include"), "-I", str(SRC_DIR),
                        str(HERE / "test_search_match.c"), str(LIB),
                        "-lm", "-o", str(CBIN)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        note("FAIL: link test harness")
        sys.stdout.write(r.stderr)
        return False
    note(f"built libsublimation.a + harness via {Path(cc).name} (match.c: zero warnings)")
    return True


def _argv(*parts):
    return [os.fsencode(p) if isinstance(p, str) else p for p in parts]


def c_count(face, k, pat: bytes, data: bytes) -> int:
    r = subprocess.run(_argv(str(CBIN), "count", face, str(k), pat),
                       input=data, capture_output=True)
    return int(r.stdout.decode().strip() or "-1")


def c_find(face, k, pat: bytes, data: bytes):
    r = subprocess.run(_argv(str(CBIN), "find", face, str(k), pat),
                       input=data, capture_output=True)
    out = r.stdout.decode().strip()
    if out == "-1":
        return None
    a, b = out.split()
    return int(a), int(b)


def c_full(face, k, pat: bytes, data: bytes) -> int:
    r = subprocess.run(_argv(str(CBIN), "full", face, str(k), pat),
                       input=data, capture_output=True)
    return int(r.stdout.decode().strip() or "-1")


def main() -> int:
    if not build_lib():
        return 1

    corpora = gen_corpora()
    fails = 0

    # Exact / literal face: overlapping occurrence count.
    note("")
    note("exact face (fixed): count vs Python overlapping_count")
    ex_fail = 0
    for name, data, pat, _ in corpora:
        truth = overlapping_count(data, pat)
        got = c_count("fixed", 0, pat, data)
        ok = got == truth
        note(f"  {name:20s} got={got:<7d} truth={truth:<7d} " + ("ok" if ok else "DIVERGED"))
        if not ok:
            ex_fail += 1
    edge = [
        ("pat_longer",  b"abcdefgh", b"abc"),
        ("nul_in_data", b"ab", b"a\x00abab\x00ab"),
        ("high_bytes",  b"\xff\xfe", b"\x00\xff\xfe\x01\xff\xfe"),
        ("pat_len_1",   b"a", b"banana"),
        ("no_match",    b"zzz", b"abcabcabc"),
        ("whole",       b"abc", b"abc"),
        ("overlap_aa",  b"aa", b"aaaa"),
    ]
    for nm, pat, data in edge:
        truth = overlapping_count(data, pat)
        got = c_count("fixed", 0, pat, data)
        ok = got == truth
        note(f"  edge {nm:16s} got={got} truth={truth} " + ("ok" if ok else "DIVERGED"))
        if not ok:
            ex_fail += 1
    note(f"  exact face: {'all agree' if ex_fail == 0 else str(ex_fail) + ' DIVERGED'}")
    fails += ex_fail

    # Regex face: match-end count. rcases cover classes, ranges, negation, dot,
    # * + ?, alternation, grouping, anchors ^ $, nullable, bounded {m,n}.
    note("")
    note("regex face: count vs Python re (match-end positions)")
    rcases = [
        ("gr[ae]y", b"grey gray groy grey xgraey"),
        ("a.c", b"abc axc a c aac abcabc"),
        ("[0-9][0-9]", b"12 3 456 78x90 007"),
        ("[^ ]a", b"ba ca  a xa zza"),
        ("[a-c][x-z]", b"ax by cz dz aw"),
        ("ab*c", b"ac abc abbc abbbc axc"),
        ("a+b", b"ab aab aaab b ba"),
        ("colou?r", b"color colour colr colour"),
        ("cat|dog", b"cat dog cot catdog"),
        ("[0-9]+", b"12 3 456 xyz 78"),
        ("(ab)+c", b"abc ababc abababc ac"),
        ("a.*b", b"ab axxb aXXb a b bab"),
        ("^abc", b"abc xabc abcx abc"),
        ("xyz$", b"xyz xyzq axyz zzxyz"),
        ("^cat$", b"cat"),
        ("^cat$", b"cats"),
        ("a*", b"bab aa b"),
        ("x?y", b"xy y ay xz"),
        ("[0-9]{3}", b"12 345 6789 00"),
        ("a{2,4}", b"a aa aaa aaaa aaaaa"),
    ]
    re_fail = 0
    for rpat, text in rcases:
        got = c_count("regex", 0, rpat.encode(), text)
        truth = end_positions(rpat, text)
        ok = got == truth
        note(f"  {rpat:14s} got={got} truth={truth} " + ("ok" if ok else "DIVERGED"))
        if not ok:
            re_fail += 1
    note(f"  regex face: {'all agree' if re_fail == 0 else str(re_fail) + ' DIVERGED'}")
    fails += re_fail

    # Regex prefilter stress (large repeated texts): the count must still equal the
    # field oracle -- proving the internal literal prefilter never changes the count.
    note("")
    note("regex prefilter parity: prefiltered count vs field oracle on repeated data")
    bcases = [
        ("gr[ae]y", b"grey gray groy xgraey " * 200),
        ("colou?r", b"color colour colr coloured " * 200),
        ("hel[lp]o", b"hello help hellp helo heIIo " * 200),
        ("[0-9][0-9]ax", b"11ax 2ax 33ax 4a5ax " * 200),
        ("th[aeiou]", b"the tha thi tho thx th  " * 200),
        ("wo[a-z]d", b"word wold wobd wox wo1d " * 200),
    ]
    real = next((d for nm, d, p, e in corpora if nm == "real_src"), None)
    if real is not None:
        bcases.append(("str[a-z]ct", real))
        bcases.append(("ret[a-z]rn", real))
    b_fail = 0
    for rpat, text in bcases:
        got = c_count("regex", 0, rpat.encode(), text)
        # end_positions is O(n^2); on the big real corpus use the exact overlapping
        # start count instead. The real_src patterns are fixed-length, so each match
        # has a unique end and the two counts coincide with the field's match-ends.
        truth = end_positions(rpat, text) if len(text) < 20000 else overlap_start_count(rpat, text)
        ok = got == truth
        tag = f"{len(text)//1000}KB" if len(text) >= 1000 else f"{len(text)}B"
        note(f"  {rpat:14s} {tag:>6s} got={got} truth={truth} " + ("ok" if ok else "DIVERGED"))
        if not ok:
            b_fail += 1
    note(f"  prefilter: {'byte-parity' if b_fail == 0 else str(b_fail) + ' DIVERGED'}")
    fails += b_fail

    # Fuzzy face: k-mismatch window count.
    note("")
    note("fuzzy face: count vs Python brute k-mismatch")
    fcases = [
        (b"hello", b"hello hallo hellp world help", 1),
        (b"abcd", b"abcd abxd axcd abxy zzzz", 1),
        (b"GATTACA", b"GATTACA GATTTCA GAAAACA CCCCCCC", 2),
        (b"needle", b"needle noodle kindle needlz", 2),
    ]
    fz_fail = 0
    for pat, text, k in fcases:
        got = c_count("fuzzy", k, pat, text)
        truth = kmismatch_count(text, pat, k)
        ok = got == truth
        note(f"  k={k} {pat.decode():10s} got={got} truth={truth} " + ("ok" if ok else "DIVERGED"))
        if not ok:
            fz_fail += 1
    big = (b"the quick brown fox jumps over the lazy dog " * 40000)
    for pat, k in [(b"quick", 1), (b"jumps", 2), (b"brown", 1)]:
        got = c_count("fuzzy", k, pat, big)
        truth = kmismatch_count(big, pat, k)
        ok = got == truth
        note(f"  big k={k} {pat.decode():8s} got={got} truth={truth} " +
             ("byte-parity" if ok else "DIVERGED"))
        if not ok:
            fz_fail += 1
    note(f"  fuzzy face: {'all agree' if fz_fail == 0 else str(fz_fail) + ' DIVERGED'}")
    fails += fz_fail

    # find / full_match self-consistency (the collector/FFI surface).
    note("")
    note("find / full_match: API self-consistency")
    ff_fail = 0
    for name, data, pat, _ in corpora:
        res = c_find("fixed", 0, pat, data)
        truth = overlapping_count(data, pat)
        if truth == 0:
            if res is not None:
                note(f"  find {name:16s} expected no match, got {res} DIVERGED")
                ff_fail += 1
            continue
        if res is None:
            note(f"  find {name:16s} expected a match, got none DIVERGED")
            ff_fail += 1
            continue
        start, end = res
        exp = data.find(pat)
        if start != exp or end != start + len(pat) or data[start:end] != pat:
            note(f"  find {name:16s} start={start} end={end} expected {exp} DIVERGED")
            ff_fail += 1
    for pat in [b"abc", b"quicksort", b"GATTACA"]:
        if c_full("fixed", 0, pat, pat) != 1:
            note(f"  full '{pat.decode()}' on itself != 1 DIVERGED")
            ff_fail += 1
        if c_full("fixed", 0, pat, pat + b"x") != 0:
            note(f"  full '{pat.decode()}' on superset != 0 DIVERGED")
            ff_fail += 1
    # regex find: leftmost start must equal Python re.search on non-anchored cases.
    for rpat, text in [("a.c", b"xxabcxx"), ("colou?r", b"see color here"),
                       ("[0-9]+", b"abc123def"), ("cat|dog", b"the dog ran")]:
        res = c_find("regex", 0, rpat.encode(), text)
        m = re.search(rpat, text.decode("latin1"))
        if (res is None) != (m is None):
            note(f"  regex find {rpat} presence mismatch DIVERGED")
            ff_fail += 1
        elif res is not None and res[0] != m.start():
            note(f"  regex find {rpat} start={res[0]} re={m.start()} DIVERGED")
            ff_fail += 1
    note(f"  find/full: {'consistent' if ff_fail == 0 else str(ff_fail) + ' DIVERGED'}")
    fails += ff_fail

    note("")
    if fails:
        note(f"GATE FAILED: {fails} divergence(s)")
        return 1
    note("GATE PASSED: byte-parity holds on every face (exact, regex, fuzzy) "
         "plus prefilter parity and find/full self-consistency")
    return 0


def overlap_start_count(pattern, text):
    # Exact overlapping count of start positions where `pattern` matches, via a
    # zero-width lookahead scan in the regex C engine (fast on 30 MB). For the
    # fixed-length patterns this is used on, match-end positions are unique, so this
    # equals the field engine's match-end count.
    rx = re.compile("(?=(" + pattern + "))")
    return sum(1 for _ in rx.finditer(text.decode("latin1")))


if __name__ == "__main__":
    sys.exit(main())
