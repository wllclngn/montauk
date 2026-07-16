#!/usr/bin/env python3
"""Harness for search_research.c: byte-parity oracle plus per-regime throughput.

This is a research harness, wired to become a real tests/ module once the search
primitive stabilizes. It answers one question with data: does choosing the anchor
by MEASURING this corpus beat ASSUMING an English model, and where.

For each corpus regime it (1) proves every C strategy agrees with a Python
ground-truth substring count (byte-parity, loud fail on divergence) and (2) times
each C strategy plus the external baselines that are installed (grep always, rg
and python always, a Go program if `go` is present), against the wc -l
touch-every-byte ceiling.

Deterministic: all corpora are seeded, so a run reproduces byte for byte.
"""
import glob
import os
import random
import re
import shutil
import statistics
import subprocess
import sys
import time
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent


def note(msg):
    print(f"[search] {msg}", flush=True)


CBIN = HERE / "search_research"
CSRC = HERE / "search_research.c"
# leverage_g (the local pattern graph) is shelved as a FUTURE item, gated on
# structured tails -- its mechanism is proven (beats the proxy on correlated data)
# but it is never the overall winner on the current corpora. Code and R_eff stay.
# recur is UNSOUND (extrapolates the match count from one period, wrong when the
# matches are not periodic) so it is NOT in the parity-gated set. It is exercised
# only in the Phase 2 section below, which shows both its win and its limit.
STRATS = ["bmh", "shiftand", "frozen", "data_relative", "qgram", "leverage", "classify"]
SIZE = 30_000_000
SEED = 1729


def build() -> bool:
    cc = shutil.which("clang") or shutil.which("cc") or shutil.which("gcc")
    if not cc:
        note("FAIL: no C compiler (clang/cc/gcc)")
        return False
    r = subprocess.run([cc, "-O2", "-march=native", "-std=c23",
                        str(CSRC), "-o", str(CBIN)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        note("FAIL: build error")
        sys.stdout.write(r.stderr)
        return False
    note(f"built {CBIN.name} via {Path(cc).name}")
    return True


def plant(buf: bytearray, pat: bytes, k: int, rng: random.Random) -> None:
    n = len(buf)
    for pos in rng.sample(range(0, n - len(pat), 991), k):
        buf[pos:pos + len(pat)] = pat


def gen_corpora():
    """Return [(name, bytes, pattern, expect_note)]. Each ~SIZE bytes, seeded."""
    rng = random.Random(SEED)
    out = []

    # english: pseudo-English. frozen ~ data_relative (control -- English IS the
    # frozen model's assumption).
    words = (b"the of and to in a is that for it as was with be by on not he "
             b"this are or his from at which but have an had they you were their "
             b"one all would there her so what up out if about who get which go me")
    ws = words.split()
    b = bytearray()
    while len(b) < SIZE:
        b += ws[rng.randrange(len(ws))]
        b += b" " if rng.random() < 0.85 else b"\n"
    b = bytearray(b[:SIZE])
    plant(b, b"quicksort", 400, rng)
    out.append(("english", bytes(b), b"quicksort", "control: frozen ~ data"))

    # dna: uniform ACGT. control -- max entropy, nothing to exploit, expect parity.
    b = bytearray(rng.choices(b"ACGT", k=SIZE))
    plant(b, b"ACGTTGCAACGTTGCAACGTTGCA", 300, rng)
    out.append(("dna", bytes(b), b"ACGTTGCAACGTTGCAACGTTGCA", "control: uniform, expect parity"))

    # base64: base64 alphabet, mild skew.
    alpha = (b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
    b = bytearray(rng.choices(alpha, k=SIZE))
    plant(b, b"aGVsbG8gd29ybGQ", 300, rng)
    out.append(("base64", bytes(b), b"aGVsbG8gd29ybGQ", "modest"))

    # frozen_adversarial: English-rare letters (z q x j k v w y) made COMMON,
    # English-common 'e' made RARE. frozen anchors on 'z' (common here -> crater);
    # data_relative measures 'e' rare -> wins. The clean thesis demonstrator.
    common = b"zqxjkvwy"
    b = bytearray()
    while len(b) < SIZE:
        b.append(common[rng.randrange(len(common))] if rng.random() < 0.99 else ord("e"))
    b = bytearray(b[:SIZE])
    plant(b, b"zqxjeqzx", 300, rng)
    out.append(("frozen_adversarial", bytes(b), b"zqxjeqzx",
                "frozen mispicks 'z' (common); data anchors 'e' (rare)"))

    # repetitive: one block repeated. anchor strategies do not exploit recurrence
    # yet (that is the PALIMPSEST primitive, later) -- included to watch behavior.
    block = bytes(rng.choices(b"ACGTacgt0123", k=4096))
    b = bytearray()
    while len(b) < SIZE:
        b += block
    b = bytearray(b[:SIZE])
    plant(b, b"MARKERpatternXYZ", 300, rng)
    out.append(("repetitive", bytes(b), b"MARKERpatternXYZ", "recurrence unexploited yet"))

    # markov: order-1 chain, strong adjacency correlation (each byte predicts the
    # next). Positions are statistically dependent, which the LOCAL graph can see
    # and the space-by-2 proxy cannot. The corpus that tests whether leverage_g
    # earns its place -- independent corpora above cannot show it by construction.
    alpha = b"ACGTacgt"
    b = bytearray()
    cur = 0
    while len(b) < SIZE:
        b.append(alpha[cur])
        cur = (cur + 1) % len(alpha) if rng.random() < 0.75 else rng.randrange(len(alpha))
    b = bytearray(b[:SIZE])
    plant(b, b"ACGTacgtACGT", 300, rng)
    out.append(("markov", bytes(b), b"ACGTacgtACGT", "correlated: the leverage_g test"))

    # pure_repeat: one small-alphabet block repeated identically. Pattern is a
    # substring of the block, so it is COMMON (no rare byte, the anchor cannot
    # skip) and recurs once per copy. Max repetition. THE prize: current scans all
    # n, a delta-proportional matcher could do ~one block.
    block = bytes(rng.choices(b"ACGTacgt", k=4096))
    b = bytearray((block * (SIZE // len(block) + 1))[:SIZE])
    out.append(("pure_repeat", bytes(b), block[100:116],
                "common pat + max repetition: the prize"))

    # versioned: a base document repeated with ~1% per-copy edits (logs, git
    # history, telemetry). Common pattern, near-repetition, realistic.
    base = bytearray(rng.choices(b"abcdefghijklmnop ", k=8192))
    b = bytearray()
    while len(b) < SIZE:
        copy = bytearray(base)
        for _ in range(len(base) // 100):
            copy[rng.randrange(len(base))] = rng.choice(b"abcdefghijklmnop ")
        b += copy
    b = bytearray(b[:SIZE])
    out.append(("versioned", bytes(b), bytes(base[200:216]),
                "common pat + near-repetition (logs/git)"))

    # real data: actual on-disk bytes (kernel C source), not synthetic. Skipped if
    # absent. Reinforces that the numbers are not a synthetic artifact.
    srcs = glob.glob("/home/mod/.cache/pandemonium/prism-cachyos-assets/"
                     "linux-6.14.7/**/*.c", recursive=True)
    if srcs:
        rb = bytearray()
        for f in srcs:
            if len(rb) >= SIZE:
                break
            try:
                rb += open(f, "rb").read()
            except OSError:
                pass
        rb = bytes(rb[:SIZE])
        if len(rb) > 100_000 and b"struct " in rb:
            out.append(("real_src", rb, b"struct ", "real on-disk source"))
    return out


def overlapping_count(data: bytes, pat: bytes) -> int:
    """Count ALL occurrences including overlaps -- what a real search reports, and
    what the C strategies count. bytes.count() is non-overlapping, wrong oracle."""
    c, i = 0, data.find(pat)
    while i != -1:
        c += 1
        i = data.find(pat, i + 1)
    return c


def pos_checksum(data: bytes, pat: bytes) -> int:
    """FNV-style fold over match START positions (overlapping, increasing) matching
    the C accumulator exactly, uint64 wraparound. Verifies WHERE, not just count."""
    MASK = (1 << 64) - 1
    h = 1469598103934665603
    i = data.find(pat)
    while i != -1:
        h = (h * 1000003 + i) & MASK
        i = data.find(pat, i + 1)
    return h


def c_run(mode: str, strat: str, pat: bytes, data: bytes) -> str:
    # pat is passed as raw BYTES in argv (os.fsencode leaves bytes untouched), so
    # binary/high-byte patterns survive -- a str arg would UTF-8-mangle them.
    r = subprocess.run([str(CBIN), mode, strat, pat], input=data,
                       capture_output=True)
    return r.stdout.decode().strip()


def c_count(strat: str, pat: bytes, data: bytes) -> int:
    return int(c_run("count", strat, pat, data) or -1)


def c_poscheck(strat: str, pat: bytes, data: bytes) -> int:
    return int(c_run("poscheck", strat, pat, data) or -1)


def c_bench(strat: str, pat: bytes, data: bytes) -> float:
    try:
        return float(c_run("bench", strat, pat, data))
    except ValueError:
        return 0.0


def ext_bench(argv, data: bytes) -> float:
    ts = []
    for _ in range(5):
        t0 = time.perf_counter()
        subprocess.run(argv, input=data, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
        ts.append(time.perf_counter() - t0)
    dt = min(ts)
    return len(data) / 1e6 / dt if dt > 0 else 0.0


def py_bench(pat: bytes, data: bytes) -> float:
    ts = []
    for _ in range(5):
        t0 = time.perf_counter()
        data.count(pat)
        ts.append(time.perf_counter() - t0)
    dt = min(ts)
    return len(data) / 1e6 / dt if dt > 0 else 0.0


def reff_test() -> bool:
    """Effective resistance vs closed-form resistor-network values (exact)."""
    r = subprocess.run([str(CBIN), "reff_selftest"], capture_output=True, text=True)
    ok = True
    for line in r.stdout.splitlines():
        p = line.split()
        name = p[0]
        got = float(p[1].split("=")[1])
        want = float(p[2].split("=")[1])
        close = abs(got - want) < 1e-6
        note(f"  {name:20s} got={got:.6f} want={want:.6f} " + ("ok" if close else "FAIL"))
        ok = ok and close
    return ok


def main() -> int:
    if not build():
        return 1

    note("effective-resistance correctness (vs closed-form networks):")
    if not reff_test():
        note("FAIL: effective resistance wrong -- fix the math before using it")
        return 1

    have_rg = shutil.which("rg") is not None
    have_grep = shutil.which("grep") is not None
    corpora = gen_corpora()

    # PARITY: every C strategy must equal Python's ground-truth substring count.
    note("byte-parity oracle (C strategies vs Python ground truth):")
    fails = 0
    for name, data, pat, _ in corpora:
        truth = overlapping_count(data, pat)
        row = {s: c_count(s, pat, data) for s in STRATS}
        ok = all(v == truth for v in row.values())
        note(f"  {name:20s} truth={truth:<6d} " +
             ("all agree" if ok else "DIVERGED " + str(row)))
        if not ok:
            fails += 1
    if fails:
        note(f"FAIL: {fails} corpus/corpora diverged -- correctness before speed")
        return 1

    # PHASE R: POSITION-checksum parity (stronger than count -- an off-by-one anchor
    # passes a count check but not this).
    note("")
    note("position-checksum parity (Phase R): WHERE matches land, not just count")
    pos_fail = 0
    for name, data, pat, _ in corpora:
        gt = pos_checksum(data, pat)
        row = {s: c_poscheck(s, pat, data) for s in STRATS}
        ok = all(v == gt for v in row.values())
        note(f"  {name:20s} " + ("positions agree" if ok else f"DIVERGED gt={gt} {row}"))
        if not ok:
            pos_fail += 1
    if pos_fail:
        note(f"FAIL: {pos_fail} corpus/corpora position-diverged")
        return 1

    # PHASE R: edge cases -- count parity on tricky inputs (binary, overlap,
    # pattern longer than data, high bytes, single byte, no match, whole).
    note("")
    note("edge cases (Phase R): count parity on tricky inputs")
    edge = [
        ("pat_longer",  b"abcdefgh", b"abc"),
        ("nul_in_data", b"ab", b"a\x00abab\x00ab"),
        ("high_bytes",  b"\xff\xfe", b"\x00\xff\xfe\x01\xff\xfe"),
        ("pat_len_1",   b"a", b"banana"),
        ("no_match",    b"zzz", b"abcabcabc"),
        ("whole",       b"abc", b"abc"),
        ("overlap_aa",  b"aa", b"aaaa"),
    ]
    edge_fail = 0
    for nm, pat, data in edge:
        truth = overlapping_count(data, pat)
        row = {s: c_count(s, pat, data) for s in STRATS}
        ok = all(v == truth for v in row.values())
        note(f"  {nm:16s} truth={truth} " + ("ok" if ok else f"DIVERGED {row}"))
        if not ok:
            edge_fail += 1
    if edge_fail:
        note(f"FAIL: {edge_fail} edge case(s) diverged")
        return 1

    # PHASE 1: the repetition detector must flag the repetitive corpora and stay
    # quiet on the diverse ones (distinct-16gram fraction, low = repetitive).
    note("")
    note("repetition detector (Phase 1): low score = repetitive")
    REPETITIVE = {"repetitive", "pure_repeat", "versioned"}
    det_fail = 0
    for name, data, _, _ in corpora:
        r = subprocess.run([str(CBIN), "repscore"], input=data,
                           capture_output=True)
        score = float(r.stdout.decode().strip())
        want_rep = name in REPETITIVE
        got_rep = score < 0.5
        ok = got_rep == want_rep
        note(f"  {name:20s} score={score:.3f} "
             f"{'repetitive' if got_rep else 'diverse':10s} " + ("ok" if ok else "MISFLAG"))
        if not ok:
            det_fail += 1
    if det_fail:
        note(f"FAIL: repetition detector misflagged {det_fail} corpus/corpora")
        return 1

    # PHASE 2: the regex field, classes (fixed-length) plus quantifiers,
    # alternation and grouping (the Glushkov NFA), vs an independent Python oracle
    # that counts MATCH-END positions (what the field computes). Non-nullable.
    def end_positions(pattern, text):
        # Text-anchor semantics matching the C engine: a leading ^ forces the
        # match to start at 0, a trailing $ to end at len(text). fullmatch alone
        # would treat ^/$ as redundant, so strip them and apply the constraint.
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
    note("")
    note("regex field (Phase 2): C field vs Python re, match-end count")
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
        ("^abc", b"abc xabc abcx abc"),          # A1 start anchor
        ("xyz$", b"xyz xyzq axyz zzxyz"),         # A1 end anchor
        ("^cat$", b"cat"),                        # A1 both, whole
        ("^cat$", b"cats"),                       # A1 both, no match
        ("a*", b"bab aa b"),                      # A2 nullable unanchored
        ("x?y", b"xy y ay xz"),                   # A2 optional (non-nullable)
        ("[0-9]{3}", b"12 345 6789 00"),          # A3 bounded exact
        ("a{2,4}", b"a aa aaa aaaa aaaaa"),       # A3 bounded range
    ]
    rfail = 0
    for rpat, text in rcases:
        got = int(subprocess.run([str(CBIN), "regexcount", rpat], input=text,
                                 capture_output=True).stdout.decode().strip())
        truth = end_positions(rpat, text)
        ok = got == truth
        note(f"  {rpat:14s} got={got} truth={truth} " + ("ok" if ok else "DIVERGED"))
        if not ok:
            rfail += 1
    if rfail:
        note(f"FAIL: {rfail} regex case(s) diverged")
        return 1

    # PHASE 3: fuzzy k-mismatch (Hamming <= k) vs an independent Python brute oracle.
    def kmismatch_count(text, pat, k):
        m = len(pat)
        c = 0
        for i in range(len(text) - m + 1):
            mis = sum(1 for j in range(m) if text[i + j] != pat[j])
            if mis <= k:
                c += 1
        return c
    note("")
    note("fuzzy k-mismatch (Phase 3): C field vs Python brute")
    fcases = [
        (b"hello", b"hello hallo hellp world help", 1),
        (b"abcd", b"abcd abxd axcd abxy zzzz", 1),
        (b"GATTACA", b"GATTACA GATTTCA GAAAACA CCCCCCC", 2),
        (b"needle", b"needle noodle kindle needlz", 2),
    ]
    ffail = 0
    for pat, text, k in fcases:
        truth = kmismatch_count(text, pat, k)
        brute = int(subprocess.run([str(CBIN), "fuzzycount", str(k), pat],
                                   input=text, capture_output=True).stdout.decode().strip())
        # E3: the pigeonhole-prefiltered fuzzy must equal the brute exactly.
        pre = int(subprocess.run([str(CBIN), "fuzzypre", str(k), pat],
                                 input=text, capture_output=True).stdout.decode().strip())
        ok = brute == truth == pre
        note(f"  k={k} {pat.decode():10s} brute={brute} pre={pre} truth={truth} " +
             ("ok" if ok else "DIVERGED"))
        if not ok:
            ffail += 1
    # E3 on larger data: prefiltered fuzzy byte-identical to brute, and faster.
    big = (b"the quick brown fox jumps over the lazy dog " * 40000)
    for pat, k in [(b"quick", 1), (b"jumps", 2), (b"brown", 1)]:
        brute = int(subprocess.run([str(CBIN), "fuzzycount", str(k), pat],
                                   input=big, capture_output=True).stdout.decode().strip())
        pre = int(subprocess.run([str(CBIN), "fuzzypre", str(k), pat],
                                 input=big, capture_output=True).stdout.decode().strip())
        ok = brute == pre
        note(f"  big k={k} {pat.decode():8s} brute={brute} pre={pre} " +
             ("byte-parity" if ok else "DIVERGED"))
        if not ok:
            ffail += 1
    if ffail:
        note(f"FAIL: {ffail} fuzzy case(s) diverged")
        return 1

    # PHASE 4: the unified dispatcher. `search` routes a plain literal to the
    # anchor face and a regex to the field, and must agree with each face's oracle.
    note("")
    note("dispatch (Phase 4): search routes by pattern class")
    dfail = 0
    for name, data, pat, _ in corpora:
        got = int(subprocess.run([str(CBIN), "search", pat], input=data,
                                 capture_output=True).stdout.decode().strip())
        if got != overlapping_count(data, pat):
            note(f"  literal {name:16s} got={got} truth={overlapping_count(data, pat)} DIVERGED")
            dfail += 1
    for rpat, text in rcases:
        got = int(subprocess.run([str(CBIN), "search", rpat], input=text,
                                 capture_output=True).stdout.decode().strip())
        if got != end_positions(rpat, text):
            note(f"  regex {rpat:14s} got={got} truth={end_positions(rpat, text)} DIVERGED")
            dfail += 1
    note("  " + ("literal corpora and regex cases all route correctly"
                 if dfail == 0 else f"{dfail} case(s) misrouted"))
    if dfail:
        note(f"FAIL: dispatch misrouted {dfail} case(s)")
        return 1

    # PHASE B: prefilter wiring. The prefiltered regex must equal the un-prefiltered
    # field exactly (byte-parity), including on large real data. The prefilter may
    # only skip provable non-matches, never alter the count.
    note("")
    note("prefilter wiring (Phase B): prefiltered == field, byte-parity")
    bcases = [
        ("gr[ae]y", b"grey gray groy xgraey " * 200),
        ("colou?r", b"color colour colr coloured " * 200),
        ("hel[lp]o", b"hello help hellp helo heIIo " * 200),
        ("[0-9][0-9]ax", b"11ax 2ax 33ax 4a5ax " * 200),
        ("th[aeiou]", b"the tha thi tho thx th  " * 200),   # class run > literal run
        ("wo[a-z]d", b"word wold wobd wox wo1d " * 200),     # class contents not the literal
    ]
    real = next((d for nm, d, p, e in corpora if nm == "real_src"), None)
    if real is not None:
        bcases.append(("str[a-z]ct", real))       # 'struct' etc., prefilter on 'str'
        bcases.append(("ret[a-z]rn", real))       # 'return', prefilter on 'ret'
    bfail = 0
    for rpat, text in bcases:
        pre = int(subprocess.run([str(CBIN), "regexpre", rpat], input=text,
                                 capture_output=True).stdout.decode().strip())
        full = int(subprocess.run([str(CBIN), "regexcount", rpat], input=text,
                                  capture_output=True).stdout.decode().strip())
        ok = pre == full
        tag = f"{len(text)//1000}KB" if len(text) >= 1000 else f"{len(text)}B"
        note(f"  {rpat:14s} {tag:>6s} pre={pre} field={full} " +
             ("byte-parity" if ok else "DIVERGED"))
        if not ok:
            bfail += 1
    if bfail:
        note(f"FAIL: prefilter broke byte-parity on {bfail} case(s)")
        return 1

    # THROUGHPUT: C strategies + external baselines, MB/s, vs wc -l ceiling.
    note("")
    note("throughput MB/s (median of 9) -- higher is better:")
    hdr = f"  {'regime':20s} " + " ".join(f"{s[:9]:>9s}" for s in STRATS) + \
          f" | {'ceil':>7s} {'grep':>7s} {'rg':>7s} {'python':>7s}"
    note(hdr)
    for name, data, pat, expect in corpora:
        cells = [f"{c_bench(s, pat, data):9.0f}" for s in STRATS]
        ceil = ext_bench(["wc", "-l"], data)
        grep = ext_bench(["grep", "-Fc", pat.decode("latin1")], data) if have_grep else 0.0
        rg = ext_bench(["rg", "-Fc", pat.decode("latin1")], data) if have_rg else 0.0
        py = py_bench(pat, data)
        # Compressibility = prize ceiling. High ratio + common pattern (anchor
        # can't skip) => a delta-proportional matcher has room the byte-scanners
        # cannot reach. len/compressed via zlib is a cheap repetition proxy.
        comp = len(data) / max(1, len(zlib.compress(data, 6)))
        note(f"  {name:20s} " + " ".join(cells) +
             f" | {ceil:7.0f} {grep:7.0f} {rg:7.0f} {py:7.0f}")
        note(f"  {'':20s} ({expect}) comp={comp:.0f}x")

    # PHASE 2: recurrence exploit vs ground truth and the flat scan. Kept off the
    # parity gate because its correctness is conditional on EXACT periodicity.
    note("")
    note("recurrence exploit (Phase 2): recur vs truth and flat best")
    for want in ("pure_repeat", "versioned", "repetitive"):
        data, pat = next((d, p) for nm, d, p, e in corpora if nm == want)
        truth = overlapping_count(data, pat)
        got = c_count("recur", pat, data)
        exact = "byte-exact" if got == truth else "WRONG (near-repetition)"
        speed = c_bench("recur", pat, data)
        flat = max(c_bench(s, pat, data) for s in ("bmh", "data_relative"))
        note(f"  {want:20s} recur={got} truth={truth} -> {exact}")
        note(f"  {'':20s} recur {speed:.0f} MB/s vs flat_best {flat:.0f} MB/s "
             f"-> {'FASTER' if speed > flat else 'not faster'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
