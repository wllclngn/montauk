#!/usr/bin/env python3
"""Shared search corpus fixture: the seeded corpora and the overlapping-count
oracle, used by the committed shipped-matcher gate (test_search_match.py) and by
the search research harness in tests/research/search/. Extracted here so the
committed gate has no dependency on the (gitignored) research tree.

Deterministic: all corpora are seeded, so a run reproduces byte for byte.
"""
import glob
import random

SIZE = 30_000_000
SEED = 1729


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
