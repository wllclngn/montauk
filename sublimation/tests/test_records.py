#!/usr/bin/env python3
"""The f64 record stream between value verbs, held to the text path.

A record is a value with its bits intact, and the CLI's text is shortest
round-trip, so the two carry the same values and every check here holds them
equal. A producer's text, parsed back, must be its records exactly. A consumer
fed records must answer exactly as it answers the same values as text. Every
producer into every consumer must agree with the text pipeline, including on a
value whose digits past the twelfth decide the answer. A consumer told
--records-in and handed text reads it as text, and every malformed stream or
misplaced flag is exit 2.
"""
import random
import struct
import subprocess
import sys
from pathlib import Path

# The binary under test is named by the caller (tests/run.py passes montauk's
# build/sublimation; a standalone sublimation build passes its own), so the
# test needs nothing outside this directory.
SUB = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else None
HEADER = b"SUBR\x01\x01\x00\x00"

PRODUCERS = [["sort"], ["sort", "--desc"], ["outliers"],
             ["locate", "sorted", "--values", "--window", "64"]]
CONSUMERS = [["sort"], ["sort", "--desc"], ["quantile", "0.5"],
             ["quantile", "0.99", "--nearest"], ["select", "3"],
             ["searchsorted", "500"], ["sum"], ["mean"], ["stdev"], ["variance"],
             ["min"], ["max"], ["describe"], ["outliers"], ["histogram"],
             ["classify"], ["locate", "random", "--window", "64"],
             ["locate", "sorted", "--values", "--window", "64"], ["rand"],
             ["characterize"]]

fails = 0


def note(m):
    print(f"[records] {m}", flush=True)


def fail(m):
    global fails
    fails += 1
    note(f"FAIL {m}")


def sub(args, data):
    r = subprocess.run([str(SUB), *args], input=data, capture_output=True)
    return r.returncode, r.stdout, r.stderr


def pipe(first, second, data):
    p1 = subprocess.Popen([str(SUB), *first], stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p2 = subprocess.Popen([str(SUB), *second], stdin=p1.stdout,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p1.stdout.close()
    p1.stdin.write(data)
    p1.stdin.close()
    out, err = p2.communicate()
    p1.wait()
    return p1.returncode, p2.returncode, out, err


def records(values):
    return HEADER + struct.pack(f"<{len(values)}d", *values)


def decode(blob):
    if blob[:8] != HEADER or (len(blob) - 8) % 8:
        return None
    return list(struct.unpack(f"<{(len(blob) - 8) // 8}d", blob[8:]))


def text(values, fmt=repr):
    return "".join(fmt(v) + "\n" for v in values).encode()


def main():
    if SUB is None or not SUB.exists():
        note(f"FAIL usage: test_records.py PATH/TO/sublimation (got {SUB})")
        return 1
    rng = random.Random(8140)

    # Full-precision doubles across magnitudes, with a sorted run for locate.
    exact = [rng.uniform(-1e3, 1e3) * 10 ** rng.randint(-6, 6) for _ in range(1500)]
    exact += sorted(rng.uniform(0, 1e3) for _ in range(500))
    # Integers, which '%.12g' carries without loss, plus fence-breaking outliers.
    whole = [float(rng.randrange(1000)) for _ in range(1500)]
    whole += [float(v) for v in range(1000, 1500)]
    whole += [1e7, -1e7, 3e7]

    # PRODUCERS: The records hold exactly the values the text prints.
    for p in PRODUCERS:
        for label, vals in (("exact", exact), ("whole", whole)):
            rc_t, out_t, _ = sub(p, text(vals))
            rc_r, out_r, _ = sub([*p, "--records-out"], text(vals))
            got = decode(out_r)
            if rc_r != rc_t or got is None:
                fail(f"{' '.join(p)} --records-out on {label}: rc {rc_r} vs {rc_t}, "
                     f"stream {'malformed' if got is None else 'ok'}")
            elif [float(x) for x in out_t.split()] != got:
                fail(f"{' '.join(p)} --records-out on {label}: records differ from text")
    sorted_r = decode(sub(["sort", "--records-out"], text(exact))[1])
    if sorted_r != sorted(exact):
        fail("sort --records-out does not carry the exact sorted values")
    note(f"producers: {len(PRODUCERS)} verbs, records match text and keep every bit")

    # CONSUMERS: records answer exactly as lossless text does.
    for c in CONSUMERS:
        for label, vals in (("exact", exact), ("whole", whole)):
            want = sub(c, text(vals))
            got = sub([*c, "--records-in"], records(vals))
            if got != want:
                fail(f"{' '.join(c)} --records-in on {label}: {got[:2]} vs {want[:2]}")
    note(f"consumers: {len(CONSUMERS)} verbs, records answer as lossless text does")

    # PAIRS: Every producer into every consumer, on whole and full-precision
    # values alike.
    npairs = 0
    for p in PRODUCERS:
        for c in CONSUMERS:
            for vals in (whole, exact):
                t = pipe(p, c, text(vals))
                r = pipe([*p, "--records-out"], [*c, "--records-in"], text(vals))
                npairs += 1
                if r != t:
                    fail(f"{' '.join(p)} | {' '.join(c)}: records {r[:3]} vs text {t[:3]}")
    note(f"pairs: {npairs} producer/consumer pipelines agree with text")

    # PRECISION: A value whose digits past the twelfth put it on the other side
    # of V. Text once printed it as 0.123456789012 and answered 1; both paths
    # must now answer as the direct run does.
    vals = [0.1234567890123456]
    probe = ["searchsorted", "0.12345678901234"]
    direct = sub(probe, text(vals))[1]
    via_text = pipe(["sort"], probe, text(vals))[2]
    via_rec = pipe(["sort", "--records-out"], [*probe, "--records-in"], text(vals))[2]
    if not (direct == via_rec == via_text == b"0\n"):
        fail(f"precision: direct {direct!r}, records {via_rec!r}, text {via_text!r}")
    big = [rng.uniform(-1e6, 1e6) for _ in range(300_000)]
    if pipe(["sort", "--records-out"], ["sum", "--records-in"], text(big))[2] != sub(["sum"], text(sorted(big)))[1]:
        fail("300k values: the record pipeline's sum differs from the sum of the exact values")
    note("precision: text and records both keep every digit, across 300k values too")

    # FALLBACK: text handed to --records-in reads as text, whatever the
    # 8-byte header read took from it.
    for blob in (b"", b"5\n", b"1\n2\n3\n4\n5\n", b"1234567\n8\n", b"12345678901",
                 b"x\n1\n2\n", b"  3.5  \n-2\n", text(exact[:50])):
        for c in (["sum"], ["sort"], ["describe"]):
            if sub([*c, "--records-in"], blob) != sub(c, blob):
                fail(f"fallback {' '.join(c)} on {blob[:16]!r}")
    note("fallback: text into --records-in reads as text")

    # ERRORS: a stream this build cannot read, or a flag a verb cannot honour.
    bad = {"version 2": b"SUBR\x02\x01\x00\x00" + struct.pack("<d", 1.0),
           "type 2": b"SUBR\x01\x02\x00\x00" + struct.pack("<d", 1.0),
           "reserved byte set": b"SUBR\x01\x01\x00\x01" + struct.pack("<d", 1.0),
           "cut mid-value": HEADER + struct.pack("<d", 1.0) + b"\x00\x01\x02"}
    for label, blob in bad.items():
        rc, out, err = sub(["sum", "--records-in"], blob)
        if rc != 2 or out or not err:
            fail(f"{label}: rc {rc}, stdout {out!r}")
    misuse = [["search", "x", "--records-in"], ["field", "1", "--records-in"],
              ["tally", "--records-in"], ["count", "--records-in"],
              ["sort", "--keyed", "--records-in"], ["sum", "--records-in", "--field", "1"],
              ["sum", "--records-out"], ["quantile", "0.5", "--records-out"],
              ["locate", "sorted", "--records-out"], ["sort", "--keyed", "--records-out"],
              ["search", "x", "--records-out"]]
    for args in misuse:
        rc, out, err = sub(args, text(whole[:10]))
        if rc != 2 or out or not err:
            fail(f"{' '.join(args)}: rc {rc}, stdout {out[:40]!r}")
    note(f"errors: {len(bad)} malformed streams and {len(misuse)} misplaced flags exit 2")

    if fails:
        note(f"GATE FAILED: {fails} check(s)")
        return 1
    note("GATE PASSED: records carry exactly the values text carries, every bit "
         "of them, between every producer and consumer")
    return 0


if __name__ == "__main__":
    sys.exit(main())
