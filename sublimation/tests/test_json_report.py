#!/usr/bin/env python3
"""The report verbs' --json face, held to their text reports.

describe, histogram, classify, locate, rand and characterize each print one
JSON object with --json. Every figure the text prints must be in it, equal
where the text is exact and within the text's own rounding where the text
rounds, and every figure the text leaves out as unmeasured must be null. The
class must be spelled as CLASS is, --records-in must give the same document,
and --json on any other verb, or on locate --values, is exit 2.
"""
import json
import random
import struct
import subprocess
import sys
from pathlib import Path

# The binary under test is named by the caller, so the test needs nothing
# outside this directory.
SUB = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else None

fails = 0
# Each null-or-measured field must be seen measured at least once, so a run
# whose inputs never reach the measured path cannot pass on nulls alone.
seen = {"phase_boundary": 0, "comparison_efficiency": 0, "lens": 0}


def note(m):
    print(f"[json] {m}", flush=True)


def check(ok, what):
    global fails
    if not ok:
        fails += 1
        note(f"FAIL {what}")


def run(args, data):
    return subprocess.run([str(SUB), *args], input=data, capture_output=True)


def near(a, text, places):
    """A JSON number against the text's fixed-point rendering of it."""
    return a is not None and abs(a - float(text)) <= 0.5 * 10 ** -places + 1e-9


def text_class(s):
    return s.lower().replace("_", "-")


def inputs():
    rng = random.Random(1666)
    gauss = [rng.gauss(0, 1) for _ in range(2000)]
    asc = list(range(1024))
    # A sorted prefix, then a scrambled run above it: The classifier names the
    # boundary. The scramble is a fixed stride, since the sampled inversion ratio
    # can tip a seeded draw of the same shape into nearly-sorted.
    phased = list(range(2000)) + [2000 + (i * 1237) % 2000 for i in range(2000)]
    # Small and nearly sorted: The tableau runs, so characterize measures its
    # comparison efficiency where every other input leaves it unmeasured.
    nearly = list(range(230)) + [230 + rng.random() * 26 for _ in range(26)]
    few = [rng.choice((1.5, 2.5, 3.5)) for _ in range(900)]
    const = [5.0] * 600

    def text(xs, junk=False):
        lines = [repr(x) for x in xs]
        if junk:
            lines.insert(3, "not a number")
        return ("\n".join(lines) + "\n").encode()

    return {"gauss": text(gauss), "sorted": text(asc), "phased": text(phased),
            "nearly-sorted": text(nearly),
            "few-unique": text(few), "constant": text(const),
            "gauss+junk": text(gauss, junk=True)}


def envelope(doc, verb, data, label):
    n = sum(1 for ln in data.decode().splitlines() if ln and ln[0] != "n")
    skipped = data.count(b"not a number")
    check(doc.get("schema_version") == 1, f"{label}: schema_version")
    check(doc.get("verb") == verb, f"{label}: verb")
    check(doc.get("n") == n, f"{label}: n {doc.get('n')} vs {n}")
    check(doc.get("skipped") == skipped, f"{label}: skipped {doc.get('skipped')} vs {skipped}")


def describe(doc, text, label):
    rows = dict(ln.split(None, 1) for ln in text.splitlines())
    check(int(rows["count"]) == doc["n"], f"{label}: count")
    for t, k in (("mean", "mean"), ("stdev", "stdev"), ("min", "min"), ("25%", "q25"),
                 ("50%", "q50"), ("75%", "q75"), ("max", "max")):
        check(float(rows[t]) == doc[k], f"{label}: {k} {doc[k]!r} vs {rows[t]}")


def histogram(doc, text, label):
    lines = text.splitlines()
    bins = doc["bins"]
    check(len(bins) == len(lines), f"{label}: {len(bins)} bins vs {len(lines)} lines")
    for b, ln in zip(bins, lines):
        edge, count = ln.split()[:2]
        check(b["count"] == int(count), f"{label}: bin count")
        check(f"{b['lo']:.6g}" == edge, f"{label}: edge {b['lo']!r} vs {edge}")
    for a, b in zip(bins, bins[1:]):
        check(a["hi"] == b["lo"], f"{label}: bins do not tile")
    check(sum(b["count"] for b in bins) == doc["n"], f"{label}: counts cover n")


def kv(text):
    out = {}
    for tok in text.split():
        for sep in ("=", "~"):
            if sep in tok:
                k, v = tok.split(sep, 1)
                out[k] = v
                break
    return out


def classify(doc, text, label):
    f = kv(text)
    check(doc["class"] == text_class(text.split()[0]), f"{label}: class")
    check(near(doc["inversion_ratio"], f["inversion_ratio"], 3), f"{label}: inversion_ratio")
    check(doc["lis"] == int(f["lis"]), f"{label}: lis")
    check(doc["distinct_estimate"] == int(f["distinct"]), f"{label}: distinct")
    check(doc["runs"] == int(f["runs"]), f"{label}: runs")
    if "phase_boundary" in f:
        seen["phase_boundary"] += 1
        check(doc["phase_boundary"] == int(f["phase_boundary"]), f"{label}: phase_boundary")
    else:
        check(doc["phase_boundary"] is None, f"{label}: phase_boundary should be null")


def rand(doc, text, label):
    head, *lens = text.splitlines()
    f = kv(head)
    check(near(doc["confidence"], f["confidence"], 3), f"{label}: confidence")
    check(doc["verdict"] == f["verdict"], f"{label}: verdict")
    k, n = f["(k"].split("/")
    check((doc["agree_count"], doc["lens_count"]) == (int(k), int(n)), f"{label}: k/N")
    check(len(doc["lenses"]) == len(lens), f"{label}: lens count")
    for ln in lens:
        name, v = ln.split()
        got = doc["lenses"].get(name, "missing")
        seen["lens"] += v == "--"
        check(got is None if v == "--" else near(got, v, 2), f"{label}: lens {name} {got!r} vs {v}")


def characterize(doc, text, label):
    f = kv(text)
    check(doc["class"] == text_class(text.split()[0]), f"{label}: class")
    check(near(doc["rand_confidence"], f["rand_confidence"], 3), f"{label}: rand_confidence")
    if "comparison_efficiency" in f:
        seen["comparison_efficiency"] += 1
        check(near(doc["comparison_efficiency"], f["comparison_efficiency"], 3),
              f"{label}: comparison_efficiency")
        check(near(doc["info_bound_bits"], f["info_bound"], 1), f"{label}: info_bound_bits")
    else:
        check(doc["comparison_efficiency"] is None and doc["info_bound_bits"] is None,
              f"{label}: unmeasured efficiency should be null")


def locate(doc, text, label, cls):
    head, *rows = text.splitlines()
    check(doc["class"] == cls, f"{label}: class")
    check(int(head.split()[0]) == len(doc["matches"]) == len(rows), f"{label}: match count")
    for m, ln in zip(doc["matches"], rows):
        span, inv, dist = ln.split()
        a, b = span.strip("[)").split(",")
        check((m["start"], m["end"]) == (int(a), int(b)), f"{label}: span")
        check(near(m["inversion_ratio"], inv.split("=")[1], 2), f"{label}: inv")
        check(m["distinct_estimate"] == int(dist.split("~")[1]), f"{label}: distinct")


def main() -> int:
    if SUB is None or not SUB.is_file():
        note("DECLINED: usage: test_json_report.py PATH/TO/sublimation")
        return 2
    verbs = {"describe": describe, "histogram": histogram, "classify": classify,
             "rand": rand, "characterize": characterize}
    docs = 0
    for name, data in inputs().items():
        for verb, held in verbs.items():
            label = f"{verb} on {name}"
            t, j = run([verb], data), run([verb, "--json"], data)
            check(t.returncode == j.returncode == 0, f"{label}: rc {t.returncode}/{j.returncode}")
            check(j.stdout.count(b"\n") == 1, f"{label}: one line, one object")
            doc = json.loads(j.stdout)
            docs += 1
            envelope(doc, verb, data, label)
            held(doc, t.stdout.decode(), label)
            if verb in ("classify", "characterize"):
                # The class is CLASS's spelling, so it feeds locate as it is.
                r = run(["locate", doc["class"], "--window", "128", "--json"], data)
                check(r.returncode == 0, f"{label}: class {doc['class']!r} refused by locate")
        for cls in ("sorted", "random", "few-unique", "phased"):
            label = f"locate {cls} on {name}"
            args = ["locate", cls, "--window", "128"]
            t, j = run(args, data), run([*args, "--json"], data)
            check(t.returncode == j.returncode == 0, f"{label}: rc")
            doc = json.loads(j.stdout)
            docs += 1
            envelope(doc, "locate", data, label)
            check((doc["window"], doc["stride"]) == (128, 128), f"{label}: window/stride")
            locate(doc, t.stdout.decode(), label, cls)

    # Records in, the same document out.
    data = inputs()["gauss"]
    recs = b"SUBR\x01\x01\x00\x00" + b"".join(
        struct.pack("<d", float(x)) for x in data.split())
    for verb in verbs:
        a = run([verb, "--json"], data).stdout
        b = run([verb, "--json", "--records-in"], recs).stdout
        check(a == b, f"{verb}: --records-in gives a different document")

    for args in (["sum"], ["sort"], ["quantile", "0.5"], ["outliers"], ["count"],
                 ["tally"], ["field", "1"], ["search", "x"],
                 ["locate", "sorted", "--values"]):
        r = run([*args, "--json"], b"1\n2\n3\n")
        check(r.returncode == 2 and r.stdout == b"", f"{' '.join(args)} --json is not refused")

    for what, k in seen.items():
        check(k > 0, f"no input reached a {'null ' if what == 'lens' else 'measured '}{what}")

    if fails:
        note(f"GATE FAILED: {fails} check(s)")
        return 1
    note(f"{docs} documents match their text reports; --records-in gives the same "
         f"document; --json is refused off the report verbs")
    return 0


if __name__ == "__main__":
    sys.exit(main())
