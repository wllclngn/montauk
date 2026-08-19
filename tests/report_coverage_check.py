#!/usr/bin/env python3
"""Which reports does the fixture actually EXERCISE, and which only ever run empty?

A passing golden does not distinguish "correct" from "never ran". kstrand proved
that: the fixture emitted a SCHED event with a comment calling it a strand, but
the report reads TRACE_EVT_KSTRAND and returns immediately on SCHED -- so its
aggregation, ranking, quantiles, HELD/DARK split and holder attribution were all
gated by never executing, for an unknown number of releases, while the gate
stayed green.

So this asks the cheap mechanical question of EVERY report: does the fixture
drive it to a real conclusion, or only to its empty path? The answer is frozen
below. A report that moves between the two lists must do so DELIBERATELY:

  - one leaving EXERCISED is a coverage regression, and the gate fails.
  - one leaving EMPTY is progress, and the gate fails too, so the list gets
    updated on purpose rather than drifting.

This is not a correctness check. It is a check that the correctness checks run.
"""
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))
import harness                                    # noqa: E402
import corpus_check as cc                         # noqa: E402

# Reports the fixture drives to a REAL conclusion -- their analysis path runs.
EXERCISED = {
    "classmix", "dispatch-stall", "doublefree", "endstate", "fractal",
    "iowait", "kick-latency", "kstrand", "locality", "matrix-profile",
    "pairing", "placement-race", "sched", "seat", "service", "slice",
    "summary", "wakers", "work-conservation",
    # Lit by fixture input added in v8.10.0: NTSYNC wait COMPLETIONS (the fixture
    # had only entry sentinels), a spin streak long enough to clear the 1000-
    # iteration detector, and futex waits through the IO door.
    "futex", "spins", "waits",
    # And by signal + abort records: signals had no events at all, and
    # abortpm reads TRACE_EVT_ABORT, which a SIGABRT delivery is not.
    "abortpm", "signals",
}

# Reports with NO INPUT in the fixture: the event class they read is absent, so
# only their empty path has ever executed. Each line names what is missing --
# that is the shopping list for closing the hole, not a shrug.
EMPTY_PATH = {
    "field-persist": "no field-gate events",
    "heapstk":       "no heap STACK captures (needs MONTAUK_HEAP_STACK_SIZE)",
    "iolat":         "no tracked I/O completions",
    "keyedevt":      "no keyed-event uprobe records",
    "storm":         "no scx storm records (opt-in, and 7.1-unsafe)",
    
}

# "no X" is ambiguous on its own: it can mean the report RAN and found nothing
# (a real result, e.g. work-conservation scanning for idle strands) or that it
# had nothing to run on. Only the latter counts as unexercised, so membership is
# declared above rather than inferred from the wording.
EMPTY_RE = re.compile(r"^(no |too few|empty trace|zero-duration)", re.I)


def note(m):
    print(f"[coverage] {m}", flush=True)


def main() -> int:
    if harness.missing_bins(harness.MONTAUK):
        note("FAIL: montauk not built"); return 1
    if not cc.FIXTURE.exists():
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            cc.regenerate_fixture(Path(td))

    out = harness.run_text([*harness.ANALYZE, str(cc.FIXTURE), "--json"],
                           env={**os.environ, "TZ": "UTC"}).stdout
    try:
        reports = json.loads(out)["reports"]
    except (ValueError, KeyError):
        note("FAIL: could not parse the JSON envelope"); return 1

    seen = {r["name"]: r for r in reports}
    fails = 0

    # Every report must conclude SOMETHING -- that is the envelope contract.
    silent = sorted(n for n, r in seen.items() if not r.get("verdict"))
    if silent:
        note(f"FAIL: {len(silent)} report(s) publish no verdict: {silent}")
        fails += 1

    declared = EXERCISED | set(EMPTY_PATH)
    missing = declared - set(seen)
    extra = set(seen) - declared
    if missing:
        note(f"FAIL: declared but absent from the envelope: {sorted(missing)}")
        fails += 1
    if extra:
        note(f"FAIL: new report(s) not classified here: {sorted(extra)} -- add "
             f"each to EXERCISED or EMPTY_PATH so the hole cannot open silently")
        fails += 1

    for name in sorted(EXERCISED & set(seen)):
        v = seen[name].get("verdict", "")
        # These legitimately CONCLUDE with a "no ..." sentence: they ran their
        # analysis and found the absence, which is a result. signals says "no
        # mid-trace signal deaths" while reporting the exits and deliveries it
        # counted; fractal says no series separates from uncorrelated after
        # running the DFA. The wording cannot distinguish them from "had no
        # input", so membership is declared rather than inferred.
        if EMPTY_RE.match(v) and name not in ("fractal", "work-conservation",
                                              "pairing", "wakers", "signals"):
            note(f"FAIL: {name} was exercised and now reads as empty: {v[:60]!r}")
            fails += 1

    for name in sorted(set(EMPTY_PATH) & set(seen)):
        v = seen[name].get("verdict", "")
        if not EMPTY_RE.match(v):
            note(f"FAIL: {name} now reaches a real conclusion ({v[:50]!r}) -- "
                 f"good, move it to EXERCISED")
            fails += 1

    note(f"{len(EXERCISED)} of {len(seen)} reports exercised by the fixture; "
         f"{len(EMPTY_PATH)} run only their empty path")
    if fails:
        note("GATE FAILED"); return 1
    note("coverage unchanged")
    return 0


if __name__ == "__main__":
    sys.exit(main())
