#!/usr/bin/env python3
"""The query face against the fixture's kicks, whose answers are known.

The fixture issues 12 KICK_ISSUE events, 10 answered by a RESCHED 3.0-7.5us
later and 2 never answered. Every check here is arithmetic over those, so a
wrong operator cannot pass by being stable.
"""
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))
import harness                                    # noqa: E402
import corpus_check as cc                         # noqa: E402


def note(m):
    print(f"[query] {m}", flush=True)


def query(*args):
    r = harness.run_text([*harness.ANALYZE, str(cc.FIXTURE), "--select", *args, "--json"],
                         env={**os.environ, "TZ": "UTC"})
    return r.returncode, (json.loads(r.stdout) if r.returncode == 0 else None)


def main() -> int:
    if harness.missing_bins(harness.MONTAUK):
        note("FAIL: montauk not built"); return 1
    if not cc.FIXTURE.exists():
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            cc.regenerate_fixture(Path(td))

    fails = []
    def expect(label, got, want):
        if got != want:
            fails.append(f"{label}: got {got}, want {want}")

    _, c = query("sched.KICK_ISSUE", "--count")
    kicks = c["rows"][0][0]
    expect("kick count", kicks, 12)

    _, p = query("sched.KICK_ISSUE", "--by", "cpu", "--pair", "RESCHED")
    expect("paired + unanswered", len(p["rows"]) + p["unanswered"], kicks)
    expect("unanswered", p["unanswered"], 2)

    # A clause the closer cannot satisfy: true of the first kick, false of the
    # RESCHED 3us after it. --where must leave the closer alone; --pair-where
    # must apply to it.
    _, ts = query("sched.KICK_ISSUE", "--by", "timestamp_ns", "--count")
    clause = f"timestamp_ns<{min(r[0] for r in ts['rows']) + 1}"
    _, opener = query("sched.KICK_ISSUE", "--where", clause, "--pair", "RESCHED")
    expect("--where on the opener only (paired, unanswered)",
           (len(opener["rows"]), opener["unanswered"]), (1, 0))
    _, closer = query("sched.KICK_ISSUE", "--where", clause, "--pair", "RESCHED",
                      "--pair-where", clause)
    expect("--pair-where on the closer (paired, unanswered)",
           (len(closer["rows"]), closer["unanswered"]), (0, 1))

    rc, _ = query("sched.KICK_ISSUE", "--count", "--pair-where", clause)
    expect("--pair-where without --pair exits", rc, 2)

    for f in fails:
        note(f"FAIL {f}")
    if fails:
        note("GATE FAILED"); return 1
    note("query face agrees with the fixture's known kicks")
    return 0


if __name__ == "__main__":
    sys.exit(main())
