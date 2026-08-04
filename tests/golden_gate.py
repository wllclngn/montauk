#!/usr/bin/env python3
"""Behavioral-golden gate: the checker's own contract, both lanes.

The golden itself cannot be a byte-golden -- it records the freezing
machine's kernel, CPU model and core count, so its bytes differ per host.
What IS fixed is the checker's BEHAVIOR, and that is what this pins:

  freeze      --update writes a file whose every line this build can read
              back, and the round trip PASSES against the capture it froze
  exit codes  0 pass, 1 a frozen fact moved, 2 DECLINED. The three are
              distinct on purpose: "this regressed" and "this was never
              actually checked" are different answers and a caller must be
              able to tell them apart
  refusals    every path that declines rather than answering -- unknown
              completeness without --allow-unknown, an unknown key in the
              file, --performance over a golden with no watched gauge, a
              frozen report or gauge the run did not produce, a golden with
              no workload label, a stray lane flag with no --golden
  keying      a gauge is keyed by (name, labels), not name: the four
              locality_tier_moves rows must survive as four distinct facts

The DECLINED paths carry most of the weight. A gate that answers PASS when
it could not actually compare is the failure mode this whole item exists to
prevent, so each refusal is pinned by exit code and by the phrase that tells
the operator which refusal it was.

Run:  python3 tests/golden_gate.py   (or via tests/run.py, gate layer)
"""
import sys
import tempfile
from pathlib import Path

import harness

ANALYZE = harness.MONTAUK_ANALYZE
TRACE = harness.ROOT / "tests" / "fixtures" / "synthetic.mtk"
# No CPU_IDLE stream, so placement-race reports NO-IDLE-STREAM: the one class
# the freeze refuses to freeze.
TRACE_NOIDLE = harness.ROOT / "tests" / "fixtures" / "synthetic_noidle.mtk"
note = harness.logger("golden")

failures = []


def check(label, argv, want_exit, want_in=(), want_not_in=(), target=None):
    """Run the analyzer and assert exit status plus output phrases."""
    r = harness.run_text([str(ANALYZE), str(target or TRACE)] + argv)
    blob = r.stdout + r.stderr
    if r.returncode != want_exit:
        failures.append(f"{label}: exit {r.returncode}, want {want_exit}")
        note(f"FAIL {label} (exit {r.returncode} != {want_exit})")
        sys.stdout.write(blob)
        return blob
    for phrase in want_in:
        if phrase not in blob:
            failures.append(f"{label}: missing {phrase!r}")
            note(f"FAIL {label} (missing {phrase!r})")
            sys.stdout.write(blob)
            return blob
    for phrase in want_not_in:
        if phrase in blob:
            failures.append(f"{label}: unexpected {phrase!r}")
            note(f"FAIL {label} (unexpected {phrase!r})")
            sys.stdout.write(blob)
            return blob
    note(f"PASS {label}")
    return blob


def main():
    missing = harness.missing_bins(ANALYZE)
    if missing or not TRACE.exists():
        note(f"SKIP -- missing {[str(m) for m in missing] or str(TRACE)}")
        return 0

    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        g = d / "syn.golden"
        perf = d / "perf.golden"

        # FREEZE. --label is mandatory: a golden with no workload identity
        # cannot be matched to a run, so the tool refuses rather than
        # inventing one.
        check("freeze needs --label", ["--golden", str(g), "--update",
                                       "--allow-unknown"], 2,
              ["--update needs --label"])

        # THE FREEZE IS GATED THE SAME WAY THE CHECK IS. It was not: the same
        # capture froze with rc 0 and then declined on check with rc 2, so
        # montauk refused to COMPARE data it would happily CANONIZE. A declined
        # check wastes one run; a poisoned baseline invalidates every future one.
        check("freeze declines unknown completeness, like the check does",
              ["--golden", str(g), "--update", "--label", "synthetic"], 2,
              ["DECLINED", "will not freeze", "UNKNOWN"])
        check("freeze", ["--golden", str(g), "--update", "--label", "synthetic",
                         "--allow-unknown"], 0, ["froze 14 class(es)"])

        # The fixture predates drop accounting, which makes it the exact case
        # the three-state rule exists for: absence of the counter is not
        # evidence of a lossless capture.
        text = g.read_text()
        if "completeness unknown" not in text:
            failures.append("freeze: completeness not recorded as unknown")
            note("FAIL freeze -- completeness not recorded as unknown")
        else:
            note("PASS completeness recorded as unknown, not flattened to whole")

        check("unknown completeness declines", ["--golden", str(g)], 2,
              ["DECLINED", "UNKNOWN"])
        check("round trip", ["--golden", str(g), "--allow-unknown"], 0,
              ["PASS 14 frozen fact(s)"])

        # A CLASS THAT MOVED IS EXIT 1, not 2, and the failure names golden,
        # actual and the accept command on the same screen.
        moved = d / "moved.golden"
        moved.write_text(text.replace("class slice EVEN", "class slice SKEWED"))
        check("class moved", ["--golden", str(moved), "--allow-unknown"], 1,
              ["FUNCTIONAL FAIL", "golden SKEWED", "actual EVEN", "accept:"])

        # A GOLDEN THIS BUILD CANNOT FULLY INTERPRET IS NOT PARTIALLY
        # COMPARED. Silently checking the subset it understands is how a gate
        # comes to pass while checking nothing.
        junk = d / "junk.golden"
        junk.write_text("golden_version 2\nworkload x\nbogus 1\n")
        check("unknown key declines", ["--golden", str(junk)], 2,
              ["unknown key 'bogus'"])

        nolabel = d / "nolabel.golden"
        nolabel.write_text("golden_version 2\nclass slice EVEN\n")
        check("no workload label declines", ["--golden", str(nolabel)], 2,
              ["no workload label"])

        stale = d / "stale.golden"
        stale.write_text(text.replace("golden_version 2", "golden_version 99"))
        check("format version declines", ["--golden", str(stale)], 2,
              ["golden_version 99"])

        absent = d / "absent.golden"
        absent.write_text(text + "class no-such-report SOMETHING\n")
        check("frozen report the run did not produce declines",
              ["--golden", str(absent), "--allow-unknown"], 2,
              ["DECLINED", "no-such-report"])

        # PERFORMANCE LANE. Gauges are opt-in per key, so a golden frozen
        # without --watch has nothing for this lane and says so.
        check("performance over a classes-only golden declines",
              ["--golden", str(g), "--performance", "--allow-unknown"], 2,
              ["DECLINED", "opt-in per key"])
        check("--watch matching nothing declines",
              ["--golden", str(perf), "--update", "--label", "synthetic",
               "--watch", "no_such_metric_family", "--allow-unknown"], 2,
              ["matched no gauge"])
        check("freeze with --watch",
              ["--golden", str(perf), "--update", "--label", "synthetic",
               "--watch", "wake2run", "--watch", "tier_moves",
               "--tolerance", "8", "--floor", "50", "--allow-unknown"], 0,
              ["gauge(s) into"])

        # GAUGE KEYS ARE (NAME, LABELS). montauk_analysis_locality_tier_moves
        # appears four times with different tier= labels; keying by name alone
        # would collapse them into one frozen fact and three silent holes.
        ptext = perf.read_text()
        tiers = [ln for ln in ptext.splitlines()
                 if "locality_tier_moves" in ln]
        if len(tiers) != 4:
            failures.append(f"gauge keying: {len(tiers)} tier_moves rows, want 4")
            note(f"FAIL gauge keying -- {len(tiers)} tier_moves rows, want 4")
        else:
            note("PASS gauge keyed by (name, labels) -- 4 tier_moves rows")

        # No cumulative PMU counter exists yet, so nothing can legitimately
        # carry the deterministic tier. When _total counters land this flips,
        # and it should flip loudly rather than quietly.
        det = [ln for ln in ptext.splitlines() if ln.startswith("gauge deterministic")]
        if det:
            note(f"NOTE {len(det)} deterministic-tier gauge(s) -- cumulative "
                 f"counters have landed, update this gate's expectation")

        check("performance round trip",
              ["--golden", str(perf), "--performance", "--allow-unknown"], 0,
              ["PASS"])

        # THE BAND IS max(percent, floor). Drift inside it is tuning and must
        # not fail; drift outside it must, with the delta and the band both on
        # the failure line.
        drifted = d / "drifted.golden"
        rows = []
        for ln in ptext.splitlines():
            f = ln.split()
            # gauge TIER REDUCTION TOL FLOOR VALUE KEY -- VALUE is field 5,
            # and KEY is everything past it (it carries spaces and quotes).
            if f and f[0] == "gauge" and 'quantile="0.99"' in ln:
                f[5] = str(float(f[5]) * 2.0)
                ln = " ".join(f[:6]) + " " + ln.split(None, 6)[6]
            rows.append(ln)
        drifted.write_text("\n".join(rows) + "\n")
        check("gauge outside the band fails",
              ["--golden", str(drifted), "--performance", "--allow-unknown"], 1,
              ["PERFORMANCE FAIL", "band +-"])

        # BOTH LANES AT ONCE count into one total, so a caller running the
        # pair gets one verdict rather than two half-answers.
        blob = check("both lanes",
                     ["--golden", str(perf), "--functional", "--performance",
                      "--allow-unknown"], 0, ["PASS 34 frozen fact(s)"])

        # A lane flag with no --golden is an error, never a no-op.
        # THE REDUCTION IS PART OF THE FORMAT, not a default the reader has to
        # guess. A single trace's report gauges are single-valued, so every
        # gauge line frozen from one says `point`; a recording's are series and
        # say how they were reduced.
        for ln in ptext.splitlines():
            if not ln.startswith("gauge "):
                continue
            f = ln.split()
            if len(f) < 6 or f[2] != "point":
                failures.append(f"reduction: trace gauge line not 'point': {ln[:60]}")
                note(f"FAIL reduction -- trace gauge line not 'point': {ln[:60]}")
                break
        else:
            note("PASS every trace-frozen gauge records reduction 'point'")

        badred = d / "badred.golden"
        badred.write_text(ptext.replace(" point ", " sideways ", 1))
        check("unknown reduction declines",
              ["--golden", str(badred), "--performance", "--allow-unknown"], 2,
              ["unknown reduction 'sideways'"])

        # RECORDING-DIR LANE. The deterministic tier's gauges are the monitor's
        # montauk_pmu_* families, which live in a recording's .prom scrapes and
        # never in a single trace's reports -- so without this path the tier is
        # unreachable no matter how the checker is written.
        rec = d / "rec"
        rec.mkdir()
        (rec / "montauk_2026-01-01_00.prom").write_text(
            "# HELP montauk_pmu_instructions_total insns\n"
            "# TYPE montauk_pmu_instructions_total counter\n"
            "montauk_pmu_instructions_total 1000\n"
            "# TYPE montauk_probe_gauge gauge\n"
            "montauk_probe_gauge 10\n"
            "montauk_pmu_instructions_total 3000\n"
            "montauk_probe_gauge 30\n")
        recg = d / "rec.golden"
        # A .prom-only recording has no event stream, so the functional lane has
        # nothing to freeze and must say so rather than write an empty pass.
        check("prom-only recording refuses the functional lane",
              ["--golden", str(recg), "--update", "--label", "rec",
               "--allow-unknown"], 2, ["no event stream"], target=rec)
        check("freeze gauges from a recording",
              ["--golden", str(recg), "--update", "--label", "rec",
               "--performance", "--watch", "montauk_", "--allow-unknown"], 0,
              ["froze 0 class(es) and 2 gauge(s)"], target=rec)
        rtext = recg.read_text()
        # A COUNTER reduces by `last` (the run total); an instantaneous gauge by
        # `mean`. Both are recorded per line, so a checker applies the same
        # reduction it froze instead of inferring one.
        want = {"montauk_pmu_instructions_total": ("deterministic", "last", "3000"),
                "montauk_probe_gauge": ("statistical", "mean", "20")}
        seen = {}
        for ln in rtext.splitlines():
            if not ln.startswith("gauge "):
                continue
            f = ln.split()
            seen[f[6]] = (f[1], f[2], f[5])
        if seen != want:
            failures.append(f"recording reduction: {seen} != {want}")
            note(f"FAIL recording reduction -- got {seen}, want {want}")
        else:
            note("PASS counter reduces by last, gauge by mean, both recorded")
        check("recording round trip",
              ["--golden", str(recg), "--performance", "--allow-unknown"], 0,
              ["PASS 2 frozen fact(s)"], target=rec)
        # `RECORDING_DIR --golden --report X` used to fall into single-trace
        # mode and open the DIRECTORY as a trace file, failing with "short read
        # on header" -- a corruption message for a wrong-mode flag.
        check("recording-dir honors --report instead of misreading the dir",
              ["--golden", str(d / "recrep.golden"), "--update", "--label",
               "rec", "--performance", "--watch", "montauk_", "--report",
               "slice", "--allow-unknown"], 0, ["gauge(s) into"],
              want_not_in=["short read"], target=rec)

        check("--reduce validates",
              ["--golden", str(recg), "--update", "--label", "rec",
               "--performance", "--watch", "montauk_", "--reduce", "sideways",
               "--allow-unknown"], 2, ["--reduce takes"], target=rec)

        # --exclude. Without it, excluding ONE report means naming the other
        # 29 by hand -- the friction that gets a gate abandoned.
        exg = d / "excl.golden"
        check("exclude drops reports from the freeze",
              ["--golden", str(exg), "--update", "--label", "t",
               "--exclude", "slice,storm", "--allow-unknown"], 0,
              ["froze 12 class(es)"])
        check("unknown --exclude name is an error",
              ["--golden", str(exg), "--update", "--label", "t",
               "--exclude", "nosuch", "--allow-unknown"], 2,
              ["unknown report 'nosuch' in --exclude"])
        check("--exclude needs --golden", ["--exclude", "slice"], 2,
              ["has no meaning without --golden"])

        # A CAPTURE LIMITATION IS A RECORDED SKIP, NOT A REFUSAL. Freezing used
        # to abort entirely and recommend --report as the escape, which was
        # broken in recording-dir mode -- so a workload with a structurally
        # capture-limited report could not be frozen by any route.
        #
        # The WRITER side of this needs a capture with no PICK/idle stream, and
        # none exists as a fixture (see ROADMAP); what is gated here is the
        # reader and checker, which is where a malformed or mishandled skip line
        # would actually corrupt a verdict.
        skipg = d / "skip.golden"
        skipg.write_text(text + "skipped placement-race NO-IDLE-STREAM\n")
        check("a skipped report is accepted and not compared",
              ["--golden", str(skipg), "--allow-unknown"], 0,
              ["PASS 14 frozen fact(s)"])
        # The fixture's placement-race carries a REAL class, so the golden's
        # skip is stale -- that must read as news to act on, never as a failure
        # of the run under test.
        check("a skip the capture can now answer is a NOTE, not a failure",
              ["--golden", str(skipg), "--allow-unknown"], 0,
              ["NOTE placement-race was skipped at freeze", "re-freeze"])
        badskip = d / "badskip.golden"
        badskip.write_text(text + "skipped placement-race\n")
        check("malformed skip declines",
              ["--golden", str(badskip), "--allow-unknown"], 2,
              ["skipped needs REPORT and TOKEN"])

        # THE WRITER'S REFUSAL, which had no fixture until 2026-08-04. Freezing
        # must not record a capture limitation as a finding: it says so, writes
        # a `skipped` line instead, and still freezes everything else. A real
        # no-sched-detail capture under root confirmed this is the mechanism;
        # the fixture reproduces it synthetically so the gate needs no privileges.
        if TRACE_NOIDLE.exists():
            skipg2 = d / "fromnoidle.golden"
            blob = check("freeze records the capture limitation as skipped",
                         ["--golden", str(skipg2), "--update", "--label", "noidle",
                          "--allow-unknown"], 0,
                         ["capture limitation"], target=TRACE_NOIDLE)
            t2 = skipg2.read_text()
            if "skipped placement-race NO-IDLE-STREAM" not in t2:
                failures.append("writer: no skipped line for placement-race")
                note("FAIL writer skip -- no `skipped placement-race NO-IDLE-STREAM` line")
                sys.stdout.write(t2)
            elif "class placement-race" in t2:
                failures.append("writer: froze placement-race as a class anyway")
                note("FAIL writer skip -- placement-race frozen as a class")
            else:
                note("PASS capture limitation recorded as skipped, not frozen")
            # And the rest of the freeze still happened -- a refusal that took
            # the whole artifact with it is the defect this replaced.
            if sum(1 for ln in t2.splitlines() if ln.startswith("class ")) < 10:
                failures.append("writer: skip aborted the rest of the freeze")
                note("FAIL writer skip -- the other classes did not freeze")
            else:
                note("PASS the skip did not abort the rest of the freeze")
            check("a golden with a skip round-trips",
                  ["--golden", str(skipg2), "--allow-unknown"], 0,
                  ["PASS"], target=TRACE_NOIDLE)
        else:
            note("SKIP writer refusal -- synthetic_noidle.mtk absent")

        check("stray --performance", ["--performance"], 2,
              ["has no meaning without --golden"])
        check("stray --update", ["--update"], 2,
              ["has no meaning without --golden"])
        check("--golden with --json", ["--golden", str(g), "--json"], 2,
              ["alternate outputs"])

    if failures:
        note(f"FAIL golden -- {len(failures)} check(s):")
        for f in failures:
            note(f"  {f}")
        return 1
    note("PASS golden (all checks)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
