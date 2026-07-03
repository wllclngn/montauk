#!/usr/bin/env python3
"""montauk --trace load-test harness.

Automates the live BPF trace-capture workflow the synthetic corpus cannot cover
(the corpus feeds a hand-built trace that bypasses the BPF entirely). It spawns a
known workload, captures it with montauk --trace, stops it cleanly, then validates
and decodes the result.

Two modes:

  (default)  one capture against a spawned workload (or --pattern for a live
             process). Asserts: parent dir auto-created, .bin non-empty with the
             MTKTRACE magic, montauk stops within the timeout of a single SIGINT
             (the teardown / Ctrl+C path), decode succeeds. Reports the clean-exit
             EXIT_ABNL stderr count -- 0 means the flood suppression holds.

  --compare A.bin B.bin
             decode both and diff their per-op event counts. This is the T1
             before/after load-test: the sched_reserve refactor must not add,
             drop or rename an event category, only fold the emit path.

Needs root for the capture mode (BPF). Run:
    sudo python3 tests/trace_loadtest.py
The --compare mode needs no privileges.
"""
import argparse
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MONTAUK = ROOT / "build" / "montauk"
DECODE = ROOT / "build" / "montauk_trace_decode"
SUBL = ROOT / "build" / "sublimation"

fails = 0


def note(msg):
    print(f"[trace-loadtest] {msg}", flush=True)


def emit_csv(dest, header, rows):
    """Write a CSV report for the user. dest '-' (or None) -> stdout, else a file."""
    text = ",".join(header) + "\n" + "".join(
        ",".join(str(c) for c in r) + "\n" for r in rows)
    if dest in (None, "-"):
        sys.stdout.write(text)
    else:
        Path(dest).write_text(text)
        note(f"CSV report written -> {dest}")


def check(ok, label):
    global fails
    note(f"{'PASS' if ok else 'FAIL'} {label}")
    if not ok:
        fails += 1
    return ok


def need_bins(*bins):
    missing = [str(b) for b in bins if not b.exists()]
    if missing:
        note(f"build first -- missing: {', '.join(missing)}")
        sys.exit(1)


def op_counts(binpath):
    """Decode a capture and tally its event categories via sublimation.

    The category is `TYPE subtype` (e.g. 'SCHED WAKEUP', 'NTSYNC event_set'), taken
    AFTER stripping the [timestamp] prefix so it is robust to the timestamp width.
    Returns {category: count}.

    Reads the DEFAULT (native) decode, never --csv. Per the project line, CSV is a
    report (output) format only -- it never sits upstream as an event interchange;
    the pipe stays binary/native until sublimation has reduced it. tally is
    sublimation's sort|uniq -c|sort -rn, so each line is `count category`.
    """
    dec = subprocess.run([str(DECODE), str(binpath)],
                         capture_output=True, text=True)
    if dec.returncode != 0:
        note(f"decode failed for {binpath} (rc={dec.returncode}): {dec.stderr.strip()}")
        return None
    rows = [l for l in dec.stdout.splitlines() if l.startswith("[")]  # event lines only
    if not rows:
        return {}
    body = "\n".join(rows) + "\n"
    # Strip the "[   ts]" prefix (split on ']'), then TYPE+subtype = first two tokens.
    after_ts = subprocess.run([str(SUBL), "field", "2", "--delim", "]"],
                              input=body, capture_output=True, text=True)
    cat = subprocess.run([str(SUBL), "field", "1,2"],
                         input=after_ts.stdout, capture_output=True, text=True)
    tally = subprocess.run([str(SUBL), "tally"],
                           input=cat.stdout, capture_output=True, text=True)
    counts = {}
    for line in tally.stdout.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2 and parts[0].isdigit():
            counts[parts[1].strip()] = int(parts[0])
    return counts


def run_capture(args):
    global fails
    if os.geteuid() != 0:
        note("SKIP: capture needs root for BPF -- run: sudo python3 tests/trace_loadtest.py")
        return 0
    need_bins(MONTAUK, DECODE)

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        kids = []
        if args.pattern:
            pattern = args.pattern
            note(f"tracing existing processes matching '{pattern}'")
        else:
            # A reliably-matchable workload: copies of /usr/bin/sleep renamed to a
            # unique token, alive longer than the capture so the BPF enrolls them.
            token = "mtkloadgen"
            binp = tmp / token
            shutil.copy2("/usr/bin/sleep", binp)
            kids = [subprocess.Popen([str(binp), str(args.run + 5)])
                    for _ in range(args.procs)]
            pattern = token
            note(f"spawned {len(kids)} '{token}' workers; tracing pattern '{token}'")

        # Deliberately point --trace-out at a NON-EXISTENT subdir to exercise the
        # parent-directory auto-create.
        out = tmp / "auto" / "made" / "capture.bin"
        proc = subprocess.Popen(
            [str(MONTAUK), "--trace", pattern, "--trace-out", str(out)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

        time.sleep(args.run)
        proc.send_signal(signal.SIGINT)
        t0 = time.monotonic()
        stopped_first = True
        try:
            proc.wait(timeout=args.stop_timeout)
        except subprocess.TimeoutExpired:
            stopped_first = False
            note(f"montauk still alive {args.stop_timeout}s after first SIGINT -- "
                 "escalating with a second (the teardown backstop)")
            proc.send_signal(signal.SIGINT)
            try:
                proc.wait(timeout=args.stop_timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                note("still alive after second SIGINT -- killed")
        stop_dt = time.monotonic() - t0
        stderr = proc.stdout.read() if proc.stdout else ""

        for k in kids:
            k.terminate()

        check(stopped_first, f"clean stop on a single SIGINT ({stop_dt:.2f}s)")
        check(out.exists() and out.stat().st_size > 0,
              f"parent dir auto-created + non-empty capture "
              f"({out.stat().st_size if out.exists() else 0} bytes)")
        if out.exists() and out.stat().st_size >= 8:
            check(out.read_bytes()[:8] == b"MTKTRACE", "MTKTRACE header magic")
        counts = None
        if out.exists() and out.stat().st_size > 0:
            counts = op_counts(out)
            check(counts is not None and sum(counts.values()) > 0,
                  f"decode OK ({sum(counts.values()) if counts else 0} events, "
                  f"{len(counts) if counts else 0} op kinds)")

        flood = [l for l in stderr.splitlines()
                 if "EXIT_ABNL" in l and "sig=(none)" in l]
        check(not flood, f"no clean-exit EXIT_ABNL flood on stderr ({len(flood)} lines)")
        if "requires eBPF" in stderr or "requires root" in stderr:
            note("note: montauk reported a capability/eBPF problem -- see its stderr above")

        # CSV report for the user: the captured event breakdown, category,count.
        if args.csv is not None and counts:
            emit_csv(args.csv, ["category", "count"], sorted(counts.items()))

    note("OK" if fails == 0 else f"{fails} check(s) FAILED")
    return 1 if fails else 0


def run_compare(args):
    need_bins(DECODE, SUBL)
    a_path, b_path = Path(args.compare[0]), Path(args.compare[1])
    for p in (a_path, b_path):
        if not p.exists():
            note(f"missing capture: {p}")
            return 1
    a, b = op_counts(a_path), op_counts(b_path)
    if a is None or b is None:
        return 1
    cats = sorted(set(a) | set(b))

    # CSV is a REPORT format only -- the reduced output, after sublimation has
    # tallied. It never sits upstream of the pipe (the events stay in the .bin).
    # Pure stdout so it redirects cleanly to a .csv; no [trace-loadtest] prefix.
    if args.csv is not None:
        rows = [(c, a.get(c, 0), b.get(c, 0), b.get(c, 0) - a.get(c, 0)) for c in cats]
        emit_csv(args.csv, ["category", "before", "after", "delta"], rows)
        return 0

    note(f"event categories  {a_path.name}  vs  {b_path.name}")
    note(f"  {'category':<22} {'before':>10} {'after':>10} {'delta':>10}")
    regressions = 0
    for c in cats:
        ca, cb = a.get(c, 0), b.get(c, 0)
        flag = ""
        if (ca == 0) != (cb == 0):  # a category appeared or vanished
            flag = "  <-- category appeared/vanished"
            regressions += 1
        note(f"  {c:<22} {ca:>10} {cb:>10} {cb - ca:>+10}{flag}")

    # A pure-dedup refactor keeps every op category present in both runs. Absolute
    # counts differ run-to-run (live timing), so only appear/vanish is a hard fail.
    return check(regressions == 0,
                 f"no op category added or dropped between captures "
                 f"({regressions} changed)") and 0 or 1


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pattern", help="trace existing processes matching PATTERN "
                                       "instead of spawning a workload")
    ap.add_argument("--procs", type=int, default=4,
                    help="spawned workers when no --pattern (default 4)")
    ap.add_argument("--run", type=float, default=4.0,
                    help="capture seconds before SIGINT (default 4)")
    ap.add_argument("--stop-timeout", type=float, default=10.0,
                    help="seconds to allow for a clean stop (default 10)")
    ap.add_argument("--compare", nargs=2, metavar=("A.bin", "B.bin"),
                    help="diff two captures' per-category counts (the T1 before/after test)")
    ap.add_argument("--csv", nargs="?", const="-", default=None, metavar="PATH",
                    help="write a CSV report for the user -- capture: category,count; "
                         "compare: category,before,after,delta. bare --csv or '-' = stdout, "
                         "else a file path. (report format only, never upstream)")
    args = ap.parse_args()

    return run_compare(args) if args.compare else run_capture(args)


if __name__ == "__main__":
    sys.exit(main())
