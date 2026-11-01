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
             The spawned workload is traced by the SECOND of three names, the
             first matching nothing: The workers start before attach and sit in
             one sleep for the whole capture, and a program exec'd after attach
             double-frees. Both must be traced, and the abort must carry glibc's
             own text.

  --compare A.bin B.bin
             decode both and diff their per-op event counts. This is the T1
             before/after load-test: the sched_reserve refactor must not add,
             drop or rename an event category, only fold the emit path.

Needs root for the capture mode (BPF). Run:
    sudo python3 tests/trace_loadtest.py
The --compare mode needs no privileges.
"""
import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import harness
from harness import ROOT, MONTAUK, DECODE, SUBLIMATION as SUBL

fails = 0

note = harness.logger("trace-loadtest")


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
    missing = harness.missing_bins(*bins)
    if missing:
        note(f"build first -- missing: {', '.join(str(b) for b in missing)}")
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
    dec = harness.run_text([*DECODE, str(binpath)])
    if dec.returncode != 0:
        note(f"decode failed for {binpath} (rc={dec.returncode}): {dec.stderr.strip()}")
        return None
    rows = [l for l in dec.stdout.splitlines() if l.startswith("[")]  # event lines only
    if not rows:
        return {}
    body = "\n".join(rows) + "\n"
    # Strip the "[   ts]" prefix (split on ']'), then TYPE+subtype = first two tokens.
    after_ts = harness.run_text([str(SUBL), "field", "2", "--delim", "]"], input=body)
    cat = harness.run_text([str(SUBL), "field", "1,2"], input=after_ts.stdout)
    # A CATEGORY IS A SHAPE, NOT AN INSTANCE. Some subtypes carry a run-specific
    # value -- `EXEC pid=44397`, `DROPS total=19115`, `MMAP pid=122654` -- and
    # keeping the value made every one of them a category that could never match
    # across two captures. The T1 comparison this function exists for was then
    # unusable by construction: it reported dozens of appeared/vanished
    # categories on any two runs, including two runs of the SAME build, and the
    # real signal (SCHED WAKEUP and kin, which are stable) was buried in them.
    # Strip the value, keep the key.
    cat = harness.run_text([str(SUBL), "replace", "=[^ ]*", "="], input=cat.stdout)
    tally = harness.run_text([str(SUBL), "tally"], input=cat.stdout)
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
    need_bins(MONTAUK)

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        kids = []
        if args.pattern:
            pattern = args.pattern
            note(f"tracing existing processes matching '{pattern}'")
        else:
            # A reliably-matchable workload: copies of /usr/bin/sleep renamed to a
            # unique token, asleep until the test kills them.
            token = "mtkloadgen"
            binp = tmp / token
            shutil.copy2("/usr/bin/sleep", binp)
            kids = [subprocess.Popen([str(binp), "infinity"]) for _ in range(args.procs)]
            # A double free glibc aborts on, held on its stdin until montauk has
            # found it by its post-exec name.
            src = tmp / "abortgen.c"
            src.write_text("#include <stdlib.h>\n#include <unistd.h>\n"
                           "int main(void) { char c; read(0, &c, 1); void *volatile p = malloc(24);"
                           " free(p); free(p); return 0; }\n")
            cc = subprocess.run(["cc", "-O0", "-w", "-o", str(tmp / "mtkabortgen"), str(src)],
                                capture_output=True, text=True)
            check(cc.returncode == 0, f"abort workload builds ({cc.stderr.strip()[:120]})")
            pattern = f"mtknomatch,{token},mtkabortgen"
            note(f"spawned {len(kids)} '{token}' workers; tracing pattern '{pattern}'")

        # Deliberately point --trace-out at a NON-EXISTENT subdir to exercise the
        # parent-directory auto-create.
        out = tmp / "auto" / "made" / "capture.bin"
        env = dict(os.environ)
        if args.storm:
            env["MONTAUK_SCX_STORM"] = "1"
            note("storm path: MONTAUK_SCX_STORM=1 arms the kick, reenqueue and resched probes")
        proc = subprocess.Popen(
            [str(MONTAUK), "--trace", pattern, "--trace-out", str(out)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env)
        # montauk's log, read as it arrives, so each step below waits on the
        # event it needs rather than on a guess at how long it takes.
        log = []
        reader = threading.Thread(target=lambda: log.extend(proc.stdout), daemon=True)
        reader.start()

        def wait_for(pred):
            end = time.monotonic() + args.stop_timeout
            while time.monotonic() < end:
                if any(pred(l) for l in list(log)):
                    return True
                time.sleep(0.05)
            return False

        if kids:
            wait_for(lambda l: "eBPF trace attached" in l)
            abortgen = subprocess.Popen([str(tmp / "mtkabortgen")], stdin=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL)
            wait_for(lambda l: f"DISCOVERED pid={abortgen.pid} " in l)
            abortgen.communicate(b"x", timeout=args.stop_timeout)
            for k in kids:
                k.terminate()
            for k in kids:
                k.wait()
            for k in kids:
                wait_for(lambda l, pid=k.pid: "SIGNAL" in l and f"pid={pid} " in l)
        else:
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
        reader.join(timeout=args.stop_timeout)
        stderr = "".join(log)

        for k in kids:
            k.terminate()

        check(stopped_first, f"clean stop on a single SIGINT ({stop_dt:.2f}s)")
        # The detach is explicit and timed in stop(): Its line carries the time
        # by link kind and the slowest links, the record a faster teardown
        # will be built against.
        detach = [l for l in stderr.splitlines() if "BPF detach:" in l]
        check(len(detach) == 1, f"one timed detach line ({len(detach)})")
        for l in stderr.splitlines():
            if "BPF detach" in l:
                note(l.strip())
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

        # Drop accounting: a final DROPS snapshot is stamped unconditionally
        # at teardown, and a nominal load must lose nothing. A capture with
        # neither the record nor zero drops is either pre-drop-accounting
        # montauk (a build problem here) or genuinely lossy.
        if out.exists() and out.stat().st_size > 0:
            dec = harness.run_text([*DECODE, str(out)])
            drops = [l for l in dec.stdout.splitlines() if "] DROPS " in l]
            check(bool(drops), f"final DROPS snapshot present ({len(drops)})")
            if drops:
                last = drops[-1]
                check("total=0 " in last,
                      f"zero ring drops under nominal load ({last.strip()})")
        if kids and out.exists() and out.stat().st_size > 0:
            def rows(*q):
                r = harness.run_text([str(MONTAUK), "--analyze", str(out), "--select", *q, "--json"])
                return json.loads(r.stdout)["rows"] if r.returncode == 0 else []
            # Each worker dies on the SIGTERM above, and a traced death is a
            # signal event under its pid.
            killed = {r[0] for r in rows("signal", "--by", "pid,comm", "--count") if r[1] == "mtkloadgen"}
            check(len(killed) == len(kids),
                  f"a second name finds processes blocked since before attach "
                  f"({len(killed)} of {len(kids)} deaths traced)")
            aborts = rows("abort.abort", "--by", "comm,msg", "--count")
            check(any(r[0] == "mtkabortgen" and r[1].strip() for r in aborts),
                  f"a third name finds a process by its post-exec name, and its abort "
                  f"carries the C library's text ({aborts})")
        if "requires eBPF" in stderr or "requires root" in stderr:
            note("note: montauk reported a capability/eBPF problem -- see its stderr above")

        # CSV report for the user: the captured event breakdown, category,count.
        if args.csv is not None and counts:
            emit_csv(args.csv, ["category", "count"], sorted(counts.items()))

        # A failed run keeps its evidence: The capture to analyze and montauk's
        # own log, which names each process it discovered.
        if fails:
            keep = Path("/tmp/montauk/trace_loadtest")
            keep.mkdir(parents=True, exist_ok=True)
            if out.exists():
                shutil.copy2(out, keep / "capture.bin")
            (keep / "montauk.log").write_text(stderr)
            note(f"evidence kept in {keep}")

    note("OK" if fails == 0 else f"{fails} check(s) FAILED")
    return 1 if fails else 0


def run_compare(args):
    need_bins(MONTAUK, SUBL)
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
    # `check(...) and 0 or 1` was the original spelling and it ALWAYS returned 1:
    # a pass makes check() return True, True and 0 is 0, and 0 is falsy, so the
    # `or 1` fires. The comparison reported failure on every successful run --
    # which, combined with the category bug above, made this gate report a
    # regression no matter what it was given.
    return 0 if check(regressions == 0,
                      f"no op category added or dropped between captures "
                      f"({regressions} changed)") else 1


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
    ap.add_argument("--storm", action="store_true",
                    help="capture with MONTAUK_SCX_STORM=1, so the teardown measured "
                         "includes the sched_ext kfunc trampolines")
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
