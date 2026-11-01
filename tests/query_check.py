#!/usr/bin/env python3
"""The query face against the fixture's kicks, whose answers are known.

The fixture issues 12 KICK_ISSUE events, 10 answered by a RESCHED 3.0-7.5us
later and 2 never answered. Every check here is arithmetic over those, so a
wrong operator cannot pass by being stable. Its futex waits are known too:
tid 1004's twelve enter and leave, tid 1005's one enters with no deadline,
takes its site and never leaves, and endstate names it parked on its word.
"""
import json
import os
import struct
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

    # An unknown field names the fields the class does have, under --by,
    # --value and --where alike, so a wrong guess costs one try.
    for flag, val in (("--by", "nope"), ("--value", "nope"), ("--where", "nope=1")):
        r = harness.run_text([*harness.ANALYZE, str(cc.FIXTURE), "--select", "sched", flag, val, "--json"])
        expect(f"{flag} unknown field exits", r.returncode, 2)
        expect(f"{flag} unknown field lists the fields",
               "has no field 'nope' (fields: " in r.stderr and "timestamp_ns" in r.stderr, True)

    # The futex wait records: each by its command, its enters and leaves apart,
    # and the one site, keyed to its thread and word.
    _, c = query("futex", "--count")
    expect("futex records", c["rows"][0][0], 25)
    _, c = query("futex.wait_bitset", "--count")
    expect("futex.wait_bitset, the flags masked", c["rows"][0][0], 24)
    _, c = query("futex.wait", "--count")
    expect("futex.wait", c["rows"][0][0], 1)
    _, c = query("futex", "--where", "result=-999", "--by", "tid", "--count")
    expect("enters by thread", c["rows"], [[1004, 12], [1005, 1]])
    _, c = query("futex", "--where", "result!=-999", "--by", "tid", "--count")
    expect("leaves by thread, none for the parked one", c["rows"], [[1004, 12]])
    _, c = query("futexstack", "--by", "tid,uaddr,stack_depth", "--count")
    expect("the parked wait's site", c["rows"], [[1005, 0xF00000, 3, 1]])
    r = harness.run_text([*harness.ANALYZE, str(cc.FIXTURE), "--report", "endstate", "--json"],
                         env={**os.environ, "TZ": "UTC"})
    es = next((x for x in json.loads(r.stdout)["reports"] if x["name"] == "endstate"), {}) if r.returncode == 0 else {}
    on_word = [(t["tid"], t["status"], t.get("op")) for t in es.get("parked", [])
               if t.get("wait") == "futex" and t.get("uaddr") == "0x0000000000f00000"]
    expect("endstate names the thread parked on the futex word", on_word, [(1005, "PARKED", "wait")])

    import tempfile
    with tempfile.TemporaryDirectory() as td:
        check_syscall_capture(Path(td) / "syscalls.mtk", expect)
    with tempfile.TemporaryDirectory() as td:
        check_signal_capture(Path(td), expect)

    for f in fails:
        note(f"FAIL {f}")
    if fails:
        note("GATE FAILED"); return 1
    note("query face agrees with the fixture's known kicks and the written syscall capture")
    return 0


ANCHOR = 1_000_000_000          # the capture's start, CLOCK_MONOTONIC ns
MS = 1_000_000


def ring(type_, pid, ppid, child, comm, filename, ts=None, path=b"", argv=b"", code=0):
    """A lifecycle record: the 96-byte layout older captures wrote when ts is
    None, else today's, with its path and argument tails."""
    head = struct.pack("<IIII16s64s", type_, pid, ppid, child, comm.encode(), filename.encode())
    if ts is None:
        return head
    return head + struct.pack("<QHHi", ts, len(path), len(argv), code) + path + argv


def syscall(nr, pid, tid, args, result, ts, ip, vma, anon, comm, path=b"", path2=b"", lie=0):
    """A syscall record; `lie` overstates its first tail's length."""
    fixed = struct.pack("<IIIi6QqQQQQQBBHHH16s", 24, pid, tid, nr, *args, result, ts, 2000, ip,
                        vma[0], vma[1], 1, anon, len(path) + lie, len(path2), 0, comm.encode())
    return fixed + path + path2


def check_syscall_capture(path, expect):
    """A capture written here, its answers known: the syscall class's records,
    their paths and the mapping each call came from, exec's whole filename and
    argument vector, an older capture's lifecycle and drop records, and a record
    whose text runs past its end."""
    anon, filed = (0x7F0000000000, 0x7F0000001000), (0x400000, 0x401000)
    recs = [
        ring(2, 500, 0, 0, "oldproc", "/usr/bin/old"),
        ring(1, 501, 1, 502, "wine64", "", ts=ANCHOR + 50 * MS),
        ring(2, 501, 1, 0, "wine64", "/x/Proton - Experime", ts=ANCHOR + 100 * MS,
             path=b"/home/u/.steam/Proton - Experimental/files/bin/wine64",
             argv=b"wine64\0C:\\game.exe\0-eac\0"),
        syscall(89, 501, 503, (0x1000, 0x2000, 4096, 0, 0, 0), 15, ANCHOR + 300 * MS, anon[0] + 0x10,
                anon, 1, "wine64", b"/proc/self/exe", b"/tmp/fx/anonsys"),
        syscall(267, 501, 503, (0xFFFFFF9C, 0x1000, 0x2000, 4096, 0, 0), 15, ANCHOR + 400 * MS,
                anon[0] + 0x20, anon, 1, "wine64", b"/proc/self/exe", b"/tmp/fx/anonsys"),
        syscall(82, 501, 504, (0x3000, 0x4000, 0, 0, 0, 0), 0, ANCHOR + 500 * MS, filed[0] + 0x40,
                filed, 0, "wine64", b"/tmp/a", b"/tmp/b"),
        syscall(257, 501, 504, (0xFFFFFF9C, 0x5000, 0, 0, 0, 0), 3, ANCHOR + 1200 * MS, filed[0] + 0x80,
                filed, 0, "wine64", b"/etc/passwd"),
        syscall(257, 501, 504, (0, 0, 0, 0, 0, 0), 3, ANCHOR + 1300 * MS, filed[0], filed, 0, "wine64",
                b"/x", lie=4000),
        ring(3, 501, 1, 0, "wine64", "", ts=ANCHOR + 1500 * MS, code=0x100),
        # A drop record as an older capture wrote it: 24 slots, 7 io records lost.
        struct.pack("<II", 20, 0) + struct.pack("<Q", ANCHOR) + struct.pack("<24Q", *([0] * 5 + [7] + [0] * 18))
        + struct.pack("<QQQ", 0, 0, 0),
    ]
    header = b"MTKTRACE" + struct.pack("<IIQQ32s", 1, 0, ANCHOR, 1_700_000_000_000_000_000, b"fixture")
    path.write_bytes(header + b"".join(struct.pack("<I", len(r)) + r for r in recs))

    def q(*args):
        r = harness.run_text([*harness.ANALYZE, str(path), "--select", *args, "--json"])
        return r.returncode, (json.loads(r.stdout) if r.returncode == 0 else None)

    _, c = q("syscall", "--count")
    expect("syscall records, the one whose text runs past its end skipped", c["rows"], [[4]])
    _, c = q("syscall.readlink,readlinkat", "--by", "path2", "--count")
    expect("readlink's returned target", c["rows"], [["/tmp/fx/anonsys", 2]])
    _, c = q("syscall", "--where", "path~/proc/", "--count")
    expect("--where path~ a substring", c["rows"], [[2]])
    _, c = q("syscall", "--where", "anon=1", "--by", "nr,vma_start", "--count")
    expect("calls from memory no file backs, with their mapping",
           c["rows"], [[89, anon[0], 1], [267, anon[0], 1]])
    _, c = q("syscall.rename", "--by", "path,path2", "--count")
    expect("a rename's two paths", c["rows"], [["/tmp/a", "/tmp/b", 1]])
    _, c = q("syscall", "--between", "250ms:450ms", "--by", "nr", "--count")
    expect("--between in ms from the capture's start", c["rows"], [[89, 1], [267, 1]])
    _, c = q("syscall", "--between", "1.1s:", "--count")
    expect("--between an open end, in s", c["rows"], [[1]])
    _, c = q("syscall", "--between", "256:", "--count")
    expect("--between a bare number is seconds", c["rows"], [])
    rc, _ = q("syscall", "--between", "1x:2", "--count")
    expect("--between refuses a unit it does not know", rc, 2)
    rc, _ = q("syscall", "--where", "nr~8", "--count")
    expect("~ on a number is refused", rc, 2)
    _, c = q("exec", "--by", "pid,path,argv", "--count")
    expect("exec's whole filename and arguments, the older record's empty",
           c["rows"], [[500, "", "", 1],
                       [501, "/home/u/.steam/Proton - Experimental/files/bin/wine64", "wine64 C:\\game.exe -eac", 1]])
    _, c = q("exec", "--by", "comm", "--first")
    expect("--first, t_ns from the capture's start; the older record has no time",
           c["rows"], [["oldproc", -1], ["wine64", 100 * MS]])
    _, c = q("exit", "--by", "pid,exit_code", "--count")
    expect("exit's status", c["rows"], [[501, 0x100, 1]])
    _, c = q("fork", "--by", "pid,child_pid,ts", "--count")
    expect("fork's child and time", c["rows"], [[501, 502, ANCHOR + 50 * MS, 1]])

    d = harness.run_text([*harness.DECODE, str(path)]).stdout
    for want in ("SYSCALL readlink(89)", "path2='/tmp/fx/anonsys'", "in=[0x7f0000000000-0x7f0000001000) anon",
                 "argv='wine64 C:\\game.exe -eac'", "file='/usr/bin/old'", "exit_code=0x100", "child=502"):
        expect(f"decode prints {want}", want in d, True)
    s = harness.run_text([*harness.ANALYZE, str(path), "--report", "summary", "--json"]).stdout
    env = json.loads(s) if s.strip() else {}
    expect("an older capture's drop record still reads", env.get("trace", {}).get("dropped_events"), 7)


# abort() two calls below main, in code that keeps no frame pointer. The
# SIGABRT handler writes what the kernel hands a delivery: The interrupted
# registers and the stack above them, then the process's maps, which is what a
# capture's signal record and <pid>.maps sidecar carry.
ABORT_SITE_C = r"""
#define _GNU_SOURCE
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ucontext.h>
#include <unistd.h>
static int out_fd;
static uint64_t stack_end;
static void on_abort(int sig, siginfo_t *si, void *p) {
  (void)sig; (void)si;
  ucontext_t *uc = p;
  uint64_t r[4] = {(uint64_t)uc->uc_mcontext.gregs[REG_RIP], (uint64_t)uc->uc_mcontext.gregs[REG_RSP],
                   (uint64_t)uc->uc_mcontext.gregs[REG_RBP], 4096};
  if (stack_end - r[1] < r[3]) r[3] = stack_end - r[1];
  write(out_fd, r, sizeof r);
  write(out_fd, (const void *)r[1], r[3]);
  _exit(0);
}
__attribute__((noinline)) void site_f2(void) { abort(); }
__attribute__((noinline)) void site_f1(void) { site_f2(); __asm__ volatile(""); }
int main(int argc, char **argv) {
  if (argc < 3) return 2;
  out_fd = open(argv[1], O_WRONLY | O_CREAT | O_TRUNC, 0644);
  FILE *m = fopen("/proc/self/maps", "r"), *o = fopen(argv[2], "w");
  char line[1024];
  while (fgets(line, sizeof line, m)) {
    if (strstr(line, "[stack]")) sscanf(line, "%*lx-%lx", &stack_end);
    fputs(line, o);
  }
  fclose(m);
  fclose(o);
  struct sigaction sa = {0};
  sa.sa_sigaction = on_abort;
  sa.sa_flags = SA_SIGINFO;
  sigaction(SIGABRT, &sa, 0);
  site_f1();
  return 1;
}
"""


def signal_record(pid, sig, disposition, ts, comm, sender=0, ctx=None, legacy=False):
    """A signal record; `ctx` (ip, sp, bp, stack bytes) is the interrupted user
    context. legacy=True writes the 336-byte layout older captures wrote."""
    head = struct.pack("<IIIIiiiI", 9, pid, pid, 0, sig, sender, 0, 0) + bytes(32 * 8)
    head += struct.pack("<Q16siiQQ", ts, comm.encode(), -1, -1, 0, 0)
    if legacy:
        return head
    ip, sp, bp, stack = ctx or (0, 0, 0, b"")
    return head + struct.pack("<IIQQQ", disposition, len(stack), ip, sp, bp) + stack.ljust(4096, b"\0")


def check_signal_capture(td, expect):
    """The signal class's disposition and sender, an older capture's signal
    record, and a site walked by .eh_frame through code with no frame pointer."""
    import subprocess
    src, prog = td / "site.c", td / "abortsite"
    src.write_text(ABORT_SITE_C)
    cc_run = subprocess.run(["cc", "-O2", "-fomit-frame-pointer", "-fno-optimize-sibling-calls",
                             "-o", str(prog), str(src)], capture_output=True, text=True)
    if cc_run.returncode != 0:
        expect("the abort-site program builds", cc_run.stderr.strip()[:200], "")
        return
    blob, maps = td / "ctx.bin", td / "maps.txt"
    run = subprocess.Popen([str(prog), str(blob), str(maps)])
    run.wait()
    expect("the abort-site program's handler ran", run.returncode, 0)
    raw = blob.read_bytes()
    ip, sp, bp, n = struct.unpack_from("<4Q", raw, 0)
    stack = raw[32:32 + n]
    cap = td / "signals.mtk"
    (td / f"{run.pid}.maps").write_text(maps.read_text())
    recs = [
        signal_record(400, 15, 0, ANCHOR + 10 * MS, "oldsig", legacy=True),
        signal_record(401, 2, 2, ANCHOR + 20 * MS, "ignorer", sender=77),
        signal_record(run.pid, 15, 3, ANCHOR + 30 * MS, "catcher", sender=78),
        signal_record(run.pid, 6, 3, ANCHOR + 40 * MS, "abortsite", ctx=(ip, sp, bp, stack)),
    ]
    header = b"MTKTRACE" + struct.pack("<IIQQ32s", 1, 0, ANCHOR, 1_700_000_000_000_000_000, b"fixture")
    cap.write_bytes(header + b"".join(struct.pack("<I", len(r)) + r for r in recs))

    r = harness.run_text([*harness.ANALYZE, str(cap), "--select", "signal", "--by",
                          "comm,disposition,sender_pid", "--count", "--json"])
    rows = json.loads(r.stdout)["rows"] if r.returncode == 0 else None
    expect("each signal row's disposition and sender, the older record's unknown",
           rows, [["abortsite", 3, 0, 1], ["catcher", 3, 78, 1], ["ignorer", 2, 77, 1], ["oldsig", 0, 0, 1]])
    r = harness.run_text([*harness.ANALYZE, str(cap), "--report", "signals", "--json"])
    rep = next((x for x in json.loads(r.stdout)["reports"] if x["name"] == "signals"), {}) if r.returncode == 0 else {}
    events = {e["comm"]: e for e in rep.get("events", [])}
    expect("dispositions by name", [events.get(c, {}).get("disposition") for c in ("oldsig", "ignorer", "catcher")],
           ["-", "ignored", "caught"])
    ab = events.get("abortsite", {})
    expect("the abort site is walked by .eh_frame", ab.get("site_by"), "eh_frame")
    funcs = harness.elf_functions(prog, {"site_f2", "site_f1", "main"})
    named = harness.site_callers(ab.get("site", ""), prog.name, funcs)
    expect("the site reaches both callers and main, in order", named, ["site_f2", "site_f1", "main"])
    d = harness.run_text([*harness.DECODE, str(cap)]).stdout
    expect("decode prints the disposition", "disposition=caught" in d and "disposition=ignored" in d, True)


if __name__ == "__main__":
    sys.exit(main())
