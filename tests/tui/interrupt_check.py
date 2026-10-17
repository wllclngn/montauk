#!/usr/bin/env python3
"""Ctrl+C hands the terminal back clean.

The first interrupt used to restore the terminal from the signal handler while
the async writer could still be mid-frame, so a frame could land after the
restore and paint the alternate screen's content onto the user's shell. The
writer is now joined before the main thread restores. This drives the real
binary on a pseudo-terminal it owns as its controlling tty, so the ^C the line
discipline turns into SIGINT is a real one, and holds the byte stream to the
order that matters: After the terminal leaves the alternate screen, no frame
follows -- no re-entry and no cursor positioning -- and montauk exits by itself.

This one asserts on the raw stream, not a parsed screen, because the property
IS the order of the bytes. Standard library only.
"""
import os
import pty
import re
import select
import signal
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
MONTAUK = ROOT / "build" / "montauk"
ALT_ON, ALT_OFF = b"\x1b[?1049h", b"\x1b[?1049l"
CURSOR_MOVE = re.compile(rb"\x1b\[\d+;\d+H")


def note(m):
    print(f"[interrupt] {m}", flush=True)


def read_for(fd, seconds):
    out, end = b"", time.time() + seconds
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.1)
        if r:
            try:
                chunk = os.read(fd, 65536)
            except OSError:
                break
            if not chunk:
                break
            out += chunk
    return out


def run_once(stall):
    pid, fd = pty.fork()
    if pid == 0:
        os.environ["TERM"] = "xterm-256color"
        os.execv(str(MONTAUK), [str(MONTAUK)])
    before = read_for(fd, 3.0)
    if stall:
        # Stop draining: The pty fills and the writer blocks inside a frame,
        # which is exactly when an interrupt used to restore underneath it.
        time.sleep(2.0)
    os.write(fd, b"\x03")
    after = read_for(fd, 6.0)
    try:
        wpid, status = os.waitpid(pid, os.WNOHANG)
    except ChildProcessError:
        wpid, status = pid, 0
    exited = wpid == pid
    if not exited:
        # A stall's record is what fixes it: every thread's state and wait
        # channel, read before the kill takes them.
        for row in threads(pid):
            note(row)
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
    os.close(fd)
    return before, after, exited, status


def threads(pid):
    rows = []
    base = Path(f"/proc/{pid}/task")
    try:
        tids = sorted(base.iterdir(), key=lambda p: int(p.name))
    except OSError:
        return rows
    for t in tids:
        try:
            comm = (t / "comm").read_text().strip()
            wchan = (t / "wchan").read_text().strip()
            state = (t / "stat").read_text().split(") ")[1].split()[0]
        except (OSError, IndexError):
            continue
        rows.append(f"  tid {t.name:>8} {state} {comm:<16} {wchan}")
    return rows


def main() -> int:
    if not MONTAUK.exists():
        note(f"FAIL: missing {MONTAUK} (build first)")
        return 1
    fails = 0
    for attempt in range(4):
        stall = attempt % 2 == 1
        before, after, exited, status = run_once(stall)
        label = f"run {attempt + 1}{' (reader stalled)' if stall else ''}"
        if ALT_ON not in before:
            note(f"FAIL {label}: the TUI never entered the alternate screen")
            fails += 1
            continue
        if not exited:
            note(f"FAIL {label}: still running 6 s after ^C")
            fails += 1
            continue
        if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
            note(f"FAIL {label}: exit status {status:#x}, want a clean 0")
            fails += 1
        cut = after.find(ALT_OFF)
        if cut < 0:
            note(f"FAIL {label}: no alternate-screen exit after ^C")
            fails += 1
            continue
        tail = after[cut + len(ALT_OFF):]
        if ALT_ON in tail or CURSOR_MOVE.search(tail):
            note(f"FAIL {label}: a frame followed the restore: {tail[:80]!r}")
            fails += 1
    if fails:
        note(f"GATE FAILED: {fails} problem(s) over 4 runs")
        return 1
    note("4 runs, two with the reader stalled: ^C exits clean, and nothing paints "
         "after the terminal leaves the alternate screen")
    return 0


if __name__ == "__main__":
    sys.exit(main())
