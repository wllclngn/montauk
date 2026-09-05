#!/usr/bin/env python3
"""The TUI, driven through a real PTY. The last surface with no coverage.

WHY THIS EXISTS, beyond the obvious. An async HelpOverlay was written to get
popen off the render thread, it built, and it was REVERTED -- not because it was
wrong, but because the overlay could not be opened from any harness, so "does
help still display" could not be answered. An unverifiable UI change is not
worth a perf nicety, and the thing that made it unverifiable was the absence of
this file.

The rules that make a TUI test honest rather than flaky:
  - Drive the REAL binary over a PTY. A mock renders whatever it is told to.
  - Assert on a parsed screen buffer, not on the raw byte stream. Escape
    sequences are an implementation detail; what a person sees is not.
  - Give the render loop time after every send. A TUI is not request/response,
    and asserting immediately tests the scheduler rather than the program.
  - Quit through the program's own key, then confirm it actually exited. A test
    that leaks a full-screen process is worse than one that fails.
"""
import os
import sys
import time
from pathlib import Path

try:
    import pexpect
    import pyte
except ImportError as e:
    print(f"[tui] SKIP: {e.name} not installed (pip install pexpect pyte)")
    sys.exit(0)

ROOT = Path(__file__).resolve().parent.parent.parent
MONTAUK = ROOT / "build" / "montauk"
COLS, ROWS = 120, 40

failures, checks = [], 0


def note(msg):
    print(f"[tui] {msg}", flush=True)


def check(cond, what):
    global checks
    checks += 1
    if not cond:
        failures.append(what)
        note(f"  FAIL {what}")


class Screen:
    """A montauk under a PTY, with its output parsed into a screen buffer."""

    def __init__(self, argv=None, env=None):
        self.stream = pyte.Stream()
        self.screen = pyte.Screen(COLS, ROWS)
        self.stream.attach(self.screen)
        # Spawned RELATIVE to the repo root, not by absolute path: pexpect
        # word-splits the command string whenever args is empty, and this
        # checkout lives under a directory whose name contains a space, so the
        # absolute form resolves to ".../SYSTEM" and fails to exec.
        self.child = pexpect.spawn(
            "./build/montauk", argv or [], cwd=str(ROOT), dimensions=(ROWS, COLS),
            env={**os.environ, "TERM": "xterm-256color", **(env or {})},
            timeout=20, encoding="utf-8", codec_errors="replace")

    def pump(self, seconds=1.5):
        """Read whatever the program has emitted and fold it into the buffer."""
        deadline = time.time() + seconds
        while time.time() < deadline:
            try:
                self.stream.feed(self.child.read_nonblocking(65536, timeout=0.2))
            except pexpect.TIMEOUT:
                pass
            except (pexpect.EOF, OSError):
                break
        return self.text()

    def send(self, keys, settle=1.2):
        self.child.send(keys)
        return self.pump(settle)

    def text(self):
        return "\n".join(self.screen.display)

    def close(self):
        try:
            self.child.close(force=True)
        except Exception:
            pass


def test_starts_and_renders():
    """The TUI must paint something recognizable, not a blank or a stack trace."""
    s = Screen()
    body = s.pump(3.0)
    # It renders SOMETHING: a non-trivial amount of non-blank screen.
    painted = sum(1 for line in s.screen.display if line.strip())
    check(painted > 5, f"TUI paints more than 5 non-blank rows (got {painted})")
    low = body.lower()
    check("traceback" not in low and "segmentation" not in low,
          "TUI start is free of a crash message")
    s.close()


def test_quit_key_exits():
    """`q` must exit. A TUI that cannot be quit from its own key is a hang."""
    s = Screen()
    s.pump(2.5)
    s.child.send("q")
    exited = False
    for _ in range(40):
        if not s.child.isalive():
            exited = True
            break
        time.sleep(0.25)
    check(exited, "q exits the TUI within 10s")
    s.close()


def words(text):
    return {w for w in text.split() if len(w) > 3}


# Markers that appear in montauk's man page and nowhere in the live TUI. "NAME"
# is deliberately excluded: it is a process-table column header, and using it
# was how a first version of this check reported help working when it was not.
MAN_MARKERS = ("SYNOPSIS", "DESCRIPTION", "OPTIONS", "EXAMPLES", "montauk(1)")


def probe_help_overlay():
    """DIAGNOSTIC, NOT A GATE -- and the distinction is the point.

    `?` is the help toggle (Renderer.cpp), `q` exits, so input demonstrably
    reaches the app. Yet no man-page text ever appears: toggle() fires and
    nothing renders. That is the blocker that got the async HelpOverlay rewrite
    reverted, and it is reproducible here rather than merely asserted.

    It reports instead of failing because the defect is already on the board;
    gating on it would wedge the suite on a known-open bug. When help is fixed,
    promote this to check() and it becomes the regression test the rewrite
    needed.
    """
    s = Screen()
    s.pump(2.5)
    before = s.text()
    after = s.send("?", settle=4.0)
    found = [m for m in MAN_MARKERS if m in after and m not in before]
    if found:
        note(f"  help overlay RENDERS (markers: {found}) -- promote this to a check()")
    else:
        note("  help overlay does NOT render: '?' toggles, no man-page text "
             "appears. Known open defect, reproduced, not gated.")
    s.close()


def main():
    if not MONTAUK.exists():
        note(f"FAIL: missing {MONTAUK} (build first)")
        return 1
    note(f"driving {MONTAUK.name} over a {COLS}x{ROWS} PTY")

    for fn in (test_starts_and_renders, test_quit_key_exits, probe_help_overlay):
        try:
            fn()
        except Exception as e:
            failures.append(fn.__name__)
            note(f"  FAIL {fn.__name__}: {type(e).__name__}: {e}")

    if failures:
        note(f"GATE FAILED: {len(failures)} of {checks} checks")
        return 1
    note(f"GATE PASSED: {checks} checks -- the TUI starts, renders and exits on "
         "its own key (help overlay probed separately, see above)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
