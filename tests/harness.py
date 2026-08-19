"""Shared test-harness module for montauk's Python gate/test scripts
(corpus_check.py, parity_check.py, trace_loadtest.py) -- one place for the
logging, subprocess-capture, missing-binary, and diff-printing idioms all
three independently reimplemented, modeled on PANDEMONIUM's
pandemonium_common.py. run.py is deliberately NOT retrofit onto this: it's
already the suite's one orchestrator and doesn't need restructuring.
"""
import difflib
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# One canonical name per build artifact -- previously three different names
# for the sublimation binary alone (SUBLIMATION, SUB, SUBL) across
# corpus_check.py/parity_check.py/trace_loadtest.py.
MONTAUK = ROOT / "build" / "montauk"
# The analyzer and the decoder are MODES of montauk, not binaries. These are
# argv prefixes, not paths: callers splat them (`[*ANALYZE, file, ...]`).
# They were paths to separate executables; when those became symlinks and then
# were deleted, a stale build/montauk_analyze kept resolving -- to montauk
# PROPER, which launched the TUI and hung the gate for twenty minutes instead of
# failing. A missing binary is a loud failure; a binary that means something else
# is a silent one.
ANALYZE = [str(MONTAUK), "--analyze"]
DECODE = [str(MONTAUK), "--decode"]
SUBLIMATION = ROOT / "build" / "sublimation"


def logger(prefix):
    """note = logger("corpus") -> note(msg) prints "[corpus] msg", flushed."""
    def note(msg):
        print(f"[{prefix}] {msg}", flush=True)
    return note


def missing_bins(*bins):
    """The subset of `bins` that don't exist yet (empty if all present).
    A pure check -- callers decide whether to sys.exit or return False, since
    that control-flow choice differs by script (trace_loadtest.py exits
    immediately; corpus_check.py reports and keeps checking other surfaces)."""
    return [b for b in bins if not b.exists()]


def run_text(argv, **kwargs):
    """subprocess.run with capture_output=True, text=True -- the shape every
    script's ad hoc subprocess.run call already used."""
    kwargs.setdefault("capture_output", True)
    kwargs.setdefault("text", True)
    return subprocess.run(argv, **kwargs)


def print_diff(label, want, got, limit=40):
    """Unified diff of two text blobs, capped at `limit` lines -- the same
    divergence-report shape corpus_check.py wrote out twice (once for named
    surfaces, once for the CLI blob)."""
    diff = difflib.unified_diff(
        want.splitlines(keepends=True), got.splitlines(keepends=True),
        fromfile=f"{label}.golden", tofile=f"{label}.actual",
    )
    sys.stdout.writelines(list(diff)[:limit])
