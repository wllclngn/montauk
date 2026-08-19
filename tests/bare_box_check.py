#!/usr/bin/env python3
"""One binary, and it must start on a box that has none of its optional libraries.

montauk hard-linked libbpf, liburing and libnvidia-ml. That put all three in
DT_NEEDED, so a machine without them could not exec montauk AT ALL -- not the
TUI, not the analyzer, not the decoder, none of which need every one of them.
That is the entire reason the analyzer and decoder shipped as separate
executables: the split was a workaround for a linking decision.

All three are dlopen'd now, so the split is gone and the three names are one
inode. This gate holds that property down from both ends:

  STATIC  -- none of the three appear in the merged binary's DT_NEEDED.
  DYNAMIC -- with all three genuinely REMOVED from the filesystem, montauk still
             runs, and --decode still decodes.

The dynamic half masks the real libraries with an empty file inside an
unprivileged user+mount namespace, so it tests actual absence rather than
simulating it with an env override. An env-override test would only prove our
own loader takes its error path; it would say nothing about whether ld.so can
still map the binary, which is the property that was broken.
"""
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MONTAUK = ROOT / "build" / "montauk"
OPTIONAL = ("libbpf.so.1", "liburing.so.2", "libnvidia-ml.so.1")


def note(m):
    print(f"[bare] {m}", flush=True)


def find_lib(name):
    for d in ("/usr/lib", "/usr/lib64", "/lib", "/lib64", "/usr/local/lib"):
        p = Path(d) / name
        if p.exists():
            return p
    return None


def check_static() -> bool:
    r = subprocess.run(["ldd", str(MONTAUK)], capture_output=True, text=True)
    bad = [n for n in OPTIONAL if n in r.stdout]
    if bad:
        note(f"FAIL: still hard-linked (DT_NEEDED carries {', '.join(bad)})")
        note("  a box without these cannot exec montauk at all")
        return False
    note(f"PASS static (none of {len(OPTIONAL)} optional libs in DT_NEEDED)")
    return True


def check_dynamic(capture: Path) -> bool:
    present = [p for p in (find_lib(n) for n in OPTIONAL) if p]
    if not present:
        note("SKIP dynamic (none of the optional libs installed here -- "
             "nothing to mask, and the static half already covers the property)")
        return True
    if subprocess.run(["unshare", "-r", "-m", "true"],
                      capture_output=True).returncode != 0:
        note("SKIP dynamic (unprivileged user+mount namespaces unavailable)")
        return True

    with tempfile.TemporaryDirectory() as td:
        empty = Path(td) / "empty.so"
        empty.write_bytes(b"")
        # Runs INSIDE the namespace: mask each library, then exec montauk.
        inner = f"""
import ctypes, subprocess, sys
from pathlib import Path
libs = {[str(p) for p in present]!r}
for lib in libs:
    if subprocess.run(["mount", "--bind", {str(empty)!r}, lib]).returncode != 0:
        print("could not mask " + lib); sys.exit(70)
# PROVE THE MASK BIT. Without this the gate passes when the bind mount silently
# fails to take -- montauk would then be running with the real libraries present
# and the test would report exactly the same PASS. A check that cannot fail is
# not a check, so load each masked library and require that it is now unusable.
for lib in libs:
    try:
        ctypes.CDLL(lib)
    except OSError:
        continue
    print("mask did not take: " + lib + " still loads"); sys.exit(72)
r = subprocess.run([{str(MONTAUK)!r}, "--decode", {str(capture)!r}],
                   capture_output=True, text=True)
sys.stdout.write(r.stdout)
sys.stderr.write(r.stderr[-2000:])
sys.exit(0 if r.returncode == 0 else 71)
"""
        r = subprocess.run(["unshare", "-r", "-m", sys.executable, "-c", inner],
                           capture_output=True, text=True, timeout=180)
        if r.returncode == 70:
            note("SKIP dynamic (bind mount refused inside the namespace)")
            return True
        if r.returncode == 72:
            note("FAIL: the mask did not take, so the run proved nothing:")
            note(f"  {(r.stdout or '').strip().split(chr(10))[-1]}")
            return False
        if r.returncode != 0:
            note(f"FAIL: montauk could not run with {len(present)} libs absent "
                 f"(rc={r.returncode})")
            for line in (r.stderr or "").strip().split("\n")[-6:]:
                note(f"  {line}")
            return False
        if not r.stdout.strip():
            note("FAIL: ran with the libs absent but --decode produced nothing")
            return False
        masked = ", ".join(p.name for p in present)
        note(f"PASS dynamic (--decode produced "
             f"{len(r.stdout.strip().split(chr(10)))} lines with {masked} absent)")
        return True


def main() -> int:
    if not MONTAUK.exists():
        note(f"FAIL: missing {MONTAUK.relative_to(ROOT)} (build first)")
        return 1

    # The old names must NOT come back. montauk_analyze and montauk_trace_decode
    # were separate binaries, then briefly symlinks, and are now gone entirely --
    # the analyzer and decoder are reached as `montauk --analyze` / `--decode`.
    # A stale build/montauk_analyze is worse than a missing one: with argv[0]
    # dispatch removed it resolves to montauk PROPER, which starts the TUI and
    # hangs whatever ran it. That cost this gate a twenty-minute timeout once.
    ok = True
    for name in ("montauk_analyze", "montauk_trace_decode"):
        p = MONTAUK.parent / name
        if p.exists() or p.is_symlink():
            note(f"FAIL: {name} is back in build/ -- it now resolves to the TUI "
                 f"and will hang any caller that runs it")
            ok = False
    if ok:
        note("PASS names (the analyzer and decoder are modes, not binaries)")

    # And both modes must actually answer.
    for flag in ("--analyze", "--decode"):
        r = subprocess.run([str(MONTAUK), flag], capture_output=True, text=True,
                           timeout=60)
        if "usage" not in (r.stdout + r.stderr).lower():
            note(f"FAIL: montauk {flag} did not produce its usage text")
            ok = False

    # THE TWO GUARDS THAT MAKE A HARNESS MISTAKE LOUD. montauk used to ignore an
    # unrecognized argument and start the TUI, so a caller that passed a file
    # where a mode word belonged got an interactive render loop that spins
    # forever -- indistinguishable from a slow run when stdout is captured.
    #
    # The piped case needs BOTH directions tested. Guarding it on `headless`
    # alone rejected --json, the very mode the error message recommends, and
    # nothing caught that until it was tried by hand.
    guard_cases = [
        (["--bogus"], 2, "unrecognized argument"),
        ([], 2, "not a terminal"),
    ]
    for argv, want_rc, want_txt in guard_cases:
        r = subprocess.run([str(MONTAUK), *argv], capture_output=True, text=True,
                           timeout=60)
        blob = r.stdout + r.stderr
        if r.returncode != want_rc or want_txt not in blob:
            note(f"FAIL: montauk {' '.join(argv) or '(no args)'} -> rc={r.returncode}, "
                 f"expected {want_rc} and {want_txt!r}")
            ok = False
    # Every one-shot mode must still work when piped -- they print and exit.
    for argv in (["--json"], ["--anomalies", "3"], ["--regime", "16"],
                 ["--cpu-window", "4"]):
        r = subprocess.run([str(MONTAUK), *argv], capture_output=True, text=True,
                           timeout=120)
        if r.returncode != 0 or not r.stdout.strip():
            note(f"FAIL: montauk {' '.join(argv)} piped -> rc={r.returncode}, "
                 f"{len(r.stdout)} bytes")
            ok = False
    if ok:
        note("PASS guards (unknown arg and bare TUI refuse; 4 piped modes work)")

    ok = check_static() and ok

    # A real capture to decode. corpus_check owns the generator; reuse it rather
    # than growing a second fixture that could drift from the one the goldens
    # are frozen against.
    sys.path.insert(0, str(ROOT / "tests"))
    import corpus_check
    if not corpus_check.FIXTURE.exists():
        with tempfile.TemporaryDirectory() as td:
            corpus_check.regenerate_fixture(Path(td))
    ok = check_dynamic(corpus_check.FIXTURE) and ok

    if not ok:
        note("GATE FAILED")
        return 1
    note("one binary, and it starts bare")
    return 0


if __name__ == "__main__":
    sys.exit(main())
