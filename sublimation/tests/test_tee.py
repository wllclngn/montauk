#!/usr/bin/env python3
"""`sublimation tee` against coreutils `tee`, byte for byte, on stdout and every
file, with the exit status and SIGPIPE behaviour beside them.

Each case runs both ways: stdin and stdout as pipes, which is the zero-copy
path, and stdin from a file, which is the copy loop. Both must write what
coreutils writes. Sizes straddle a pipe buffer so the zero-copy rounds and the
duplicate pipes of the second and later files carry more than one round.
"""
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# The binary under test is named by the caller (tests/run.py passes montauk's
# build/sublimation; a standalone sublimation build passes its own), so the
# test needs nothing outside this directory.
SUB = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else None
GNU = shutil.which("tee", path="/usr/bin:/bin")


def note(m):
    print(f"[tee] {m}", flush=True)


def payload(n):
    return bytes((i * 131 + i // 7) & 0xFF for i in range(n))


def run(tool, args, data, cwd, from_file):
    argv = [str(SUB), "tee", *args] if tool == "sub" else [GNU, *args]
    if from_file:
        src = cwd / "in.bin"
        src.write_bytes(data)
        with open(src, "rb") as f:
            r = subprocess.run(argv, stdin=f, capture_output=True, cwd=cwd)
    else:
        r = subprocess.run(argv, input=data, capture_output=True, cwd=cwd)
    return r.returncode, r.stdout, r.stderr


def case(label, files, data, extra=(), seed=None, from_file=False):
    """Run both tools in fresh directories and compare everything they wrote."""
    got = {}
    for tool in ("sub", "gnu"):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            for name, content in (seed or {}).items():
                (d / name).write_bytes(content)
            for name in files:
                if name.startswith("ro/"):
                    (d / "ro").mkdir(exist_ok=True)
                    os.chmod(d / "ro", 0o500)
            rc, out, err = run(tool, [*extra, *files], data, d, from_file)
            written = {n: (d / n).read_bytes() for n in files if (d / n).is_file()}
            if (d / "ro").exists():
                os.chmod(d / "ro", 0o700)
            got[tool] = (rc, out, written)
            if tool == "sub":
                sub_err = err
    ok = got["sub"] == got["gnu"]
    path = "copy loop" if from_file else "pipes"
    # A message built from an errno nobody set reads "Success". Whatever the
    # exit status, an error line must name what actually happened.
    if b": Success" in sub_err:
        note(f"FAIL {label} ({path}): stderr reports an error as Success: {sub_err[:120]!r}")
        ok = False
    if not ok:
        s, g = got["sub"], got["gnu"]
        note(f"FAIL {label} ({path}): rc {s[0]} vs {g[0]}, stdout {len(s[1])} vs "
             f"{len(g[1])} bytes, files {sorted(s[2])} vs {sorted(g[2])}")
    return ok


def main() -> int:
    if SUB is None or not SUB.is_file() or not GNU:
        note("DECLINED: usage: test_tee.py PATH/TO/sublimation (needs coreutils tee)")
        return 2
    fails = 0
    sizes = {"empty": 0, "one byte": 1, "64 KiB": 65536, "64 KiB + 1": 65537,
             "1 MiB": 1 << 20, "1 MiB + 1": (1 << 20) + 1}
    for from_file in (False, True):
        # Every size and file count with and without -a: -a with no FILE once
        # lost everything past the first pipe buffer, and only this matrix,
        # pipe to pipe, reaches that leg.
        for extra in ((), ("-a",)):
            for label, n in sizes.items():
                data = payload(n)
                tag = f"{label}{' -a' if extra else ''}"
                fails += not case(f"{tag}, no file", [], data, extra, from_file=from_file)
                fails += not case(f"{tag}, one file", ["a"], data, extra, from_file=from_file)
                fails += not case(f"{tag}, three files", ["a", "b", "c"], data, extra, from_file=from_file)
            fails += not case(f"every FILE unopenable{' -a' if extra else ''}", ["ro/x"],
                              payload(1 << 20), extra, from_file=from_file)
        big = payload(1 << 20)
        seed = {"a": b"kept\n", "b": b"also kept\n"}
        fails += not case("-a onto existing content", ["a", "b"], big, ("-a",), seed, from_file)
        fails += not case("truncates without -a", ["a"], b"x\n", (), seed, from_file)
        fails += not case("unwritable among writable", ["a", "ro/x", "b"], big, from_file=from_file)
        fails += not case("'-' is a file name", ["-"], b"dash\n", from_file=from_file)
        fails += not case("'--' ends options", ["--", "-a"], b"x\n", from_file=from_file)
        fails += not case("non-regular FILE", ["a", "/dev/null"], big, from_file=from_file)

    r = subprocess.run([str(SUB), "tee", "-p"], input=b"x", capture_output=True)
    if r.returncode != 2 or b"-a is the only option" not in r.stderr:
        note(f"FAIL -p is refused by name (rc {r.returncode}, {r.stderr[:80]!r})"); fails += 1

    # SIGPIPE keeps its default: the reader leaves after one byte and tee ends
    # the way coreutils tee ends, by the signal.
    for tool, argv in (("sub", [str(SUB), "tee"]), ("gnu", [GNU])):
        p1 = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        p2 = subprocess.Popen(["head", "-c", "1"], stdin=p1.stdout, stdout=subprocess.DEVNULL)
        p1.stdout.close()
        try:
            p1.stdin.write(payload(8 << 20))
        except BrokenPipeError:
            pass
        p1.stdin.close()
        p2.wait()
        rc = p1.wait()
        if tool == "sub":
            sub_rc = rc
        elif rc != sub_rc:
            note(f"FAIL early reader: rc {sub_rc} vs coreutils {rc}"); fails += 1

    if fails:
        note(f"GATE FAILED: {fails} case(s) differ from coreutils tee")
        return 1
    note("every case matches coreutils tee on stdout, files and exit status, "
         "on the zero-copy path and the copy loop")
    return 0


if __name__ == "__main__":
    sys.exit(main())
