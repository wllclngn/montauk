"""Shared test-harness module for montauk's Python gate/test scripts
(corpus_check.py, parity_check.py, trace_loadtest.py) -- one place for the
logging, subprocess-capture and missing-binary idioms all three
independently reimplemented, modeled on PANDEMONIUM's
pandemonium_common.py. run.py is deliberately NOT retrofit onto this: it's
already the suite's one orchestrator and doesn't need restructuring.
"""
import struct
import subprocess
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


def elf_functions(path, names):
    """{name: (lo, hi)} in FILE offsets, from the symbol table and the load
    segments, since a site names module+file-offset."""
    b = Path(path).read_bytes()
    phoff, shoff = struct.unpack_from("<QQ", b, 0x20)
    phentsize, phnum, shentsize, shnum = struct.unpack_from("<HHHH", b, 0x36)
    loads = []
    for i in range(phnum):
        p_type, _, p_offset, p_vaddr, _, p_filesz = struct.unpack_from("<IIQQQQ", b, phoff + i * phentsize)
        if p_type == 1:
            loads.append((p_vaddr, p_offset, p_filesz))
    secs = [struct.unpack_from("<IIQQQQIIQQ", b, shoff + i * shentsize) for i in range(shnum)]
    out = {}
    for s in secs:
        if s[1] != 2:            # SHT_SYMTAB
            continue
        strtab = secs[s[6]]
        for o in range(s[4], s[4] + s[5], 24):
            st_name, st_info, _, _, st_value, st_size = struct.unpack_from("<IBBHQQ", b, o)
            name = b[strtab[4] + st_name:b.index(b"\0", strtab[4] + st_name)].decode()
            if name in names and (st_info & 0xf) == 2:
                for v, off, sz in loads:
                    if v <= st_value < v + sz:
                        out[name] = (st_value - v + off, st_value - v + off + st_size)
    return out


def site_callers(site, module, funcs):
    """The functions of `funcs` (from elf_functions) that a signals report's
    site names in `module`, innermost first. Each frame past the first is a
    return address: Past its call, and at most the function's end when the
    call is its last instruction."""
    named = []
    for frame in site.split(" <- "):
        mod, _, off = frame.partition("+0x")
        if mod != module or not off:
            continue
        o = int(off, 16)
        named += [n for n, (lo, hi) in funcs.items() if lo < o <= hi]
    return named
