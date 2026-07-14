#!/usr/bin/env python3
"""montauk test runner -- one entry point for the whole suite.

Four layers, one command, a clear split:
  unit   -- the C++ montauk_tests aggregate + the C23 montauk_sink_c_test
  gate   -- the Python byte-identical output gate (corpus_check.py): analyzer /
            decoder / sublimation CLI stdout vs frozen goldens
  trace  -- the live BPF trace harness (trace_loadtest.py); needs root, so it is
            skipped (not failed) when not run as root
  mcp    -- montauk-mcp's own `cargo test`; skipped (not failed) if the crate
            isn't built yet (no Cargo.toml)

Usage:
  python3 tests/run.py                 # build, then run every layer (trace skipped w/o root)
  sudo python3 tests/run.py            # include the live trace layer
  python3 tests/run.py --layer gate    # one layer only
  python3 tests/run.py --no-build      # skip the cmake build step (binaries already built)

The `check` CMake target invokes this with --no-build (it builds the deps itself),
so `cmake --build build --target check` and `python3 tests/run.py` are the same suite.
"""
import argparse
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BUILD = ROOT / "build"
TARGETS = ["montauk", "montauk_tests", "montauk_sink_c_test",
           "montauk_json_test", "montauk_stats_test", "montauk_analyze",
           "montauk_trace_decode", "sublimation_cli"]


def run(cmd):
    print(f"  $ {' '.join(str(c) for c in cmd)}", flush=True)
    return subprocess.run(cmd).returncode


def build():
    # A cache configured with MONTAUK_BUILD_TESTS=OFF leaves the test targets
    # undefined. `make <target>` then finds the stale binary from an earlier
    # ON-configure sitting in build/, treats it as an up-to-date plain file and
    # exits 0 without compiling anything, so every layer "passes" against
    # binaries the current sources never touched. Reconfigure to ON first.
    cache = BUILD / "CMakeCache.txt"
    if not cache.exists() or "MONTAUK_BUILD_TESTS:BOOL=ON" not in cache.read_text():
        rc = run(["cmake", "-B", str(BUILD), "-S", str(ROOT),
                  "-DMONTAUK_BUILD_TESTS=ON"])
        if rc != 0:
            print("[run] configure FAILED")
            sys.exit(1)
    rc = run(["cmake", "--build", str(BUILD), "-j", str(os.cpu_count() or 2),
              "--target", *TARGETS])
    if rc != 0:
        print("[run] build FAILED")
        sys.exit(1)


def layer_unit():
    ok = True
    for exe in ("montauk_tests", "montauk_sink_c_test", "montauk_json_test",
                "montauk_stats_test"):
        p = BUILD / exe
        if not p.exists():
            print(f"[run] unit: missing {exe} -- build first (drop --no-build)")
            ok = False
            continue
        ok = (run([str(p)]) == 0) and ok
    return ok


def layer_gate():
    corpus = run([sys.executable, str(ROOT / "tests" / "corpus_check.py")]) == 0
    parity = run([sys.executable, str(ROOT / "tests" / "parity_check.py")]) == 0
    pop = run([sys.executable, str(ROOT / "tests" / "pop_gate.py")]) == 0
    semantic = run([sys.executable, str(ROOT / "tests" / "semantic_check.py")]) == 0
    return corpus and parity and pop and semantic


def layer_perf():
    return run([sys.executable, str(ROOT / "tests" / "perf_gate.py")]) == 0


def layer_trace():
    if os.geteuid() != 0:
        print("[run] trace: SKIP (needs root -- sudo python3 tests/run.py --layer trace)")
        return True  # a skip is not a failure
    return run([sys.executable, str(ROOT / "tests" / "trace_loadtest.py")]) == 0


def layer_mcp():
    mcp_dir = ROOT / "montauk-mcp"
    if not (mcp_dir / "Cargo.toml").exists():
        print("[run] mcp: SKIP (montauk-mcp/Cargo.toml not present)")
        return True  # a skip is not a failure
    print(f"  $ cargo test --release  (in {mcp_dir})")
    return subprocess.run(["cargo", "test", "--release"], cwd=str(mcp_dir)).returncode == 0


LAYERS = {"unit": layer_unit, "gate": layer_gate, "perf": layer_perf,
          "trace": layer_trace, "mcp": layer_mcp}


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--layer", choices=list(LAYERS), help="run only this layer")
    ap.add_argument("--no-build", action="store_true", help="skip the cmake build step")
    args = ap.parse_args()

    if not args.no_build:
        build()
    else:
        # --no-build runs whatever binaries sit in build/. If any source is
        # newer than the oldest test binary, say so loudly: a green suite over
        # stale binaries is the false-gate class this runner already paid for
        # once (see the configure guard above).
        newest_src = 0.0
        for root in (ROOT / "src", ROOT / "sublimation", ROOT / "include",
                     ROOT / "bpf", ROOT / "tests"):
            if not root.exists():
                continue
            for p in root.rglob("*"):
                if p.is_file():
                    newest_src = max(newest_src, p.stat().st_mtime)
        oldest_bin = None
        for t in TARGETS:
            p = BUILD / t
            if p.exists():
                m = p.stat().st_mtime
                oldest_bin = m if oldest_bin is None else min(oldest_bin, m)
        if oldest_bin is not None and newest_src > oldest_bin:
            print("[run] WARN: sources are newer than the built binaries; "
                  "--no-build is gating STALE binaries (drop --no-build)")

    names = [args.layer] if args.layer else list(LAYERS)
    results = {}
    for name in names:
        print(f"[run] layer: {name}")
        results[name] = LAYERS[name]()

    print("[run] summary")
    for name, ok in results.items():
        print(f"  {name:8} {'PASS' if ok else 'FAIL'}")
    return 0 if all(results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
