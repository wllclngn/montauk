#!/usr/bin/env python3
"""install/uninstall symmetry gate.

cmd_uninstall used to carry its own hardcoded copy of what cmd_install placed,
and the two drifted. That is not hypothetical: when this gate was written, a
live /usr/local carried an orphaned bin/montauk-mcp from before the rename to
the retired MCP server, a share/montauk/ the installer never creates, and the
manpage at BOTH
share/man/man1/ and man/man1/ -- all of it surviving an uninstall that reported
success. The same root cause shipped in PANDEMONIUM (Issue #17) and PRISM.

So the property under test is not "uninstall removes these names". It is
SYMMETRY: whatever install placed, uninstall removes, with neither side naming
the set. A test that listed the expected paths would be a third copy of the
list, and would drift with the other two.

Everything runs against a temp prefix with the sudo prefix stripped, so the gate
needs no privileges and never touches a real install.
"""
import importlib.util
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def note(m):
    print(f"[install] {m}", flush=True)


def load_installer():
    spec = importlib.util.spec_from_file_location("montauk_install",
                                                  ROOT / "install.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    # Strip sudo: every placement lands under a temp prefix we already own.
    mod.run_cmd_sudo = lambda cmd, cwd=None: subprocess.run(
        cmd, cwd=cwd, capture_output=True).returncode
    mod.run_cmd_sudo_capture = lambda cmd, cwd=None: (0, "", "")
    return mod


def tree(prefix: Path):
    return {p.relative_to(prefix) for p in prefix.rglob("*") if p.is_file()}


def main() -> int:
    mod = load_installer()
    fails = 0

    with tempfile.TemporaryDirectory() as td:
        prefix = Path(td) / "prefix"

        # Stand in for an install: place a representative set through the same
        # helpers cmd_install uses, recording as it goes.
        placed = []
        for rel in (Path("bin") / "montauk", Path("bin") / "sublimation",
                    Path("bin") / "montauk-profile",
                    Path("lib") / "montauk" / "montauk_profile.py",
                    Path("share") / "man" / "man1" / "montauk.1"):
            dst = prefix / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_text("x")
            placed.append(rel)
        mod.manifest_record(prefix, placed)

        got = mod.manifest_read(prefix)
        if got != placed:
            note(f"FAIL: manifest round-trip lost paths: {got}")
            fails += 1

        # Orphans an older installer left behind. Uninstall must take these too,
        # or an upgrade-in-place never cleans up after its ancestors.
        # Directory-vs-file cannot be inferred from the suffix: bin/montauk-mcp
        # and bin/montauk_analyze are extensionless FILES. Anything under bin/ is
        # a binary; the rest is a directory unless it names a file.
        for rel in mod.LEGACY_TARGETS:
            dst = prefix / rel
            if dst.exists():
                continue
            if rel.parts[0] == "bin" or rel.suffix:
                dst.parent.mkdir(parents=True, exist_ok=True)
                dst.write_text("stale")
            else:
                dst.mkdir(parents=True, exist_ok=True)
                (dst / "logo.svg").write_text("stale")

        class Args:
            pass
        args = Args()
        args.prefix = str(prefix)
        # The kernel-module branch reaches ABSOLUTE paths (/lib/modules, /etc)
        # that no temp prefix can contain, so it is stubbed out entirely rather
        # than merely pointed elsewhere. Stubbing only get_kernel_version is not
        # enough -- /etc/modules-load.d/montauk.conf is hardcoded, and a gate
        # must not touch the machine's real install to test a temp one.
        mod.uninstall_kernel_module = lambda: True
        mod.get_kernel_version = lambda: "0.0.0-none"

        if not mod.cmd_uninstall(args, ROOT):
            note("FAIL: cmd_uninstall reported failure")
            fails += 1

        left = tree(prefix) if prefix.exists() else set()
        if left:
            note("FAIL: uninstall reported success and left files behind:")
            for f in sorted(left):
                note(f"  {f}")
            fails += 1
        else:
            note(f"PASS symmetry ({len(placed)} installed + "
                 f"{len(mod.LEGACY_TARGETS)} legacy, nothing left)")

    # The fallback path: an install with no manifest still gets cleaned.
    with tempfile.TemporaryDirectory() as td:
        prefix = Path(td) / "prefix"
        for rel in (Path("bin") / "montauk", Path("bin") / "sublimation",
                    Path("share") / "man" / "man1" / "montauk.1"):
            dst = prefix / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_text("x")

        class Args:
            pass
        args = Args()
        args.prefix = str(prefix)
        mod.uninstall_kernel_module = lambda: True
        mod.get_kernel_version = lambda: "0.0.0-none"
        mod.cmd_uninstall(args, ROOT)
        left = tree(prefix) if prefix.exists() else set()
        if left:
            note(f"FAIL: manifest-less fallback left {sorted(left)}")
            fails += 1
        else:
            note("PASS fallback (pre-manifest install still cleaned)")

    if fails:
        note(f"GATE FAILED: {fails} check(s)")
        return 1
    note("install/uninstall symmetric")
    return 0


if __name__ == "__main__":
    sys.exit(main())
