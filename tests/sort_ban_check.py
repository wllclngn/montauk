#!/usr/bin/env python3
"""sublimation is the only sort in montauk.

Shipped code orders through sublimation; std sorting, qsort and the kernel's
sort() survive only in tests, where they are the oracle sublimation is checked
against. The rule was written down and nothing enforced it, so six std::sort
calls arrived across five commits in four months, one of them reordering a
vector while the vector parallel to it stayed put.

Comments and string literals are stripped before matching: a comment that
names std::sort to explain why it is not used is not a use.
"""
import re
import sys
from pathlib import Path

import harness

ROOT = harness.ROOT
note = harness.logger("sort-ban")

C_TREES = ["src", "include", "components/kernel", "sublimation/src",
           "sublimation/tools", "sublimation/cli.c"]
C_SUFFIXES = {".c", ".h", ".cpp", ".hpp", ".inc"}
PY_FILES = ["install.py", "components/profile/montauk_profile.py"]

C_BANNED = re.compile(
    r"std::(?:ranges::)?(?:sort|stable_sort|partial_sort|partial_sort_copy|nth_element)\s*\("
    r"|(?<![\w:.>])(?:qsort|qsort_r|sort)\s*\(")
PY_BANNED = re.compile(r"(?<![\w])sorted\s*\(|\.sort\s*\(")

C_STRIP = re.compile(r"//[^\n]*|/\*.*?\*/|\"(?:\\.|[^\"\\\n])*\"|'(?:\\.|[^'\\\n])*'",
                     re.S)
PY_STRIP = re.compile(r"#[^\n]*|\"\"\".*?\"\"\"|'''.*?'''"
                      r"|\"(?:\\.|[^\"\\\n])*\"|'(?:\\.|[^'\\\n])*'", re.S)


def blank(m):
    """Replace a stripped span with its newlines, so line numbers survive."""
    return "\n" * m.group(0).count("\n")


def scan(path, strip, banned):
    code = strip.sub(blank, path.read_text(errors="replace"))
    return [(n, line.strip()) for n, line in enumerate(code.split("\n"), 1)
            if banned.search(line)]


def c_files():
    for t in C_TREES:
        p = ROOT / t
        if p.is_file():
            yield p
        elif p.is_dir():
            yield from (f for f in p.rglob("*") if f.suffix in C_SUFFIXES)


def main() -> int:
    hits = []
    for f in c_files():
        hits += [(f, n, s) for n, s in scan(f, C_STRIP, C_BANNED)]
    for rel in PY_FILES:
        f = ROOT / rel
        if f.exists():
            hits += [(f, n, s) for n, s in scan(f, PY_STRIP, PY_BANNED)]
    for f, n, s in hits:
        note(f"FAIL {f.relative_to(ROOT)}:{n}: {s}")
    note("PASS: sublimation is the only sort in shipped code" if not hits
         else f"FAIL: {len(hits)} non-sublimation sort(s) in shipped code")
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
