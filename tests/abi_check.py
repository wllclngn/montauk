#!/usr/bin/env python3
"""The public symbol set must match the declared ABI number.

THIS GATE EXISTS BECAUSE ITS ABSENCE COST A RELEASE. The k-way merge added
fifteen SUB_API symbols and SUBLIMATION_API_VERSION stayed at 3 through build,
test and every existing gate. Nothing in the tree compared the two, so the one
constant whose whole job is naming a header/shared-object mismatch could not
name the mismatch it was created for: a caller compiling against the new header
and linking a pre-4 shared object resolves none of those symbols, and gets raw
undefined-symbol errors instead of the clean version check the library offers.

The rule is mechanical, so it is applied mechanically: freeze the exported set
beside the abi number, and fail when the set moves without the number moving.
Additive or subtractive does not matter -- both change what a linker resolves.

Refreeze with --update AFTER bumping SUBLIMATION_API_VERSION, never before.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HEADERS = sorted((ROOT / "sublimation" / "src" / "include").glob("sublimation*.h"))
FROZEN = ROOT / "tests" / "fixtures" / "sublimation_abi.txt"
VERSION_HEADER = ROOT / "sublimation" / "src" / "include" / "sublimation.h"

# A declaration is SUB_API, then a return type, then the name. Function pointer
# typedefs are not exported symbols and are deliberately not collected.
DECL = re.compile(r"\bSUB_API\b[^;(]*?\b(sublimation_[A-Za-z0-9_]+)\s*\(", re.S)


def declared_abi():
    m = re.search(r"#define\s+SUBLIMATION_API_VERSION\s+(\d+)",
                  VERSION_HEADER.read_text())
    if not m:
        print("[abi] FAIL: cannot parse SUBLIMATION_API_VERSION")
        sys.exit(2)
    return int(m.group(1))


def exported_symbols():
    found = set()
    for h in HEADERS:
        found.update(DECL.findall(h.read_text()))
    return sorted(found)


def render(abi, syms):
    return f"abi {abi}\n" + "".join(f"{s}\n" for s in syms)


def main():
    abi = declared_abi()
    syms = exported_symbols()

    if "--update" in sys.argv:
        FROZEN.parent.mkdir(parents=True, exist_ok=True)
        FROZEN.write_text(render(abi, syms))
        print(f"[abi] froze {len(syms)} symbols at abi {abi}")
        return 0

    if not FROZEN.exists():
        print(f"[abi] FAIL: no frozen set at {FROZEN} -- create it with --update")
        return 1

    text = FROZEN.read_text().splitlines()
    was_abi = int(text[0].split()[1])
    was_syms = [ln for ln in text[1:] if ln.strip()]

    added = [s for s in syms if s not in was_syms]
    removed = [s for s in was_syms if s not in syms]

    if not added and not removed:
        if abi != was_abi:
            print(f"[abi] FAIL: abi moved {was_abi} -> {abi} with an unchanged "
                  "symbol set. Bumping the number without an ABI change makes "
                  "every consumer's version check lie.")
            return 1
        print(f"[abi] GATE PASSED: {len(syms)} public symbols, abi {abi}, unchanged")
        return 0

    if abi == was_abi:
        print(f"[abi] FAIL: the public symbol set changed and "
              f"SUBLIMATION_API_VERSION is still {abi}.")
        for s in added:
            print(f"[abi]   added   {s}")
        for s in removed:
            print(f"[abi]   removed {s}")
        print("[abi] A caller built against this header and linked against an "
              f"abi-{abi} shared object resolves none of the added symbols. "
              "Bump SUBLIMATION_API_VERSION, record why beside the previous "
              "bumps, then rerun with --update.")
        return 1

    print(f"[abi] GATE PASSED: symbol set moved with abi {was_abi} -> {abi} "
          f"({len(added)} added, {len(removed)} removed) -- refreeze with --update")
    return 1 if FROZEN.read_text() != render(abi, syms) else 0


if __name__ == "__main__":
    sys.exit(main())
