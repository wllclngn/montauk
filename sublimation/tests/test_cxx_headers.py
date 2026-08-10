#!/usr/bin/env python3
"""C++ consumer gate for sublimation's public headers.

Nothing else in the gate layer compiles the headers as C++ at all, which is how
c23_compat.h shipped an `unreachable()` macro that redefined libstdc++'s
std::unreachable for every C++ consumer. OUROBOROS -- the first outside consumer
-- could not build its main.cpp and carried two `#undef unreachable` lines in
public headers to work around it, while montauk stayed clean purely by include
order.

Two things are checked, and the second is the one that actually bites:

1. NO PUBLIC HEADER DEFINES A BARE LOWERCASE MACRO in C++. These are the
   identifiers that collide with the standard library. A library has no business
   defining them for a language that already has them.
2. THE HEADERS COMPILE AS C++ WITH <utility> SEEN AFTERWARDS, and a call to
   std::unreachable inlines at -O3. Include order is exactly what montauk got
   lucky on: the corruption happens at the DECLARATION and the error surfaces
   somewhere else entirely, so the header must come first for this to reproduce.

Both -std=c++23 and -std=c++20 are built: SUB_HAVE_C23 keys off __STDC_VERSION__
and is false in every C++ mode, so each one takes the same fallback branches.
"""
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INC = ROOT / "src" / "include"

PUBLIC = sorted(p.name for p in INC.glob("sublimation*.h"))

# Bare lowercase identifiers a C++ TU must never find defined as macros. Each is
# either a keyword, a std name, or a C23 library name C++ may grow.
FORBIDDEN = [
    "unreachable", "nullptr", "typeof", "static_assert",
    "ckd_add", "ckd_sub", "ckd_mul",
    "stdc_count_ones_ui", "stdc_leading_zeros_ui",
    "stdc_trailing_zeros_ui", "stdc_has_single_bit_ui",
]


def note(m):
    print(f"[cxx] {m}", flush=True)


def cxx():
    for cc in ("g++", "clang++"):
        if subprocess.run(["which", cc], capture_output=True).returncode == 0:
            return cc
    return None


def macro_probe(cc, std, tmp):
    """Every public header included FIRST, then assert no forbidden macro."""
    src = tmp / "probe.cpp"
    lines = [f'#include "{h}"' for h in PUBLIC]
    for sym in FORBIDDEN:
        lines += [
            f"#ifdef {sym}",
            f'#error "sublimation defines `{sym}` as a macro in C++"',
            "#endif",
        ]
    lines.append("int main() { return 0; }")
    src.write_text("\n".join(lines) + "\n")
    r = subprocess.run([cc, f"-std={std}", "-I", str(INC), "-fsyntax-only", str(src)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        note(f"  {std} macro probe FAILED")
        for ln in (r.stderr or "").splitlines()[:12]:
            note(f"    {ln}")
        return False
    note(f"  {std} macro probe ok ({len(PUBLIC)} headers, {len(FORBIDDEN)} symbols)")
    return True


def inline_probe(cc, std, tmp):
    """Headers FIRST, then <utility>, then actually call std::unreachable at -O3.

    The macro corrupts the declaration silently; the failure is an inlining error
    at the call site. Only a real call at a real optimization level reproduces it.
    """
    src = tmp / "inline.cpp"
    body = [f'#include "{h}"' for h in PUBLIC]
    body += [
        "#include <utility>", "#include <queue>", "#include <ranges>",
        "#include <string>", "#include <vector>",
        "",
        # std::unreachable is C++23; below that the macro probe carries the
        # check and this TU still proves the headers compile against the
        # standard library at -O3 with the same fallback branches taken.
        "#if defined(__cpp_lib_unreachable)",
        "[[noreturn]] static void boom() { std::unreachable(); }",
        "#else",
        "[[noreturn]] static void boom() { __builtin_unreachable(); }",
        "#endif",
        "",
        "int main(int argc, char **) {",
        "    std::vector<int> v{3, 1, 2};",
        "    if (argc > 1000) boom();",
        "    return static_cast<int>(v.size()) - 3;",
        "}",
    ]
    src.write_text("\n".join(body) + "\n")
    out = tmp / f"inline_{std}"
    r = subprocess.run([cc, f"-std={std}", "-O3", "-I", str(INC),
                        str(src), "-o", str(out)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        note(f"  {std} -O3 std::unreachable FAILED")
        for ln in (r.stderr or "").splitlines()[:12]:
            note(f"    {ln}")
        return False
    if subprocess.run([str(out)]).returncode != 0:
        note(f"  {std} binary ran but returned nonzero")
        return False
    note(f"  {std} -O3 std::unreachable ok (compiled, linked, ran)")
    return True


def main():
    cc = cxx()
    if cc is None:
        note("no C++ compiler found; DECLINED")
        return 2
    if not PUBLIC:
        note(f"no public headers found under {INC}; DECLINED")
        return 2

    note(f"compiler {cc}, headers: {', '.join(PUBLIC)}")
    fails = 0
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        for std in ("c++23", "c++20"):
            note(f"public headers as {std}, included BEFORE the standard library")
            fails += not macro_probe(cc, std, tmp)
            fails += not inline_probe(cc, std, tmp)

    note("")
    if fails:
        note(f"GATE FAILED: {fails} check(s) -- a public header is not C++-clean")
        return 1
    note("GATE PASSED: public headers define no bare lowercase macro in C++ and "
         "std::unreachable still inlines at -O3 with the headers included first")
    return 0


if __name__ == "__main__":
    sys.exit(main())
