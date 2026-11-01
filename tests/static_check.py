#!/usr/bin/env python3
"""static_check -- montauk --static against an independent second implementation.

WHY AN ORACLE AND NOT A FROZEN EXPECTATION. A lexer's failure mode is being
confidently wrong: it returns a plausible guard list that quietly omits a branch,
and a frozen expectation blesses whatever it did on the day it was frozen. Two
implementations of the same algorithm, in two languages, written from the same
description, disagree loudly instead. That is the role std::sort already holds in
sublimation's tests, and it is the same trade here -- the oracle is slower and
never ships.

The corpus is montauk's own source plus whatever the operator passes. Scanning
the tool with the tool is not a stunt: trace_analyze.cpp is 7k lines of deeply
nested C++ with macro-defined report bodies, string literals holding braces and
comments inside expressions, which is every case the scanner has to survive.

    python3 static_check.py            # build tree, montauk's own sources
    python3 static_check.py FILE...    # plus these
"""
import json
import shutil
import subprocess
import tempfile
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MONTAUK = ROOT / "build" / "montauk"
ORACLE = ROOT / "tests" / "guard_tree_oracle.py"
# The extensions each dialect claims, read from the oracle so a DIR here is
# walked exactly as --static walks it.
sys.path.insert(0, str(ROOT / "tests"))
from guard_tree_oracle import DIALECTS  # noqa: E402
DIALECT_EXTS = [d.exts for d in DIALECTS]


def note(msg):
    print(f"[static] {msg}")


def cpp_rows(path):
    """(line, depth, kind, func, guard) from the shipped scanner."""
    r = subprocess.run([str(MONTAUK), "--static", str(path)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        note(f"FAIL montauk --static exited {r.returncode} on {path}")
        note(r.stderr.strip()[:400])
        return None
    out = []
    for line in r.stdout.split("\n"):
        if not line.startswith("G\t"):
            continue
        c = line.split("\t", 6)
        if len(c) != 7:
            note(f"FAIL malformed G record: {line[:120]}")
            return None
        out.append((c[2], c[3], c[4], c[5], c[6]))
    return out


def cpp_declared(path):
    """(kind-tag, line, field, name) for every D and R row the scanner emits."""
    r = subprocess.run([str(MONTAUK), "--static", str(path)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        note(f"FAIL montauk --static exited {r.returncode} on {path}")
        return None
    out = []
    for line in r.stdout.split("\n"):
        if not (line.startswith("D\t") or line.startswith("R\t")):
            continue
        c = line.split("\t", 4)
        if len(c) != 5:
            note(f"FAIL malformed {line[0]} record: {line[:120]}")
            return None
        out.append((c[0], c[2], c[3], c[4]))
    return out


def oracle_declared(path):
    """The same tuple from the Python implementation."""
    r = subprocess.run([sys.executable, str(ORACLE), "--declared", str(path)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        note(f"FAIL oracle --declared exited {r.returncode} on {path}")
        note(r.stderr.strip()[:400])
        return None
    out = []
    for line in r.stdout.split("\n"):
        if not line:
            continue
        f = line.split("\t", 3)
        if len(f) != 4:
            note(f"FAIL malformed oracle declared row: {line[:120]}")
            return None
        out.append(tuple(f))
    return out


def oracle_rows(path):
    """The same tuple from the Python implementation."""
    r = subprocess.run([sys.executable, str(ORACLE), str(path)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        note(f"FAIL oracle exited {r.returncode} on {path}")
        return None
    out = []
    for line in r.stdout.split("\n"):
        if not line:
            continue
        f = line.split("\t", 5)
        if len(f) != 6:
            note(f"FAIL malformed oracle row: {line[:120]}")
            return None
        out.append((f[0], f[3], f[2], f[1], f[4]))   # line, depth, kind, func, guard
    return out


def check_declared(path):
    got, want = cpp_declared(path), oracle_declared(path)
    if got is None or want is None:
        return False
    nd = sum(1 for r in got if r[0] == "D")
    if got == want:
        note(f"PASS {path.name} ({nd} declarations, {len(got) - nd} references)")
        return True
    note(f"FAIL {path.name}: {len(got)} D/R rows vs oracle's {len(want)}")
    gs, ws = set(got), set(want)
    for label, rows in (("montauk only", gs - ws), ("oracle only", ws - gs)):
        for row in list(rows)[:5]:
            note(f"  {label}: {row[0]} line {row[1]} [{row[2]}] {row[3]}")
    return False


def check_refs_known(path):
    """Every R name is a name the same scan declared.

    The reference pass is restricted to known names on purpose: recording every
    identifier would bury the signal in locals and keywords. An R row naming
    something no D row declares means that restriction leaked, and the join
    would then report references to symbols that do not exist."""
    rows = cpp_declared(path)
    if rows is None:
        return False
    declared = {r[3] for r in rows if r[0] == "D"}
    stray = sorted({r[3] for r in rows if r[0] == "R"} - declared)
    if stray:
        note(f"FAIL {path.name}: {len(stray)} referenced name(s) never declared")
        for name in stray[:5]:
            note(f"  stray: {name}")
        return False
    note(f"PASS {path.name} ({len(declared)} names, no stray reference)")
    return True


FIXTURE = """\
enum kind { KIND_NONE = 0, KIND_ONE, KIND_TWO = 1 << 4, };

static int used_once(int x) { return x; }

static int never_called(void) { return KIND_TWO; }

int main(void) {
    /* used_once, KIND_ONE in a comment do not count */
    const char *s = "used_once KIND_ONE";
    return used_once(KIND_ONE) + (s != 0);
}

static long big(void) { return 1'000'000'000 + 0xFF'FF; }

static int after_big(void) { return used_once(KIND_NONE); }
"""

FIXTURE_WANT = [
    ("D", "3", "function", "used_once"),
    ("D", "5", "function", "never_called"),
    ("D", "7", "function", "main"),
    ("D", "13", "function", "big"),
    ("D", "15", "function", "after_big"),
    ("D", "1", "enumerator", "KIND_NONE"),
    ("D", "1", "enumerator", "KIND_ONE"),
    ("D", "1", "enumerator", "KIND_TWO"),
    ("R", "5", "never_called", "KIND_TWO"),
    ("R", "10", "main", "used_once"),
    ("R", "10", "main", "KIND_ONE"),
    ("R", "15", "after_big", "used_once"),
    ("R", "15", "after_big", "KIND_NONE"),
]


# What the reachability join stands on: A prototype is not a use, a macro body
# references from the macro (its parameters name nothing), a conditional's
# words reference from where they sit, a stem pasted into a name names what it
# begins, and a function placed in a section or handed to the runtime is
# reached from file scope by whoever loads it.
REACH_FIXTURE = """\
#ifndef FX_H
#define FX_H
#define SEC(n) __attribute__((section(n), used))
#define KEY(v) to_key(v)   /* to_key in a comment */
int proto_only(int x);
static int to_key(int v) { return v; }
static int dead_helper(void) { return 0; }
static int dead_caller(void) { return dead_helper(); }
SEC("tp/x") int prog(void *ctx) { return KEY(1); }
static void __attribute__((constructor)) boot(void) { }
int main(void) { return proto_only(2); }
int proto_only(int x) { return x; }
#define CAT2(a, b) a ## b
#define TYPED(n) CAT2(n, _u64)
static void sort_u64(void) { }
static void sorter(void) { TYPED(sort)(); }
#define TEST(n) static void test_##n(void)
TEST(one) { }
#endif
"""

REACH_WANT = [
    ("D", "6", "function", "to_key"),
    ("D", "7", "function", "dead_helper"),
    ("D", "8", "function", "dead_caller"),
    ("D", "9", "function", "prog"),
    ("D", "10", "function", "boot"),
    ("D", "11", "function", "main"),
    ("D", "12", "function", "proto_only"),
    ("D", "15", "function", "sort_u64"),
    ("D", "16", "function", "sorter"),
    ("D", "18", "function", "TEST:one"),
    ("D", "2", "macro", "FX_H"),
    ("D", "3", "macro", "SEC"),
    ("D", "4", "macro", "KEY"),
    ("D", "13", "macro", "CAT2"),
    ("D", "14", "macro", "TYPED"),
    ("D", "17", "macro", "TEST"),
    ("R", "8", "dead_caller", "dead_helper"),
    ("R", "9", "<file>", "SEC"),
    ("R", "9", "prog", "KEY"),
    ("R", "11", "main", "proto_only"),
    # A stem passed to a pasting macro names each declaration it begins,
    # a sibling sharing the stem included.
    ("R", "16", "sorter", "TYPED"),
    ("R", "16", "sorter", "sort_u64"),
    ("R", "16", "sorter", "sorter"),
    # A macro that defines a function is used where it defines it.
    ("R", "18", "<file>", "TEST"),
    ("R", "9", "<file>", "prog"),
    ("R", "10", "<file>", "boot"),
    ("R", "1", "<file>", "FX_H"),
    ("R", "4", "KEY", "to_key"),
    ("R", "14", "TYPED", "CAT2"),
]


def check_fixture():
    """A hand-written expectation on a file small enough to verify by eye.

    The oracle catches the two implementations disagreeing; it cannot catch
    them agreeing on the wrong thing. This pins the record shape itself: that a
    declaration is not a reference to itself, that a name inside a comment or a
    string literal is neither, that an enumerator survives an initialiser, and
    that a declared function nothing calls emits a D row with no R row -- which
    is the entire question the pair exists to answer -- and that a digit
    separator does not open a character literal and hide the rest of the file."""
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "fixture.c"
        path.write_text(FIXTURE)
        got = cpp_declared(path)
        if got is None:
            return False
        reach = Path(d) / "reach.c"
        reach.write_text(REACH_FIXTURE)
        got_reach = cpp_declared(reach)
        if got_reach is None:
            return False
        ok = True
        for label_, g, w in (("fixture", got, FIXTURE_WANT), ("reach fixture", got_reach, REACH_WANT)):
            if g == w:
                note(f"PASS {label_} ({len(g)} rows match the hand expectation)")
                continue
            ok = False
            note(f"FAIL {label_}: the artifact does not match what the file declares")
            for label, rows in (("montauk only", [r for r in g if r not in w]),
                                ("expected", [r for r in w if r not in g])):
                for row in rows[:6]:
                    note(f"  {label}: {row[0]} line {row[1]} [{row[2]}] {row[3]}")
        return ok


def cpp_cfg(path):
    """B and E rows from the shipped scanner, the file index dropped."""
    r = subprocess.run([str(MONTAUK), "--static", str(path)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        note(f"FAIL montauk --static exited {r.returncode} on {path}")
        return None
    return ["\t".join([c[0]] + c[2:]) for c in
            (ln.split("\t") for ln in r.stdout.split("\n") if ln[:2] in ("B\t", "E\t"))]


def oracle_cfg(path):
    r = subprocess.run([sys.executable, str(ORACLE), "--cfg", str(path)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        note(f"FAIL oracle --cfg exited {r.returncode} on {path}")
        note(r.stderr.strip()[-400:])
        return None
    return [ln for ln in r.stdout.split("\n") if ln]


def check_cfg(path):
    got, want = cpp_cfg(path), oracle_cfg(path)
    if got is None or want is None:
        return False
    nb = sum(1 for r in got if r[0] == "B")
    if got == want:
        note(f"PASS {path.name} ({nb} blocks, {len(got) - nb} edges)")
        return True
    note(f"FAIL {path.name}: {len(got)} B/E rows vs oracle's {len(want)}")
    for i, (g, w) in enumerate(zip(got, want)):
        if g != w:
            note(f"  first difference at row {i}: montauk {g[:100]!r}")
            note(f"                          oracle  {w[:100]!r}")
            break
    return False


# A hand-checked graph per construct: short-circuit operands, if/else, a for
# with continue and break, a switch with fall-through and default, while,
# do-while, a goto over dead code to a label, a block-opening macro, and in g a
# goto into a loop body, which gives the loop a second entry. The Rust file
# covers nested comments, raw strings, lifetimes, labeled break and continue,
# while let, match arms with return, let-else, loop, unsafe and `?`. cond.rs
# holds the blocks a Rust condition carries, which are not its body: `unsafe`
# alone, negated and as an operand, in a while and a match scrutinee, an `if`
# expression inside a condition, a struct pattern in `while let`, an open range
# before a for body, and a `{` inside a string and a char literal; and the same
# guarded return with its `unsafe` block in the condition and lifted to a `let`.
CFG_FIXTURES = {
    "cfg.c": ('int f(int a, int b) {\n    int x = 0;\n    if (a && b)\n        x = 1;\n    else\n        x = 2;\n    for (int i = 0; i < a; i++) {\n        if (i == 3) continue;\n        if (i == 5) break;\n        x += i;\n    }\n    switch (x) {\n    case 1: x = 4;\n    case 2: return x;\n    default: break;\n    }\n    while (x > 0) { x--; }\n    do { x++; } while (x < 3);\n    goto out;\n    x = 99;\nout:\n    bpf_for(i, 0, 4) { x += i; }\n    return x;\n}\nint g(int a) {\n    if (a) goto in;\n    while (a < 9) {\n        a++;\nin:\n        a += 2;\n    }\n    return a;\n}\n', {
        "f": ("entry exit stmt cond cond stmt stmt stmt cond cond stmt cond stmt stmt stmt "
              "switch case case case cond stmt do stmt cond stmt stmt label macro stmt stmt",
              "0>2 fall, 3>4 true, 2>3 fall, 4>5 true, 3>6 false, 4>6 false, 5>7 fall, "
              "6>7 fall, 7>8 fall, 8>9 true, 9>10 true, 9>11 false, 11>12 true, 11>13 false, "
              "13>14 fall, 10>14 continue, 14>8 back, 8>15 false, 12>15 break, 15>16 case, "
              "16>17 fall, 15>17 case, 15>18 default, 18>19 break, 19>20 true, 20>19 back, "
              "19>21 false, 21>22 fall, 22>23 fall, 23>21 back, 23>24 false, 25>26 fall, "
              "26>27 fall, 27>28 true, 28>27 back, 27>29 false, 17>1 return, 29>1 return, "
              "24>26 goto"),
        "g": ("entry exit cond stmt cond stmt label stmt",
              "0>2 fall, 2>3 true, 2>4 false, 4>5 true, 5>6 fall, 6>4 back, 4>7 false, "
              "7>1 return, 3>6 goto"),
    }),
    "cfg.rs": ('/* outer /* nested */ still comment { */\nimpl Thing<\'a> {\n    pub fn run(&mut self, v: &[u32]) -> Result<(), Error> {\n        let s = r#"{ "not": "code" }"#;\n        let n = self.load()?;\n        \'outer: for x in v.iter() {\n            while let Some(y) = self.next() {\n                if y == \'q\' as u32 { continue \'outer; }\n                if y > *x || n == 0 { break \'outer; }\n            }\n        }\n        let k = match n {\n            0 => return Err(Error::Empty),\n            1 | 2 => 10,\n            _ => { self.bump(); 20 }\n        };\n        let Some(z) = self.opt() else { return Ok(()); };\n        loop {\n            if k > z { break; }\n        }\n        unsafe { self.raw(); }\n        Ok(())\n    }\n}\n', {
        "run": ("entry exit stmt cond cond cond stmt cond cond stmt stmt match arm arm arm "
                "cond stmt loop cond stmt stmt",
                "0>2 fall, 2>3 fall, 3>4 true, 4>5 true, 5>6 true, 7>8 false, 5>7 false, "
                "7>9 true, 8>9 true, 8>4 back, 4>3 back, 6>3 continue, 3>10 false, "
                "9>10 break, 10>11 fall, 11>12 arm, 11>13 arm, 11>14 arm, 13>15 fall, "
                "14>15 fall, 15>16 false, 15>17 true, 17>18 fall, 18>19 true, 18>17 back, "
                "19>20 break, 20>1 fall, 2>1 try, 12>1 return, 16>1 return"),
    }),
    "cond.rs": ('fn shapes(p: *const u8, n: usize) -> u32 {\n    if unsafe { is_null(p) } {\n        return 0;\n    }\n    if !unsafe { ready(p) } {\n        return 1;\n    }\n    if unsafe { peek(p) } == 0 {\n        return 2;\n    }\n    let mut i = 0;\n    while unsafe { *p.add(i) } != 0 {\n        i += 1;\n    }\n    let w = match unsafe { tag(p) } {\n        0 => 3,\n        _ => 4,\n    };\n    if n != if w > 3 { 8 } else { 9 } {\n        return 5;\n    }\n    6\n}\nfn walk(v: &[Slot], s: &str) -> usize {\n    let mut cur = 0;\n    while let Slot::Vacant { next, .. } = v[cur] {\n        cur = next;\n    }\n    for i in 0.. {\n        if i == cur { break; }\n    }\n    if s == "{" || s.starts_with(\'{\') {\n        return 1;\n    }\n    cur\n}\nfn inline(p: *const u8) -> u32 {\n    if unsafe { is_null(p) } {\n        return 0;\n    }\n    1\n}\nfn lifted(p: *const u8) -> u32 {\n    let c = unsafe { is_null(p) };\n    if c {\n        return 0;\n    }\n    1\n}\n', {
        "shapes": ("entry exit cond stmt cond stmt cond stmt stmt cond stmt stmt match arm arm "
                   "cond stmt stmt",
                   "0>2 fall, 2>3 true, 2>4 false, 4>5 true, 4>6 false, 6>7 true, 6>8 false, "
                   "8>9 fall, 9>10 true, 10>9 back, 9>11 false, 11>12 fall, 12>13 arm, 12>14 arm, "
                   "13>15 fall, 14>15 fall, 15>16 true, 15>17 false, 17>1 fall, 3>1 return, "
                   "5>1 return, 7>1 return, 16>1 return"),
        "walk": ("entry exit stmt cond stmt cond cond stmt cond cond stmt stmt",
                 "0>2 fall, 2>3 fall, 3>4 true, 4>3 back, 3>5 false, 5>6 true, 6>7 true, "
                 "6>5 back, 8>9 false, 5>8 false, 7>8 break, 8>10 true, 9>10 true, 9>11 false, "
                 "11>1 fall, 10>1 return"),
        "inline": ("entry exit cond stmt stmt",
                   "0>2 fall, 2>3 true, 2>4 false, 4>1 fall, 3>1 return"),
        "lifted": ("entry exit stmt cond stmt stmt",
                   "0>2 fall, 2>3 fall, 3>4 true, 3>5 false, 5>1 fall, 4>1 return"),
    }),
}

# Pairs of functions in CFG_FIXTURES that are one graph once the first's `let`
# statement block is contracted: A condition's block lifted out of it changes
# nothing the graph says.
ALIKE = [("cond.rs", "lifted", "inline")]


# Python's graph, checked by hand: A short-circuit `and`, an elif chain, a for
# with continue, break and else, while, try/except/finally with a raise, match
# arms, and with.
PY_CFG_FIXTURES = {
    "cfg.py": ("def f(a, b, xs):\n    x = 0\n    if a and b:\n        x = 1\n    elif a:\n        x = 2\n    else:\n        x = 3\n    for i in xs:\n        if i == 3:\n            continue\n        if i == 5:\n            break\n        x += i\n    else:\n        x = -1\n    while x > 0:\n        x -= 1\n    try:\n        x = int(b)\n    except ValueError as e:\n        raise\n    finally:\n        x += 1\n    match x:\n        case 1:\n            return 1\n        case _:\n            pass\n    with open(b) as fh:\n        x = len(fh.read())\n    return x\n", {
        "f": ("entry exit stmt cond cond stmt cond stmt stmt cond cond stmt cond stmt stmt stmt "
              "cond stmt try stmt handler finally match arm arm stmt",
              "0>2 fall, 3>4 true, 2>3 fall, 4>5 true, 3>6 false, 4>6 false, 6>7 true, 6>8 false, "
              "5>9 fall, 7>9 fall, 8>9 fall, 9>10 true, 10>11 true, 10>12 false, 12>13 true, "
              "12>14 false, 14>9 back, 11>9 continue, 9>15 false, 13>15 break, 15>16 fall, "
              "16>17 true, 17>16 back, 16>18 false, 18>19 fall, 18>20 handler, 19>21 fall, "
              "20>21 return, 18>21 unwind, 21>22 fall, 22>23 arm, 22>24 arm, 24>25 fall, "
              "21>1 return, 23>1 return, 25>1 return"),
    }),
    # A finally is reached from every way out of its try: Its body's return, an
    # uncaught exception (the unwind edge) and each fall, and only a fall carries
    # on past it. So cleanup() after a `return True` is live and tail() is dead;
    # a try's else is reached from its body's fall alone.
    "finally.py": ("def work():\n    try:\n        return True\n    finally:\n        cleanup()\n"
                   "    tail()\n\n\ndef falls(x):\n    try:\n        x = 1\n    except ValueError:\n"
                   "        x = 2\n    else:\n        x = 3\n    finally:\n        cleanup()\n"
                   "    return x\n", {
        "work": ("entry exit try stmt finally stmt",
                 "0>2 fall, 2>3 fall, 3>4 return, 2>4 unwind, 5>1 fall, 4>1 return"),
        "falls": ("entry exit try stmt handler stmt finally stmt",
                  "0>2 fall, 2>3 fall, 2>4 handler, 3>5 fall, 5>6 fall, 4>6 fall, 2>6 unwind, "
                  "6>7 fall, 6>1 return, 7>1 return"),
    }),
}


def py_oracle(path):
    """Python's guards and declarations from CPython itself: The structure from
    ast, every keyword's line and every header's text from tokenize, over the
    source with its comments blanked. None when the file does not parse."""
    import ast
    import io
    import tokenize
    src = path.read_text()
    try:
        tree = ast.parse(src)
        toks = list(tokenize.generate_tokens(io.StringIO(src).readline))
    except (SyntaxError, tokenize.TokenError, ValueError):
        return None
    lines = src.split("\n")
    for tk in toks:
        if tk.type == tokenize.COMMENT:
            r, c0 = tk.start
            _, c1 = tk.end
            ln = lines[r - 1]
            lines[r - 1] = ln[:c0] + " " * (c1 - c0) + ln[c1:]
    def char_col(line, byte_col):
        return len(src.split("\n")[line - 1].encode()[:byte_col].decode(errors="replace"))
    def norm(s):
        return " ".join(s.split())
    def slice_(a, b):
        (l0, c0), (l1, c1) = a, b
        if l0 == l1:
            return lines[l0 - 1][c0:c1]
        return "\n".join([lines[l0 - 1][c0:]] + lines[l0:l1 - 1] + [lines[l1 - 1][:c1]])
    by_pos = {tk.start: k for k, tk in enumerate(toks)}
    def header(kw_line, kw_col):
        """The text between a keyword and its header's colon."""
        k = by_pos[(kw_line, kw_col)]
        depth = 0
        for j in range(k + 1, len(toks)):
            tk = toks[j]
            if tk.type == tokenize.OP:
                if tk.string in "([{":
                    depth += 1
                elif tk.string in ")]}":
                    depth -= 1
                elif tk.string == ":" and depth == 0:
                    return norm(slice_(toks[k].end, tk.start))
        return ""
    def kw_after(pos, words):
        for tk in toks:
            if tk.start > pos and tk.type == tokenize.NAME and tk.string in words:
                return tk.start
        return None
    def kw_before(pos, word):
        best = None
        for tk in toks:
            if tk.start >= pos:
                break
            if tk.type == tokenize.NAME and tk.string == word:
                best = tk.start
        return best
    guards = set()
    def walk(stmts, depth, func):
        for s in stmts:
            if isinstance(s, ast.If):
                at = (s.lineno, char_col(s.lineno, s.col_offset))
                text = header(*at)
                guards.add((s.lineno, depth, "if", func, text))
                walk(s.body, depth + 1, func)
                if s.orelse:
                    end = (s.body[-1].end_lineno, char_col(s.body[-1].end_lineno, s.body[-1].end_col_offset))
                    e = kw_after(end, ("else", "elif"))
                    guards.add((e[0], depth, "else", func, f"!({text})"))
                    walk(s.orelse, depth + 1, func)
            elif isinstance(s, ast.While):
                guards.add((s.lineno, depth, "while", func, header(s.lineno, char_col(s.lineno, s.col_offset))))
                walk(s.body, depth + 1, func)
                walk(s.orelse, depth, func)
            elif isinstance(s, (ast.For, ast.AsyncFor)):
                at = (s.lineno, char_col(s.lineno, s.col_offset))
                if isinstance(s, ast.AsyncFor):
                    at = kw_after(at, ("for",))
                guards.add((s.lineno, depth, "for", func, header(*at)))
                walk(s.body, depth + 1, func)
                walk(s.orelse, depth, func)
            elif isinstance(s, ast.Match):
                guards.add((s.lineno, depth, "match", func, header(s.lineno, char_col(s.lineno, s.col_offset))))
                for case in s.cases:
                    p = case.pattern
                    at = kw_before((p.lineno, char_col(p.lineno, p.col_offset)), "case")
                    guards.add((at[0], depth + 1, "arm", func, header(*at)))
                    walk(case.body, depth + 2, func)
            elif isinstance(s, (ast.Try, getattr(ast, "TryStar", ast.Try))):
                walk(s.body, depth, func)
                for h in s.handlers:
                    walk(h.body, depth, func)
                walk(s.orelse, depth, func)
                walk(s.finalbody, depth, func)
            elif isinstance(s, (ast.With, ast.AsyncWith)):
                walk(s.body, depth, func)
            elif isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                walk(s.body, depth, func)
    decls = set()
    def container(stmts):
        for s in stmts:
            if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef)):
                decls.add((s.lineno, "function", s.name))
                walk(s.body, 0, s.name)
            elif isinstance(s, ast.ClassDef):
                container(s.body)
            elif isinstance(s, (ast.If, ast.While, ast.For, ast.AsyncFor, ast.Try, ast.With,
                                ast.AsyncWith, ast.Match, getattr(ast, "TryStar", ast.Try))):
                walk([s], 0, "<file>")
    container(tree.body)
    return guards, decls


def check_python(paths):
    """Python's guards and declarations, scanner against CPython, file by file."""
    ok, files, nguards = True, 0, 0
    for path in paths:
        want = py_oracle(path)
        if want is None:
            continue
        r = subprocess.run([str(MONTAUK), "--static", str(path)], capture_output=True, text=True)
        guards, decls = set(), set()
        for ln in r.stdout.split("\n"):
            c = ln.split("\t")
            if c[0] == "G":
                guards.add((int(c[2]), int(c[3]), c[4], c[5], c[6]))
            elif c[0] == "D":
                decls.add((int(c[2]), c[3], c[4]))
        files += 1
        nguards += len(want[0])
        for label, got, exp in (("guard", guards, want[0]), ("declaration", decls, want[1])):
            if got == exp:
                continue
            ok = False
            for x in sorted(exp - got)[:3]:
                note(f"FAIL python {path.name}: CPython has {label} {x}, the scanner does not")
            for x in sorted(got - exp)[:3]:
                note(f"FAIL python {path.name}: the scanner has {label} {x}, CPython does not")
    # The runtime calls a dunder method itself, so the scan roots it at file
    # scope; an ordinary method nothing names stays unreached.
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "dunder.py"
        path.write_text("class C:\n    def __init__(self):\n        self.x = 1\n\n"
                        "    def unused(self):\n        return 2\n")
        r = subprocess.run([str(MONTAUK), "--static", str(path)], capture_output=True, text=True)
        refs = {tuple(ln.split("\t")[2:]) for ln in r.stdout.split("\n") if ln.startswith("R\t")}
        if refs != {("2", "<file>", "__init__")}:
            ok = False
            note(f"FAIL python dunder: R rows {sorted(refs)}, want __init__ rooted at line 2 alone")
    # A call inside an f-string's field is a reference, in the spec's nested
    # field, beside a conversion or a debug `=`, and across a triple-quoted
    # field's newline; a plain string's braces name nothing.
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "fstring.py"
        path.write_text('def stamp():\n    return "t"\n\n\ndef width():\n    return 3\n\n\n'
                        'def main():\n    print(f"{stamp()} x {1:>{width()}} {stamp()!r} {stamp()=}")\n'
                        '    if f"{stamp():3}" == "x":\n        return f"""{\n            width()}"""\n'
                        '    return "{width()}"\n')
        r = subprocess.run([str(MONTAUK), "--static", str(path)], capture_output=True, text=True)
        refs = sorted(tuple(ln.split("\t")[2:]) for ln in r.stdout.split("\n") if ln.startswith("R\t"))
        want_refs = sorted([("10", "main", "stamp")] * 3 + [("10", "main", "width"),
                           ("11", "main", "stamp"), ("13", "main", "width")])
        if refs != want_refs:
            ok = False
            note(f"FAIL python f-string: R rows {refs}, want {want_refs}")
    with tempfile.TemporaryDirectory() as d:
        for name, (src, want) in PY_CFG_FIXTURES.items():
            path = Path(d) / name
            path.write_text(src)
            rows = cpp_cfg(path)
            blocks, edges = {}, {}
            for row in rows or []:
                c = row.split("\t")
                if c[0] == "B":
                    blocks.setdefault(c[2], []).append(c[4])
                else:
                    edges.setdefault(c[2], []).append(f"{c[3]}>{c[4]} {c[5]}")
            for fn, (kinds, edge_list) in want.items():
                if " ".join(blocks.get(fn, [])) != kinds or ", ".join(edges.get(fn, [])) != edge_list:
                    note(f"FAIL {name} {fn}: the graph is not the hand-checked one")
                    note(f"  blocks {' '.join(blocks.get(fn, []))}")
                    note(f"  edges  {', '.join(edges.get(fn, []))}")
                    ok = False
    if ok:
        note(f"PASS python: {nguards} guards and every declaration over {files} file(s) match "
             f"CPython's ast and tokenize, f-string fields are references, and the cfg "
             f"fixtures match their hand-checked graphs")
    return ok


def check_cfg_fixtures():
    """The oracle catches two implementations disagreeing, never both agreeing
    on the wrong graph. These are small enough to have been checked by hand."""
    ok = True
    scanned = {}
    with tempfile.TemporaryDirectory() as d:
        for name, (src, want) in CFG_FIXTURES.items():
            path = Path(d) / name
            path.write_text(src)
            rows = cpp_cfg(path)
            if rows is None:
                return False
            blocks, edges = {}, {}
            for r in rows:
                c = r.split("\t")
                if c[0] == "B":
                    blocks.setdefault(c[2], []).append(c[4])
                else:
                    edges.setdefault(c[2], []).append(f"{c[3]}>{c[4]} {c[5]}")
            scanned[name] = {fn: (" ".join(blocks.get(fn, [])), ", ".join(edges.get(fn, [])))
                             for fn in want}
            for fn, (kinds, edge_list) in want.items():
                if " ".join(blocks.get(fn, [])) != kinds or ", ".join(edges.get(fn, [])) != edge_list:
                    note(f"FAIL {name} {fn}: the graph is not the hand-checked one")
                    note(f"  blocks {' '.join(blocks.get(fn, []))}")
                    note(f"  edges  {', '.join(edges.get(fn, []))}")
                    ok = False
            if ok:
                note(f"PASS {name} ({len(want)} function(s) match the hand-checked graph)")
    for name, lifted, inline in ALIKE:
        kinds_l, edges_l = scanned[name][lifted]
        kinds_i, edges_i = scanned[name][inline]
        k = kinds_l.split()
        # Contract block 2, the `let`, into entry: Its edges go, later blocks renumber.
        renum = lambda v: v if v < 2 else v - 1
        contracted = []
        for e in edges_l.split(", "):
            span, kind = e.split(" ")
            a, b = map(int, span.split(">"))
            if a == 2 or (a, b) == (0, 2):
                if a == 2:
                    contracted.append(f"0>{renum(b)} {kind}")
                continue
            contracted.append(f"{renum(a)}>{renum(b)} {kind}")
        same = (" ".join(k[:2] + k[3:]) == kinds_i
                and sorted(contracted) == sorted(edges_i.split(", ")))
        note(f"{'PASS' if same else 'FAIL'} {name}: {lifted} is {inline}'s graph with its `let` lifted out")
        ok = ok and same
    return ok


def independent_cfg(blocks, edges):
    """Reachability, cyclomatic number, dominators and loop kinds by a second
    route: dominator SETS by iterative intersection, where the analyzer walks an
    idom tree. The DFS order is the artifact's edge order, as the analyzer's is,
    because which edges retreat depends on it."""
    n = len(blocks)
    succ = [[] for _ in range(n)]
    pred = [[] for _ in range(n)]
    for f, t in edges:
        if f < n and t < n:
            succ[f].append(t)
            pred[t].append(f)
    state = [0] * n
    order, retreat = [], []
    stack = [[0, 0]]
    state[0] = 1
    while stack:
        v, k = stack[-1]
        if k < len(succ[v]):
            stack[-1][1] += 1
            w = succ[v][k]
            if state[w] == 0:
                state[w] = 1
                stack.append([w, 0])
            elif state[w] == 1:
                retreat.append((v, w))
        else:
            state[v] = 2
            order.append(v)
            stack.pop()
    reach = [v for v in range(n) if state[v]]
    full = 0
    for v in reach:
        full |= 1 << v
    dom = {v: full for v in reach}
    dom[0] = 1
    changed = True
    while changed:
        changed = False
        for v in reversed(order):
            if v == 0:
                continue
            acc = full
            for p in pred[v]:
                if state[p]:
                    acc &= dom[p]
            acc |= 1 << v
            if acc != dom[v]:
                dom[v] = acc
                changed = True
    natural = {w for u, w in retreat if dom[u] >> w & 1}
    irreducible = sum(1 for u, w in retreat if not dom[u] >> w & 1)
    er = sum(1 for f, t in edges if f < n and t < n and state[f] and state[t])
    return {
        "cyclomatic": max(1, er - len(reach) + 2),
        "dom_depth": max(bin(dom[v]).count("1") - 1 for v in reach),
        "natural": len(natural),
        "irreducible": irreducible,
        "dead": [v for v in range(n) if not state[v] and blocks[v] != "exit"],
    }


# WHAT A RUNNER OR A TABLE ENTERS. Each file below is scanned alone and its
# declarations report read: the functions a test runner calls are reached from
# file scope, with what only they call; a callback a macro declares is reached
# from the table that names it; and code nothing enters stays unreached.
ENTRY_FIXTURES = {
    "test_mod.py": ("import unittest\n\n\ndef helper():\n    return 1\n\n\n"
                    "class Base(unittest.TestCase):\n    def setUp(self):\n        self.x = helper()\n\n"
                    "    def tool(self):\n        return 3\n\n\n"
                    "class Derived(Base):\n    def test_one(self):\n        assert self.x == 1\n\n\n"
                    "class TestPlain:\n    def test_two(self):\n        assert helper()\n\n"
                    "    def other(self):\n        return 0\n\n\n"
                    "class Other:\n    def test_not(self):\n        return 0\n\n\n"
                    "def test_module():\n    def inner():\n        return 1\n    assert inner()\n\n\n"
                    "def setUpModule():\n    pass\n\n\ndef unused():\n    pass\n",
                    ["tool", "other", "test_not", "unused"]),
    "plain.py": ("import unittest\n\n\nclass T(unittest.TestCase):\n    def test_a(self):\n        pass\n\n\n"
                 "def test_free():\n    pass\n",
                 ["test_free"]),
    "lib.rs": ("fn helper() -> u32 { 1 }\n\nfn dead() -> u32 { 2 }\n\n#[cfg(test)]\nmod tests {\n"
               "    use super::*;\n    #[test]\n    fn a() { assert_eq!(helper(), 1); }\n"
               "    #[test] fn b() { helper(); }\n    #[tokio::test]\n    #[ignore]\n    async fn c() {}\n"
               "    #[inline] fn d() {}\n}\n",
               ["dead", "d"]),
    "ops.bpf.c": ("void helper(void) {}\nvoid dead(void) {}\n"
                  "int BPF_STRUCT_OPS(sched_tick, int cpu) { helper(); return 0; }\n"
                  "int BPF_STRUCT_OPS(sched_unnamed, int cpu) { return 0; }\n"
                  "SEC(\".struct_ops\")\nstruct sched_ext_ops ops = {\n    .tick = (void *)sched_tick,\n};\n",
                  ["dead", "BPF_STRUCT_OPS:sched_unnamed"]),
}


def check_entries():
    """Each entry fixture's unreached list, exactly."""
    ok = True
    with tempfile.TemporaryDirectory() as d:
        for name, (src, want) in ENTRY_FIXTURES.items():
            path, art = Path(d) / name, Path(d) / (name + ".guards")
            path.write_text(src)
            r = subprocess.run([str(MONTAUK), "--static", str(path), "-o", str(art)], capture_output=True, text=True)
            a = subprocess.run([str(MONTAUK), "--analyze", str(art), "--json"], capture_output=True, text=True)
            if r.returncode != 0 or a.returncode != 0:
                note(f"FAIL entries {name}: static rc {r.returncode}, analyze rc {a.returncode}")
                ok = False
                continue
            rep = next(x for x in json.loads(a.stdout)["reports"] if x["name"] == "declarations")
            got = [x["name"] for x in rep.get("unreached", [])]
            if got != want:
                note(f"FAIL entries {name}: unreached {got}, want {want}")
                ok = False
    if ok:
        note(f"PASS entries: test runners' functions and a struct_ops table's callbacks are entry "
             f"points over {len(ENTRY_FIXTURES)} fixtures, and what nothing enters stays unreached")
    return ok


def check_cfg_report(art, env):
    """The cfg report's arithmetic against independent_cfg over the same rows,
    and its unreachable listing against the blocks that recomputation leaves
    unreached, every one."""
    fns, rows, files = {}, {}, {}
    for ln in art.read_text().split("\n"):
        c = ln.split("\t")
        if c[0] == "B":
            fns.setdefault((c[1], c[2]), ([], []))[0].append(c[5])
            rows.setdefault((c[1], c[2]), []).append((c[3], int(c[6]), c[5]))
        elif c[0] == "E":
            fns.setdefault((c[1], c[2]), ([], []))[1].append((int(c[4]), int(c[5])))
        elif ln.startswith("file "):
            _, idx, _, path = ln.split(" ", 3)
            files[idx] = path
    if not fns:
        return []
    stats = [independent_cfg(b, e) for b, e in fns.values()]
    dead_rows = sorted((files.get(k[0], ""), *rows[k][v]) for k, s in zip(fns, stats) for v in s["dead"])
    for s in stats:
        s["dead"] = len(s["dead"])
    want = {
        "montauk_static_cfg_functions": len(fns),
        "montauk_static_cfg_blocks": sum(len(b) for b, _ in fns.values()),
        "montauk_static_cfg_edges": sum(len(e) for _, e in fns.values()),
        "montauk_static_cfg_unreachable_blocks": sum(s["dead"] for s in stats),
        "montauk_static_cfg_natural_loops": sum(s["natural"] for s in stats),
        "montauk_static_cfg_irreducible_edges": sum(s["irreducible"] for s in stats),
        "montauk_static_cfg_dominator_depth_max": max(s["dom_depth"] for s in stats),
    }
    rep = [x for x in env.get("reports", []) if x["name"] == "cfg"]
    if not rep:
        return ["the analyzer emits no cfg report"]
    got = {g["name"]: g["value"] for g in rep[0]["gauges"] if "labels" not in g}
    got_max = [g["value"] for g in rep[0]["gauges"]
               if g["name"] == "montauk_static_cfg_cyclomatic" and g.get("labels") == 'quantile="max"']
    problems = [f"{k} {got.get(k)} vs {v} recomputed" for k, v in want.items() if got.get(k) != v]
    listed = sorted((u["file"], u["function"], u["line"], u["kind"]) for u in rep[0].get("unreachable", []))
    if listed != dead_rows:
        problems.append(f"unreachable lists {len(listed)} block(s) vs {len(dead_rows)} recomputed"
                        f" (first difference {next((p for p in zip(listed, dead_rows) if p[0] != p[1]), None)})")
    if got_max != [max(s["cyclomatic"] for s in stats)]:
        problems.append(f"cyclomatic max {got_max} vs {max(s['cyclomatic'] for s in stats)}")
    return problems


SEAM_FIXTURE = """int two_phases(int *a, int n) {
    int s = 0;
    for (int i = 0; i < n; i++) {
        if (a[i] > 3) s += a[i];
        else if (a[i] < -3) s -= a[i];
        else if (a[i] == 0) continue;
        else s++;
    }
    s = s * 2;
    for (int j = 0; j < n; j++) {
        if (a[j] & 1) s ^= j;
        else if (a[j] & 2) s += j;
        else if (a[j] & 4) s -= j;
        else s--;
    }
    return s;
}
"""


def independent_seam(nblocks, edges):
    """The least-conductance sweep cut over the Fiedler vector, written apart from
    the analyzer: The reachable blocks, the graph made symmetric, a cyclic Jacobi
    eigendecomposition of its Laplacian, and the sweep."""
    succ = {}
    for a, b in edges:
        succ.setdefault(a, []).append(b)
    seen, order = {0}, [0]
    for v in order:
        for w in succ.get(v, []):
            if w not in seen:
                seen.add(w); order.append(w)
    idx = {v: i for i, v in enumerate(order)}
    n = len(order)
    W = [[0.0] * n for _ in range(n)]
    for a, b in edges:
        if a in idx and b in idx and a != b:
            W[idx[a]][idx[b]] += 1; W[idx[b]][idx[a]] += 1
    deg = [sum(r) for r in W]
    A = [[(deg[i] if i == j else 0.0) - W[i][j] for j in range(n)] for i in range(n)]
    V = [[1.0 if i == j else 0.0 for j in range(n)] for i in range(n)]
    for _ in range(100):
        off = sum(A[i][j] ** 2 for i in range(n) for j in range(n) if i != j)
        if off < 1e-22:
            break
        for p in range(n):
            for q in range(p + 1, n):
                if abs(A[p][q]) < 1e-300:
                    continue
                th = (A[q][q] - A[p][p]) / (2 * A[p][q])
                tt = (1 if th >= 0 else -1) / (abs(th) + (th * th + 1) ** 0.5)
                c = 1 / (tt * tt + 1) ** 0.5; s = tt * c
                for k in range(n):
                    akp, akq = A[k][p], A[k][q]
                    A[k][p], A[k][q] = c * akp - s * akq, s * akp + c * akq
                for k in range(n):
                    apk, aqk = A[p][k], A[q][k]
                    A[p][k], A[q][k] = c * apk - s * aqk, s * apk + c * aqk
                for k in range(n):
                    vkp, vkq = V[k][p], V[k][q]
                    V[k][p], V[k][q] = c * vkp - s * vkq, s * vkp + c * vkq
    ev = sorted(range(n), key=lambda i: A[i][i])
    f = [V[i][ev[1]] for i in range(n)]
    sweep = sorted(range(n), key=lambda i: f[i])
    vol_all, inside, cut, vol, best, best_k = sum(deg), set(), 0.0, 0.0, 2.0, 0
    for k in range(n - 1):
        v = sweep[k]
        cut += deg[v] - 2 * sum(W[v][u] for u in inside)
        vol += deg[v]; inside.add(v)
        smaller = min(vol, vol_all - vol)
        if smaller > 0 and cut / smaller < best:
            best, best_k = cut / smaller, k + 1
    return best


def check_seam():
    """The seam of a function made of two loops joined by one statement: Cut
    between the loops, with the analyzer's conductance equal to one computed
    apart from it."""
    with tempfile.TemporaryDirectory() as d:
        src, art = Path(d) / "two.c", Path(d) / "two.guards"
        src.write_text(SEAM_FIXTURE)
        subprocess.run([str(MONTAUK), "--static", str(src), "-o", str(art)], capture_output=True, check=True)
        r = subprocess.run([str(MONTAUK), "--analyze", str(art), "--json"], capture_output=True, text=True)
        env = json.loads(r.stdout)
        cfg = [x for x in env.get("reports", []) if x["name"] == "cfg"]
        seams = cfg[0].get("weakest_seams", []) if cfg else []
        blocks, edges = 0, []
        for ln in art.read_text().split("\n"):
            c = ln.split("\t")
            if c[0] == "B":
                blocks += 1
            elif c[0] == "E":
                edges.append((int(c[4]), int(c[5])))
    if len(seams) != 1 or seams[0]["function"] != "two_phases":
        note(f"FAIL seam: want one seam for two_phases, got {seams}")
        return False
    s = seams[0]
    want = independent_seam(blocks, edges)
    sides = [(x["first_line"], x["last_line"]) for x in s["sides"]]
    problems = []
    if abs(s["conductance"] - want) > 1e-9:
        problems.append(f"conductance {s['conductance']} vs {want} recomputed")
    if s["cut_edges"] != 1:
        problems.append(f"cut edges {s['cut_edges']}, want 1 (the statement between the loops)")
    if not (sides[0][1] < 9 <= sides[1][0]):
        problems.append(f"sides {sides} do not divide at the statement between the loops")
    for m in problems:
        note(f"FAIL seam: {m}")
    if not problems:
        note("PASS seam: two loops joined by one statement divide between them, at the "
             "conductance an independent sweep finds")
    return not problems


BPF_OPS = {0x10: "==", 0x20: ">", 0x30: ">=", 0x40: "&", 0x50: "!=", 0x60: "s>", 0x70: "s>=",
           0xa0: "<", 0xb0: "<=", 0xc0: "s<", 0xd0: "s<="}
A64_CC = ["eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"]


def cstr_of(img, sec, o):
    b = img[sec["off"] + o: sec["off"] + sec["size"]]
    return b[:b.index(0)].decode() if 0 in b else b.decode()


def elf_read(path):
    """Sections, symbols and relocations of an ELF64 object, by struct."""
    import struct
    img = path.read_bytes()
    e_type, = struct.unpack_from("<H", img, 0x10)
    shoff, = struct.unpack_from("<Q", img, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", img, 0x3a)
    secs = []
    for k in range(shnum):
        nm, ty, fl, addr, off, size, link, info, _al, _ent = struct.unpack_from("<IIQQQQIIQQ", img, shoff + k * shentsize)
        secs.append(dict(nm=nm, type=ty, flags=fl, addr=addr, off=off, size=size, link=link, info=info))
    def cstr(sec, o):
        b = img[sec["off"] + o: sec["off"] + sec["size"]]
        return b[:b.index(0)].decode() if 0 in b else b.decode()
    for s in secs:
        s["name"] = cstr(secs[shstrndx], s["nm"])
    syms = []
    for want in (2, 11):  # SHT_SYMTAB, then SHT_DYNSYM
        for s in secs:
            if s["type"] == want:
                for o in range(0, s["size"] - 23, 24):
                    nm, info, _o, shndx, value, size = struct.unpack_from("<IBBHQQ", img, s["off"] + o)
                    syms.append(dict(name=cstr(secs[s["link"]], nm), type=info & 0xf, bind=info >> 4,
                                     shndx=shndx, value=value, size=size))
        if syms:
            break
    reloc = {}
    for s in secs:
        if s["type"] in (4, 9):  # SHT_RELA, SHT_REL
            ent = 24 if s["type"] == 4 else 16
            for o in range(0, s["size"] - ent + 1, ent):
                off, rinfo = struct.unpack_from("<QQ", img, s["off"] + o)
                addend = struct.unpack_from("<q", img, s["off"] + o + 16)[0] if ent == 24 else 0
                if (rinfo >> 32) < len(syms):
                    reloc[(s["info"], off)] = (syms[rinfo >> 32], rinfo & 0xffffffff, addend)
    return img, e_type, secs, syms, reloc


def oracle_object_rows(path, machine):
    """The object lane's rows, decoded apart from the scanner: Each machine says
    what an instruction does to control flow, and one emitter splits blocks at
    targets and after jumps, as the lane's rule states."""
    import struct
    img, e_type, secs, syms, reloc = elf_read(path)
    entry, = struct.unpack_from("<Q", img, 0x18)
    exports = set()
    for s in secs:
        if s["type"] == 11:  # SHT_DYNSYM: a linked object's exports
            for o in range(0, s["size"] - 23, 24):
                nm, info, _o, shndx, _v, _sz = struct.unpack_from("<IBBHQQ", img, s["off"] + o)
                if info & 0xf == 2 and shndx != 0:
                    exports.add(cstr_of(img, secs[s["link"]], nm))
    unit = 8 if machine == "bpf" else 4
    exec_sec = lambda k: k < len(secs) and secs[k]["type"] == 1 and secs[k]["flags"] & 4
    fns = []
    for y in syms:
        if y["type"] == 2 and exec_sec(y["shndx"]):
            s = secs[y["shndx"]]
            off = y["value"] - s["addr"] if e_type != 1 else y["value"]
            n, start = s["size"] // unit, off // unit
            if 0 <= start < n and not any(f[0] == y["shndx"] and f[1] == start for f in fns):
                # Entered from outside: global or weak in a relocatable object,
                # exported or the entry point in a linked one.
                entered = (y["name"] in exports or y["value"] == entry) if e_type != 1 \
                    else y["bind"] in (1, 2)
                fns.append([y["shndx"], start, min(start + y["size"] // unit if y["size"] else n, n), y["name"],
                            entered])
    fns.sort(key=lambda f: (f[0], f[1]))
    for a, b in zip(fns, fns[1:]):
        if a[0] == b[0] and a[2] > b[1]:
            a[2] = b[1]
    entered = {f[3] for f in fns if f[4]}
    fns = [f[:4] for f in fns]
    fn_name = lambda sec, slot: next((f[3] for f in fns if f[0] == sec and f[1] == slot), None)
    is_map = lambda shndx: shndx < len(secs) and secs[shndx]["name"] in (".maps", "maps")

    def sext(v, bits):
        return v - (1 << bits) if v & (1 << (bits - 1)) else v

    def decode(sec, slot):
        # (kind, width, target, text, ref)
        s, r = secs[sec], reloc.get((sec, slot * unit))
        if machine == "bpf":
            code, regs, off, imm = struct.unpack_from("<BBhi", img, s["off"] + slot * 8)
            cls, opc = code & 7, code & 0xf0
            jmp = cls in (5, 6)
            if code == 0x18:
                return ("straight", 2, -1, "", r[0]["name"] if r and is_map(r[0]["shndx"]) else "")
            if code == 0x95:
                return ("return", 1, -1, "", "")
            if code == 0x85:
                ref = ""
                if regs >> 4 == 1:
                    if r and r[0]["type"] == 2:
                        ref = r[0]["name"]
                    elif r and r[0]["type"] == 3:
                        ref = fn_name(r[0]["shndx"], imm + 1) or ""
                    else:
                        ref = fn_name(sec, slot + 1 + imm) or ""
                return ("call", 1, -1, "", ref)
            if jmp and opc == 0:
                return ("goto", 1, slot + 1 + (imm if cls == 6 else off), "", "")
            if jmp and (opc in BPF_OPS or opc == 0xe0):
                if opc == 0xe0:
                    text = "may_goto"
                else:
                    w = "w" if cls == 6 else "r"
                    rhs = f"{w}{regs >> 4}" if code & 8 else str(imm)
                    text = f"{w}{regs & 15} {BPF_OPS[opc]} {rhs}"
                return ("cond", 1, slot + 1 + off, text, "")
            return ("straight", 1, -1, "", "")
        w, = struct.unpack_from("<I", img, s["off"] + slot * 4)
        def name_of(target):
            if r and r[1] in (282, 283):  # JUMP26, CALL26
                if r[0]["type"] != 3:
                    return r[0]["name"]
                return fn_name(r[0]["shndx"], r[2] // 4) or ""
            return fn_name(sec, target) or ""
        reg = "x" if w >> 31 else "w"
        if w & 0xfc000000 == 0x14000000:
            target = -1 if r else slot + sext(w & 0x3ffffff, 26)
            return ("goto", 1, target, "", name_of(target))
        if w & 0xfc000000 == 0x94000000:
            return ("call", 1, -1, "", name_of(slot + sext(w & 0x3ffffff, 26)))
        if w & 0xff000010 == 0x54000000:
            return ("cond", 1, slot + sext((w >> 5) & 0x7ffff, 19), A64_CC[w & 15], "")
        if w & 0x7e000000 == 0x34000000:
            return ("cond", 1, slot + sext((w >> 5) & 0x7ffff, 19),
                    f"{reg}{w & 31} {'!=' if w >> 24 & 1 else '=='} 0", "")
        if w & 0x7e000000 == 0x36000000:
            bit = ((w >> 31) << 5) | ((w >> 19) & 31)
            return ("cond", 1, slot + sext((w >> 5) & 0x3fff, 14),
                    f"bit {bit} of {reg}{w & 31} {'!=' if w >> 24 & 1 else '=='} 0", "")
        if w & 0xfffffc1f == 0xd65f0000 or w & 0xfffffbff == 0xd65f0bff:
            return ("return", 1, -1, "", "")
        if w & 0xfffffc1f == 0xd61f0000:
            return ("indirect", 1, -1, "", "")
        return ("straight", 1, -1, "", "")

    def data_ranges(sec, nslots):
        marks = sorted((y["value"] // unit, y["name"][1]) for y in syms
                       if y["shndx"] == sec and len(y["name"]) >= 2 and y["name"][0] == "$"
                       and y["name"][1] in "dx" and (len(y["name"]) == 2 or y["name"][2] == "."))
        return [(m[0], marks[k + 1][0] if k + 1 < len(marks) else nslots)
                for k, m in enumerate(marks) if m[1] == "d"]

    def reloc_function(r, addend):
        # The function a relocation points at: its symbol when that is one, or
        # the function starting where it lands in an executable section.
        y = r[0]
        if y["type"] == 2:
            return y["name"]
        if y["type"] != 3 or y["shndx"] >= len(secs) or not secs[y["shndx"]]["flags"] & 4:
            return ""
        if addend < 0 or addend % unit:
            return ""
        return fn_name(y["shndx"], addend // unit) or ""

    rows = set()
    for sec, start, end, name in fns:
        rows.add(("D", str(start), "function", name))
        if name in entered:
            rows.add(("R", str(start), "<file>", name))
    if machine == "bpf":
        for y in syms:
            if y["type"] == 1 and is_map(y["shndx"]):
                rows.add(("D", "0", "map", y["name"]))
    for fk, (sec, start, end, name) in enumerate(fns):
        data = data_ranges(sec, secs[sec]["size"] // unit)
        ops, pc = {}, start
        while pc < end:
            op = ("straight", 1, -1, "", "") if any(a <= pc < b for a, b in data) else decode(sec, pc)
            ops[pc] = op
            pc += op[1]
        inside = lambda t: start <= t < end and t in ops
        leaders = {start}
        for pc, (kind, width, target, _t, _r) in ops.items():
            nxt = pc + width
            if kind in ("cond", "goto"):
                if inside(target):
                    leaders.add(target)
                if nxt < end:
                    leaders.add(nxt)
            elif kind in ("return", "indirect") and nxt < end:
                leaders.add(nxt)
        first = sorted(leaders)
        block_of = {f: b + 2 for b, f in enumerate(first)}
        edges, kinds = [(0, 2, "fall")], []
        rows.add(("B", str(fk), name, "0", "entry", str(start), str(start), ""))
        rows.add(("B", str(fk), name, "1", "exit", str(end - 1), str(end - 1), ""))
        for b, f in enumerate(first):
            lim = first[b + 1] if b + 1 < len(first) else end
            term = max(pc for pc in ops if f <= pc < lim)
            kind, _w, target, text, ref = ops[term]
            has_next = b + 1 < len(first)
            if kind == "cond":
                edges.append((b + 2, block_of[target], "true") if target in block_of else (b + 2, 1, "goto-unresolved"))
                if has_next:
                    edges.append((b + 2, b + 3, "false"))
                rows.add(("G", str(term), "jump", name, text))
            elif kind == "goto":
                edges.append((b + 2, block_of[target], "goto") if target in block_of
                             else (b + 2, 1, "return" if ref else "goto-unresolved"))
            elif kind == "return":
                edges.append((b + 2, 1, "return"))
            elif kind == "indirect":
                edges.append((b + 2, 1, "goto-unresolved"))
            elif has_next:
                edges.append((b + 2, b + 3, "fall"))
            rows.add(("B", str(fk), name, str(b + 2), "cond" if kind == "cond" else "stmt",
                      str(f), str(term), text if kind == "cond" else ""))
        for a, b2, k in edges:
            rows.add(("E", str(fk), name, str(a), str(b2), k))
        for pc, op in ops.items():
            if op[4]:
                rows.add(("R", str(pc), name, op[4]))
        # An address taken in code: an aarch64 adrp/adr or literal, or a BPF
        # ld_imm64 (a callback); never a branch's own target.
        if e_type == 1:
            for (rs, off), r in sorted(reloc.items(), key=lambda kv: kv[0]):
                if rs != sec or not start * unit <= off < end * unit:
                    continue
                pc = max((q for q in ops if q <= off // unit), default=None)
                if pc is None:
                    continue
                if machine == "aarch64" and r[1] not in (274, 275, 311, 257):
                    continue
                if machine == "bpf" and ops[pc][0] == "call":
                    continue
                addend = r[2]
                if machine == "bpf" and r[0]["type"] == 3:
                    addend, = struct.unpack_from("<i", img, secs[sec]["off"] + off + 4)
                n = reloc_function(r, addend)
                if n:
                    rows.add(("R", str(pc), name, n))
    # An address held in allocated data is a reference from file scope, by an
    # absolute relocation (a PC-relative one in data is a jump table's).
    absolute = {257, 258} if machine == "aarch64" else {2, 3}
    if e_type == 1:
        for (rs, off), r in sorted(reloc.items(), key=lambda kv: kv[0]):
            if rs >= len(secs) or r[1] not in absolute:
                continue
            ds = secs[rs]
            if (not ds["flags"] & 2 or ds["flags"] & 4 or ds["name"] == ".eh_frame"
                    or ds["name"].startswith((".BTF", ".debug"))):
                continue
            addend = r[2]
            if machine == "bpf" and r[1] == 2 and ds["type"] == 1:
                addend, = struct.unpack_from("<q", img, ds["off"] + off)
            n = reloc_function(r, addend)
            if n:
                rows.add(("R", "0", "<file>", n))
    return rows


def artifact_rows(art):
    got = set()
    for ln in art.read_text().split("\n"):
        c = ln.split("\t")
        if c[0] == "G":
            got.add(("G", c[2], c[4], c[5], c[6]))
        elif c[0] == "D":
            got.add(("D", c[2], c[3], c[4]))
        elif c[0] == "R":
            got.add(("R", c[2], c[3], c[4]))
        elif c[0] == "B":
            got.add(("B", c[2], c[3], c[4], c[5], c[6], c[7], c[8]))
        elif c[0] == "E":
            got.add(("E", c[2], c[3], c[4], c[5], c[6]))
    return got


A64_FIXTURE = r"""
int helper(int x);
static int square(int v) { return v * v; }
int classify(int a, long b, unsigned m) {
    if (a == 0) return helper(b);
    if (b < 0) return -1;
    if (m & 0x20) a += 3;
    for (int i = 0; i < a; i++) {
        if (i % 7 == 3) continue;
        b += square(i);
    }
    switch (a) {
    case 1: return 10;
    case 2: return 20;
    case 3: return 30;
    case 4: return 40;
    case 5: return 50;
    case 6: return 60;
    default: break;
    }
    return (int)b;
}
int tail(int x) { return helper(x + 1); }
int pick(int k, const int *t) { return k < 4 ? t[k] : -1; }
"""


def check_object(obj, machine, label):
    """One object, scanned and decoded apart, row for row; the analyzer must
    read the artifact. Depth is left out: It is a dominator count, and the cfg
    report already holds the analyzer's dominators to an independent pass."""
    with tempfile.TemporaryDirectory() as d:
        art = Path(d) / "obj.guards"
        r = subprocess.run([str(MONTAUK), "--static", str(obj), "-o", str(art)], capture_output=True, text=True)
        if r.returncode != 0:
            note(f"FAIL object lane ({label}): --static exited {r.returncode}: {r.stderr[-200:]}")
            return False
        got = artifact_rows(art)
        env = json.loads(subprocess.run([str(MONTAUK), "--analyze", str(art), "--json"],
                                        capture_output=True, text=True).stdout)
    want = oracle_object_rows(obj, machine)
    missing, extra = want - got, got - want
    for x in sorted(missing)[:5]:
        note(f"FAIL object lane ({label}): the decoder has {x}, the scanner does not")
    for x in sorted(extra)[:5]:
        note(f"FAIL object lane ({label}): the scanner has {x}, the decoder does not")
    names = {r["name"] for r in env.get("reports", [])}
    if not {"guards", "declarations", "cfg"} <= names:
        note(f"FAIL object lane ({label}): the analyzer reads the artifact into {sorted(names)}")
        return False
    if missing or extra:
        return False
    kinds = {}
    for x in want:
        kinds[x[0]] = kinds.get(x[0], 0) + 1
    note(f"PASS object lane ({label}): decoded apart from the scanner, it agrees row for row "
         f"({', '.join(f'{v} {k}' for k, v in sorted(kinds.items()))}), and the analyzer reads it")
    return True


X86_CC = {"je": "e", "jne": "ne", "jb": "b", "jae": "ae", "jbe": "be", "ja": "a", "js": "s", "jns": "ns",
          "jp": "p", "jnp": "np", "jl": "l", "jge": "ge", "jle": "le", "jg": "g", "jo": "o", "jno": "no",
          "jrcxz": "jrcxz", "jecxz": "jrcxz", "loop": "loop", "loope": "loope", "loopne": "loopne"}
X86_PREFIX = {"bnd", "notrack", "ds", "cs", "rex", "rex.W", "data16", "addr32", "{disp32}"}


def objdump_x86(path):
    """Every conditional jump GNU objdump decodes: (function, offset, condition,
    target), offsets within their section, the function as objdump labels it;
    and the functions where objdump itself meets bytes it cannot decode, which
    are data in code (a string table after an assembly routine's ret)."""
    import re
    secaddr = {}
    for ln in subprocess.run(["objdump", "-h", "-w", str(path)], capture_output=True, text=True).stdout.split("\n"):
        c = ln.split()
        if len(c) > 4 and c[0].isdigit():
            secaddr[c[1]] = int(c[3], 16)
    out = subprocess.run(["objdump", "-d", "-w", "--no-show-raw-insn", str(path)], capture_output=True, text=True).stdout
    sec, func, start, conds, bad = None, None, 0, [], set()
    for ln in out.split("\n"):
        m = re.match(r"Disassembly of section (\S+):", ln)
        if m:
            sec = m.group(1)
            continue
        m = re.match(r"^([0-9a-f]+) <(.+)>:$", ln)
        if m:
            func, start = m.group(2), int(m.group(1), 16)
            continue
        m = re.match(r"^\s*([0-9a-f]+):\s+(.*)$", ln)
        if not m or func is None:
            continue
        if "(bad)" in m.group(2):
            bad.add((func, start))
        ins = m.group(2).split()
        while ins and ins[0] in X86_PREFIX:
            ins = ins[1:]
        mn = ins[0].split(",")[0] if ins else ""
        if mn in X86_CC and len(ins) > 1:
            base = secaddr.get(sec, 0)
            conds.append(((func, start), int(m.group(1), 16) - base, X86_CC[mn], int(ins[1], 16) - base))
    return conds, bad


def check_x86(objs):
    """The x86-64 lane against GNU objdump over real code: Every conditional jump
    inside a function the scanner reads must sit where objdump decodes one, test
    what it tests, and branch to the block that starts where objdump's target
    is. A length decoder that slips one byte fails every jump after the slip."""
    from collections import Counter
    import bisect
    if not shutil.which("objdump"):
        note("SKIP object lane (x86-64): no objdump to hold it to")
        return True
    ok, total, skipped = True, 0, 0
    for obj in objs:
        r = subprocess.run([str(MONTAUK), "--static", str(obj)], capture_output=True, text=True)
        if r.returncode != 0:
            note(f"FAIL object lane (x86-64) {obj.name}: --static exited {r.returncode}")
            ok = False
            continue
        # objdump labels an address by one of its aliases (C1/C2, D1/D2); the
        # scanner keeps the first STT_FUNC at it in symbol-table order.
        # A versioned symbol can name two functions (an old and a new
        # implementation), so a function is its name and its start.
        _img, ety, secs, syms, _rel = elf_read(obj)
        first_at, canon = {}, {}
        for y in syms:
            if y["type"] == 2:
                first_at.setdefault((y["shndx"], y["value"]), y["name"])
        for y in syms:
            if y["type"] == 2 and y["shndx"] < len(secs):
                rel = y["value"] - secs[y["shndx"]]["addr"] if ety != 1 else y["value"]
                canon[(y["name"], y["value"])] = (first_at[(y["shndx"], y["value"])], rel)
        blocks, ranges, true_to, names = {}, {}, {}, {}
        for ln in r.stdout.split("\n"):
            c = ln.split("\t")
            if c[0] == "B":
                blocks[(c[2], c[4])] = (c[5], int(c[6]), int(c[7]))
                names[c[2]] = c[3]
                if c[4] in ("0", "1"):
                    ranges.setdefault(c[2], [0, 0])[int(c[4])] = int(c[6]) + int(c[4])
            elif c[0] == "E" and c[6] == "true":
                true_to[(c[2], c[4])] = c[5]
        got = Counter()
        for (fk, b), (kind, first, last) in blocks.items():
            if kind != "cond":
                continue
            tb = true_to.get((fk, b))
            got[((names[fk], ranges[fk][0]), last, blocks[(fk, tb)][1] if tb else None)] += 1
        want = Counter()
        by_id = {(names[fk], rng[0]): rng for fk, rng in ranges.items()}
        conds, bad = objdump_x86(obj)
        data_fns = {canon.get((f.split("@")[0], a)) for f, a in bad}
        skipped += len(data_fns - {None})
        got = Counter({k: v for k, v in got.items() if k[0] not in data_fns})
        for (func, at), off, cc, target in conds:
            bare = func.split("@")[0]     # a dynamic symbol's label carries its version
            fn = canon.get((bare, at))
            rng = by_id.get(fn)
            if rng is None or fn in data_fns or not rng[0] <= off < rng[1]:
                continue
            want[(fn, off, target if rng[0] <= target < rng[1] else None)] += 1
        total += sum(want.values())
        if got != want:
            ok = False
            miss, extra = sorted((want - got).elements())[:3], sorted((got - want).elements())[:3]
            note(f"FAIL object lane (x86-64) {obj.name}: objdump has {miss}, the scanner {extra}")
    if ok:
        note(f"PASS object lane (x86-64): {total} conditional jumps over {len(objs)} object(s) sit, "
             f"and branch, where GNU objdump decodes them ({skipped} function(s) holding data "
             f"objdump cannot decode set aside)")
    return ok


def check_walk():
    """A DIR walk reads what the tree holds and nothing it should pass by: A
    dotfile and a linked file are read; a hidden directory, one carrying
    CACHEDIR.TAG, one that will not open and a linked directory are not."""
    import os
    body = "int f(int x) { if (x) return 1; return 0; }\n"
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        for sub_ in ("a/b", ".hidden", "cache", "locked", "real"):
            (root / sub_).mkdir(parents=True)
        for f in ("a/b/one.c", ".hidden/h.c", "cache/c.c", "locked/l.c", "real/r.c", ".dotfile.c"):
            (root / f).write_text(body)
        (root / "cache" / "CACHEDIR.TAG").write_text("")
        os.symlink("../real", root / "a" / "dirlink")
        os.symlink("../real/r.c", root / "a" / "filelink.c")
        (root / "locked").chmod(0)
        try:
            r = subprocess.run([str(MONTAUK), "--static", str(root)], capture_output=True, text=True)
        finally:
            (root / "locked").chmod(0o755)
        got = [ln.split(" ", 3)[3][len(d) + 1:] for ln in r.stdout.split("\n") if ln.startswith("file ")]
        want = [".dotfile.c", "a/b/one.c", "a/filelink.c", "real/r.c"]
        if os.geteuid() == 0:
            want = [".dotfile.c", "a/b/one.c", "a/filelink.c", "locked/l.c", "real/r.c"]
        if r.returncode != 0 or got != want:
            note(f"FAIL walk: rc {r.returncode}, read {got}, wanted {want}")
            return False
    note(f"PASS walk: a DIR reads {len(want)} files and passes by a hidden, a cache-tagged, "
         f"a closed and a linked directory")
    return True


# A function reached only through a pointer: twice's address is passed as a
# callback, add_one's sits in a data table, and unused_fn is kept (`used`) but
# named by nothing. In an object, a function's address taken by code or held
# in data is a reference, so only unused_fn is reached from none.
ADDR_FIXTURE = r"""
typedef int (*op_fn)(int);
int apply(op_fn f, int x);
static int add_one(int x) { return x + 1; }
static int twice(int x) { return x * 2; }
static __attribute__((used)) int unused_fn(int x) { return x - 1; }
op_fn table[] = { add_one };
int run(int x) { return apply(twice, x) + table[0](x); }
"""


def check_address_refs(clang):
    """The address-taken fixture, built for x86-64 and aarch64: its R rows name
    twice from run and add_one from file scope, and the analyzer reaches all
    but unused_fn. aarch64's rows ride the oracle as well."""
    ok = True
    with tempfile.TemporaryDirectory() as d:
        src = Path(d) / "addr.c"
        src.write_text(ADDR_FIXTURE)
        builds = [("x86-64", ["cc", "-O2", "-c"])]
        if clang:
            builds.append(("aarch64", [clang, "-target", "aarch64-linux-gnu", "-O2", "-ffreestanding",
                                       "-fno-asynchronous-unwind-tables", "-c"]))
        for label, cmd in builds:
            obj, art = Path(d) / f"addr-{label}.o", Path(d) / f"addr-{label}.guards"
            if subprocess.run([*cmd, str(src), "-o", str(obj)], capture_output=True).returncode != 0:
                note(f"SKIP address refs ({label}): the fixture does not build")
                continue
            subprocess.run([str(MONTAUK), "--static", str(obj), "-o", str(art)], capture_output=True)
            rows = {tuple(ln.split("\t")[3:5]) for ln in art.read_text().split("\n") if ln.startswith("R\t")}
            env = json.loads(subprocess.run([str(MONTAUK), "--analyze", str(art), "--json"],
                                            capture_output=True, text=True).stdout)
            rep = next(x for x in env["reports"] if x["name"] == "declarations")
            unreached = [x["name"] for x in rep.get("unreached", [])]
            if ("run", "twice") not in rows or ("<file>", "add_one") not in rows or unreached != ["unused_fn"]:
                note(f"FAIL address refs ({label}): R rows {sorted(rows)}, unreached {unreached}")
                ok = False
            if label == "aarch64":
                ok = check_object(obj, "aarch64", "the address-taken fixture for aarch64") and ok
    if ok:
        note("PASS address refs: a callback's address and a table's entry are references, in x86-64 "
             "and aarch64 code and data, and a function nothing names stays unreached")
    return ok


def check_objects():
    ok = True
    obj = ROOT / "build" / "montauk_trace.bpf.o"
    if obj.exists():
        ok = check_object(obj, "bpf", obj.name) and ok
    else:
        note(f"SKIP object lane: no {obj.name} in the build")
    clang = shutil.which("clang")
    with tempfile.TemporaryDirectory() as d:
        src, a64 = Path(d) / "a64.c", Path(d) / "a64.o"
        src.write_text(A64_FIXTURE)
        made = clang and subprocess.run([clang, "-target", "aarch64-linux-gnu", "-O2", "-ffreestanding",
                                         "-fno-asynchronous-unwind-tables", "-c", str(src), "-o", str(a64)],
                                        capture_output=True).returncode == 0
        if made:
            ok = check_object(a64, "aarch64", "an aarch64 fixture built by clang") and ok
        else:
            note("SKIP object lane (aarch64): clang cannot target aarch64-linux-gnu here")
    objs = sorted((ROOT / "build" / "CMakeFiles").rglob("*.o"))[::8]
    libc = Path("/usr/lib/libc.so.6")
    if libc.exists():
        objs.append(libc)
    ok = check_x86(objs) and ok
    ok = check_address_refs(clang) and ok
    with tempfile.TemporaryDirectory() as d:
        src, rv = Path(d) / "rv.c", Path(d) / "rv.o"
        src.write_text("int f(int a) { return a ? 1 : 2; }\n")
        made = clang and subprocess.run([clang, "-target", "riscv64-linux-gnu", "-ffreestanding", "-c",
                                         str(src), "-o", str(rv)], capture_output=True).returncode == 0
        if made:
            other = subprocess.run([str(MONTAUK), "--static", str(rv)], capture_output=True, text=True)
            if other.returncode != 2 or "aarch64 and x86-64" not in other.stderr:
                note(f"FAIL object lane: a RISC-V object is not refused by name (rc {other.returncode})")
                ok = False
    return ok


def check_analyzer(targets):
    """The join lives in the analyzer, so the analyzer is where it is checked.

    --static records and concludes nothing; --analyze is the half that says
    which declarations nothing reaches. Both faces render from one typed
    result, so the text and the JSON must agree, and the arithmetic must match
    what the artifact's own rows say -- otherwise the report is a number the
    reader cannot re-derive."""
    with tempfile.TemporaryDirectory() as d:
        art = Path(d) / "corpus.guards"
        r = subprocess.run([str(MONTAUK), "--static", "-o", str(art),
                            *[str(t) for t in targets]],
                           capture_output=True, text=True)
        if r.returncode != 0 or not art.exists():
            note(f"FAIL montauk --static -o exited {r.returncode}")
            return False
        rows = [ln.split("\t") for ln in art.read_text().split("\n")
                if ln[:2] in ("D\t", "R\t")]
        declared = [c[4] for c in rows if c[0] == "D"]
        referenced = {c[4] for c in rows if c[0] == "R"}
        # Reached, walked apart from the analyzer: Entry points are main and
        # whatever file scope (or code the scan declares nothing for) names,
        # then each name reaches what is named from inside it. One per
        # DECLARATION, as the verdict counts them.
        names = set(declared)
        edges, frontier = {}, []
        for c in rows:
            if c[0] != "R":
                continue
            if c[3] == "<file>" or c[3] not in names:
                frontier.append(c[4])
            else:
                edges.setdefault(c[3], []).append(c[4])
        for name in declared:          # `TEST:x` is reached with the macro TEST, and by x
            stem = name.split(":", 1)[0]
            if ":" in name and stem in names:
                edges.setdefault(stem, []).append(name)
            if ":" in name:
                edges.setdefault(name.split(":", 1)[1], []).append(name)
        if "main" in names:
            frontier.append("main")
        reached = set()
        while frontier:
            n = frontier.pop()
            if n not in reached:
                reached.add(n)
                frontier.extend(edges.get(n, []))
        want_unreached = [name for name in declared if name not in reached]

        def is_named(name):
            return name in referenced or (":" in name and name.split(":", 1)[1] in referenced)
        want_orphans = [name for name in want_unreached if not is_named(name)]

        r = subprocess.run([str(MONTAUK), "--analyze", str(art), "--json"],
                           capture_output=True, text=True)
        if r.returncode != 0:
            note(f"FAIL montauk --analyze --json exited {r.returncode}")
            note(r.stderr.strip()[:400])
            return False
        try:
            env = json.loads(r.stdout)
        except json.JSONDecodeError as e:
            note(f"FAIL analyzer JSON does not parse: {e}")
            return False
        rep = [x for x in env.get("reports", []) if x["name"] == "declarations"]
        if not rep:
            note("FAIL analyzer emits no declarations report")
            return False
        rep = rep[0]
        gauges = {g["name"]: g["value"] for g in rep["gauges"] if "labels" not in g}
        problems = []
        if env["static"]["declarations"] != len(declared):
            problems.append(f"declarations {env['static']['declarations']} "
                            f"vs {len(declared)} D rows")
        nref = sum(1 for c in rows if c[0] == "R")
        if env["static"]["references"] != nref:
            problems.append(f"references {env['static']['references']} vs {nref} R rows")
        if gauges.get("montauk_static_unreferenced_total") != len(want_orphans):
            problems.append(f"unreferenced {gauges.get('montauk_static_unreferenced_total')} "
                            f"vs {len(want_orphans)} by the rows")
        if gauges.get("montauk_static_unreached_total") != len(want_unreached):
            problems.append(f"unreached {gauges.get('montauk_static_unreached_total')} "
                            f"vs {len(want_unreached)} by an independent walk")
        listed = rep.get("unreached", [])
        if [x["name"] for x in listed] != want_unreached:
            problems.append(f"{len(listed)} names listed as unreached, the walk finds "
                            f"{len(want_unreached)}")
        wrong = [x["name"] for x in listed
                 if (x["named"] == "by nothing") != (not is_named(x["name"]))]
        if wrong:
            problems.append(f"named-by-nothing marked wrong for: {', '.join(wrong[:5])}")

        # One typed result, two faces: the verdict text must carry the same
        # counts the JSON does, or a reader of either is reading a different run.
        r = subprocess.run([str(MONTAUK), "--analyze", str(art)],
                           capture_output=True, text=True)
        if rep["verdict"] not in r.stdout:
            problems.append("the text report's verdict differs from the JSON's")

        problems += check_cfg_report(art, env)
        if problems:
            note("FAIL analyzer join:")
            for x in problems:
                note(f"  {x}")
            return False
        note(f"PASS analyzer ({len(declared)} declarations, {nref} references, "
             f"{len(want_unreached)} reached from no entry point, {len(want_orphans)} of them "
             f"named by nothing, the graph's arithmetic recomputed; text and JSON agree)")
        return True


def check(path):
    got, want = cpp_rows(path), oracle_rows(path)
    if got is None or want is None:
        return False
    if got == want:
        note(f"PASS {path.name} ({len(got)} guards)")
        return True
    note(f"FAIL {path.name}: {len(got)} guards vs oracle's {len(want)}")
    gs, ws = set(got), set(want)
    for label, rows in (("montauk only", gs - ws), ("oracle only", ws - gs)):
        for row in list(rows)[:5]:
            note(f"  {label}: line {row[0]} depth {row[1]} {row[2]} "
                 f"[{row[3]}] {row[4][:80]}")
    return False


def main():
    if not MONTAUK.exists():
        note(f"FAIL montauk not built ({MONTAUK})")
        return 1
    if not ORACLE.exists():
        note(f"FAIL oracle missing ({ORACLE})")
        return 1

    r = subprocess.run([sys.executable, str(ORACLE), "--self-test"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        note("FAIL the oracle's own self-test does not pass -- fix it before "
             "trusting it to judge anything")
        print(r.stdout)
        return 1
    note("PASS oracle self-test")

    targets = [Path(a) for a in sys.argv[1:]]
    if not targets:
        targets = sorted((ROOT / "src" / "tools").glob("*.cpp"))
        targets += sorted((ROOT / "src" / "bpf").glob("*.c"))
    else:
        # A DIR is the tree --static would walk: every file a dialect claims,
        # hidden directories and CACHEDIR.TAG trees skipped.
        expanded = []
        for t in targets:
            if not t.is_dir():
                expanded.append(t)
                continue
            for p in sorted(t.rglob("*")):
                rel = p.relative_to(t).parts
                if any(x.startswith(".") for x in rel[:-1]):
                    continue
                if any((t.joinpath(*rel[:k]) / "CACHEDIR.TAG").exists() for k in range(1, len(rel))):
                    continue
                if p.is_file() and p.suffix in {e for d in DIALECT_EXTS for e in d}:
                    expanded.append(p)
        targets = expanded
    missing = [t for t in targets if not t.exists()]
    for t in missing:
        note(f"FAIL no such file: {t}")
    targets = [t for t in targets if t.exists()]
    if not targets:
        note("FAIL no corpus to scan")
        return 1

    # The hand-checked fixtures ride the oracle comparison too: they are the
    # Rust corpus, since montauk carries no Rust of its own.
    fixture_dir = tempfile.TemporaryDirectory()
    for name, (src, _want) in CFG_FIXTURES.items():
        path = Path(fixture_dir.name) / name
        path.write_text(src)
        targets.append(path)

    ok = all([check(t) for t in targets]) and not missing
    note("guards agree" if ok else "guards DISAGREE")
    ok = all([check_declared(t) for t in targets]) and ok
    note("declarations and references agree" if ok else "declared structure "
         "DISAGREES")
    ok = all([check_refs_known(t) for t in targets]) and ok
    ok = all([check_cfg(t) for t in targets]) and ok
    note("graphs agree" if ok else "graphs DISAGREE")
    ok = check_fixture() and ok
    ok = check_cfg_fixtures() and ok
    ok = check_analyzer(targets) and ok
    ok = check_seam() and ok
    ok = check_entries() and ok
    ok = check_objects() and ok
    ok = check_walk() and ok
    py = sorted({p for d in ("tests", "sublimation/tests", "sublimation/tools") for p in (ROOT / d).rglob("*.py")})
    ok = check_python(py) and ok
    note("GATE PASSED: the shipped scanner agrees with an independent "
         "implementation on every guard, declaration, reference, block and "
         "edge, records a known file's declared structure and graphs exactly, "
         "and the analyzer's join and graph arithmetic hold in text and JSON"
         if ok else "GATE FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
