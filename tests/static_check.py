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
        if got == FIXTURE_WANT:
            note(f"PASS fixture ({len(got)} rows match the hand expectation)")
            return True
        note("FAIL fixture: the artifact does not match what the file declares")
        for label, rows in (("montauk only", [r for r in got if r not in FIXTURE_WANT]),
                            ("expected", [r for r in FIXTURE_WANT if r not in got])):
            for row in rows[:6]:
                note(f"  {label}: {row[0]} line {row[1]} [{row[2]}] {row[3]}")
        return False


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
# while let, match arms with return, let-else, loop, unsafe and `?`.
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
}


def check_cfg_fixtures():
    """The oracle catches two implementations disagreeing, never both agreeing
    on the wrong graph. These are small enough to have been checked by hand."""
    ok = True
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
            for fn, (kinds, edge_list) in want.items():
                if " ".join(blocks.get(fn, [])) != kinds or ", ".join(edges.get(fn, [])) != edge_list:
                    note(f"FAIL {name} {fn}: the graph is not the hand-checked one")
                    note(f"  blocks {' '.join(blocks.get(fn, []))}")
                    note(f"  edges  {', '.join(edges.get(fn, []))}")
                    ok = False
            if ok:
                note(f"PASS {name} ({len(want)} function(s) match the hand-checked graph)")
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
        "dead": sum(1 for v in range(n) if not state[v] and blocks[v] != "exit"),
    }


def check_cfg_report(art, env):
    """The cfg report's arithmetic against independent_cfg over the same rows."""
    fns = {}
    for ln in art.read_text().split("\n"):
        c = ln.split("\t")
        if c[0] == "B":
            fns.setdefault((c[1], c[2]), ([], []))[0].append(c[5])
        elif c[0] == "E":
            fns.setdefault((c[1], c[2]), ([], []))[1].append((int(c[4]), int(c[5])))
    if not fns:
        return []
    stats = [independent_cfg(b, e) for b, e in fns.values()]
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
    if got_max != [max(s["cyclomatic"] for s in stats)]:
        problems.append(f"cyclomatic max {got_max} vs {max(s['cyclomatic'] for s in stats)}")
    return problems


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
        # One per DECLARATION, as the verdict counts them: a name declared twice
        # and named nowhere is two declarations nothing reaches.
        want_orphans = [name for name in declared if name not in referenced]

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
        got_names = [x["name"] for x in rep.get("unreferenced", [])]
        if len(got_names) != min(32, len(want_orphans)):
            problems.append(f"{len(got_names)} names listed, expected "
                            f"{min(32, len(want_orphans))}")
        stray = sorted(set(got_names) - set(want_orphans))
        if stray:
            problems.append(f"listed as unreferenced but the rows reference it: "
                            f"{', '.join(stray[:5])}")

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
             f"{len(want_orphans)} unreferenced, the graph's arithmetic recomputed; "
             f"text and JSON agree)")
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
    note("GATE PASSED: the shipped scanner agrees with an independent "
         "implementation on every guard, declaration, reference, block and "
         "edge, records a known file's declared structure and graphs exactly, "
         "and the analyzer's join and graph arithmetic hold in text and JSON"
         if ok else "GATE FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
