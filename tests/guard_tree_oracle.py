#!/usr/bin/env python3
"""guard_tree_oracle -- the dominating condition on every branch in a C or Rust
file, and each function's control flow graph.

THE ORACLE, NOT THE SHIPPED IMPLEMENTATION. montauk --static is the real
scanner; this is the independent second implementation its gate checks
against, the same role std::sort holds in sublimation's tests. Two
implementations of one algorithm in two languages disagree loudly, which is
the only cheap way to catch a lexer that is confidently wrong.

WHY THIS IS A LEXER AND NOT A PARSER. The question it answers is "what had to be
true to reach this statement", and that needs paren matching, brace matching and
nothing else: no types, no name resolution, no semantics. Every route that DOES
parse costs a dependency this fixture is not allowed to have. clang's JSON AST
carries an explicit upstream warning that node fields change "in non-additive
ways" between releases, so a clang upgrade breaks the fixture silently rather
than loudly; the same file's translation unit pulls in a 161,320-line vmlinux.h
and dumps hundreds of megabytes to say something about 3,400 lines of our own.
debug.DumpCFG is a developer-debug checker printing to stderr with no stability
contract at all. libclang is a package pin against the installed LLVM. A scanner
over our own source depends on nothing and cannot rot.

Macros are NOT expanded, and that is the point rather than a shortcut. The audit
this exists for reads guards across versions, so `tier == TIER_BATCH` has to stay
spelled that way to be diffable -- an AST would hand back `tier == 2` and the
comparison would be against a constant nobody wrote.

THE SET OPERATIONS ARE SUBLIMATION'S. Rows come out tab-separated so the diff
between two trees is `subtract` and `intersect` on a stable key, not a dict
comprehension reimplementing them here.

    python3 guard-tree.py src/bpf/main.bpf.c                  # rows, TSV
    python3 guard-tree.py --tree src/bpf/main.bpf.c           # indented
    python3 guard-tree.py --symbols tier,keep_own FILE        # only these
    python3 guard-tree.py --diff OLD.c NEW.c                  # what changed
    python3 guard-tree.py --declared FILE                     # D and R rows
    python3 guard-tree.py --cfg FILE                          # B and E rows
    python3 guard-tree.py --self-test
"""

import argparse
import bisect
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import shutil

IDENT = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")
SPACE = " \t\n\r"


class Dialect:
    """One row of the dialect table: everything a language changes about the scan."""

    def __init__(self, name, exts, nested, lifetimes, raw, paren, ternary,
                 fn_word, containers, branches, block_words):
        self.name, self.exts = name, exts.split()
        self.nested, self.lifetimes, self.raw = nested, lifetimes, raw
        self.paren, self.ternary, self.fn_word = paren, ternary, fn_word
        self.containers = containers.split()
        self.branches = branches.split()
        self.block_words = block_words.split()


DIALECTS = [
    Dialect("c", ".c .h .cc .cpp .cxx .hh .hpp .hxx .inc", False, False, False, True,
            True, None, "namespace extern struct class union enum", "if while for switch", ""),
    Dialect("rust", ".rs", True, True, True, False, False, "fn", "impl mod trait extern",
            "if while for match", "unsafe async"),
]


def dialect_for(path, forced=None):
    if forced:
        return next(d for d in DIALECTS if d.name == forced)
    suffix = Path(path).suffix
    return next((d for d in DIALECTS if suffix in d.exts), DIALECTS[0])


def mask_code(src: str, keep_strings: bool = False, d: Dialect = DIALECTS[0], pp=None) -> str:
    """Blank comments, literals and preprocessor lines, byte offsets preserved.

    Every replacement is one space per byte and newlines are kept, so an offset
    into the mask is the same offset into the source and line numbers stay exact.
    Scanning the mask while SLICING a mask is what lets brace matching never trip
    over a `}` in a string.

    TWO MASKS, DIFFERING ONLY IN LITERALS, AND THE SECOND ONE IS NOT OPTIONAL.
    Guard text sliced out of the RAW source drags any comment sitting inside the
    condition along with it, and this codebase writes multi-paragraph comments
    inside expressions -- one ternary in task_deadline carried thirty lines of
    prose into its own guard text on the first real run. Slicing the
    strings-kept mask instead blanks the comment and leaves the code, at the
    cost of emptying a string literal in a condition, which is the far cheaper
    loss.

    `pp`, when a list, receives every conditional-compilation directive as
    (offset, kind): 'i' #if/#ifdef/#ifndef, 'l' #elif, 'e' #else, 'n' #endif.
    """
    out = list(src)
    n = len(src)
    i = 0
    at_line_start = True
    while i < n:
        c = src[i]
        if c == "\n":
            at_line_start = True
            i += 1
            continue
        if at_line_start and c in " \t":
            i += 1
            continue
        if at_line_start and c == "#":
            if pp is not None:
                w = i + 1
                while w < n and src[w] in " \t":
                    w += 1
                k = {"if": "i", "ifdef": "i", "ifndef": "i", "elif": "l", "else": "e",
                     "endif": "n"}.get(src[w:word_end(src, w)])
                if k:
                    pp.append((i, k))
            while i < n and src[i] != "\n":
                if src[i] == "\\" and i + 1 < n and src[i + 1] == "\n":
                    out[i] = " "
                    i += 2
                    continue
                out[i] = " "
                i += 1
            continue
        at_line_start = False
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            while i < n and src[i] != "\n":
                out[i] = " "
                i += 1
            continue
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            out[i] = out[i + 1] = " "
            i += 2
            depth = 1
            while i < n and depth:
                if src[i] == "*" and i + 1 < n and src[i + 1] == "/":
                    out[i] = out[i + 1] = " "
                    i += 2
                    depth -= 1
                    continue
                if d.nested and src[i] == "/" and i + 1 < n and src[i + 1] == "*":
                    out[i] = out[i + 1] = " "
                    i += 2
                    depth += 1
                    continue
                if src[i] != "\n":
                    out[i] = " "
                i += 1
            continue
        # A `'` inside a token that starts with a digit is a C++14/C23 digit
        # separator (`2'000'000'000`), not a character literal.
        if c == "'" and i and src[i - 1] in IDENT and i + 1 < n and src[i + 1] in IDENT:
            k = i
            while k and src[k - 1] in IDENT:
                k -= 1
            if src[k].isdigit():
                i += 1
                continue
        if d.raw and c == "r" and (i == 0 or src[i - 1] not in IDENT or
                                   (src[i - 1] == "b" and (i < 2 or src[i - 2] not in IDENT))):
            j, h = i + 1, 0
            while j < n and src[j] == "#":
                j += 1
                h += 1
            if j < n and src[j] == '"':
                k = j + 1
                while k < n:
                    if src[k] == '"':
                        m = 0
                        while m < h and k + 1 + m < n and src[k + 1 + m] == "#":
                            m += 1
                        if m == h:
                            break
                    k += 1
                stop = k + 1 + h if k < n else n
                if not keep_strings:
                    for q in range(i + 1, stop):
                        if src[q] != "\n":
                            out[q] = " "
                i = stop
                continue
        if (d.lifetimes and c == "'" and i + 1 < n and src[i + 1] != "\\"
                and ord(src[i + 1]) < 0x80 and not (i + 2 < n and src[i + 2] == "'")):
            i += 1
            continue
        if c in "\"'":
            quote = c
            if not keep_strings:
                out[i] = " "
            i += 1
            while i < n and src[i] != quote:
                if src[i] == "\\":
                    if not keep_strings:
                        out[i] = " "
                        if i + 1 < n and src[i + 1] != "\n":
                            out[i + 1] = " "
                    i += 2
                    continue
                if src[i] != "\n" and not keep_strings:
                    out[i] = " "
                i += 1
            if i < n:
                if not keep_strings:
                    out[i] = " "
                i += 1
            continue
        i += 1
    return "".join(out)


def match_pair(mask: str, i: int, opener: str, closer: str) -> int:
    """Index just PAST the closer matching the opener at mask[i]; -1 unbalanced."""
    depth = 0
    while i < len(mask):
        if mask[i] == opener:
            depth += 1
        elif mask[i] == closer:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return -1


def is_word_at(mask: str, i: int, word: str) -> bool:
    if not mask.startswith(word, i):
        return False
    if i and mask[i - 1] in IDENT:
        return False
    after = i + len(word)
    return after >= len(mask) or mask[after] not in IDENT


def skip_space(mask: str, i: int) -> int:
    while i < len(mask) and mask[i] in SPACE:
        i += 1
    return i


def word_end(mask: str, i: int) -> int:
    while i < len(mask) and mask[i] in IDENT:
        i += 1
    return i


def find_depth0(mask: str, a: int, b: int, tok: str) -> int:
    depth = 0
    for i in range(a, b):
        c = mask[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif depth == 0 and mask.startswith(tok, i):
            return i
    return -1


def brace_at_depth0(mask: str, a: int, b: int) -> int:
    depth = 0
    for i in range(a, b):
        c = mask[i]
        if c == "{" and depth == 0:
            return i
        if c in "([":
            depth += 1
        elif c in ")]":
            depth -= 1
    return -1


def norm(text: str) -> str:
    return " ".join(text.split())


def match_arms(mask: str, a: int, b: int):
    """(pat_a, pat_b, body_a, body_b) per arm: a pattern up to `=>`, then a block
    or one expression."""
    arms = []
    i = a
    while True:
        i = skip_space(mask, i)
        while i < b and mask[i] == ",":
            i = skip_space(mask, i + 1)
        if i >= b:
            break
        arrow = find_depth0(mask, i, b, "=>")
        if arrow < 0:
            break
        body = skip_space(mask, arrow + 2)
        if body < b and mask[body] == "{":
            body_end = match_pair(mask, body, "{", "}")
            if body_end < 0:
                break
        else:
            body_end = find_depth0(mask, body, b, ",")
            if body_end < 0:
                body_end = b
        arms.append((i, arrow, body, body_end))
        i = body_end
    return arms


def condition(d, mask, kw_end, end):
    """(state, a, b, body): 0 no condition here, -1 unbalanced, 1 found."""
    if d.paren:
        popen = skip_space(mask, kw_end)
        if popen >= end or mask[popen] != "(":
            return 0, 0, 0, 0
        pclose = match_pair(mask, popen, "(", ")")
        if pclose < 0:
            return -1, 0, 0, 0
        return 1, popen + 1, pclose - 1, pclose
    br = brace_at_depth0(mask, kw_end, end)
    if br < 0:
        return 0, 0, 0, 0
    return 1, kw_end, br, br


class Row:
    __slots__ = ("line", "func", "kind", "depth", "guard", "path")

    def __init__(self, line, func, kind, depth, guard, path):
        self.line = line
        self.func = func
        self.kind = kind
        self.depth = depth
        self.guard = guard
        self.path = path

    def key(self) -> str:
        """Identity for set operations: everything except WHERE it sits.

        Line numbers move on every unrelated edit, so they are excluded or the
        diff reports the whole file every time.
        """
        return f"{self.func}\t{self.kind}\t{self.guard}"

    def tsv(self, path_str: str) -> str:
        return (f"{self.line}\t{self.func}\t{self.kind}\t{self.depth}\t"
                f"{self.guard}\t{path_str}")


def find_functions(mask: str, d: Dialect = DIALECTS[0]) -> list[tuple[int, int, str, int]]:
    """(body_start, body_end, name, name_offset) for every top-level body.

    The offset is what separates a definition from a reference to it: the
    name in the head is the declaration, every other spelling is not."""
    out = []
    i = 0
    n = len(mask)
    while i < n:
        if mask[i] != "{":
            i += 1
            continue
        end = match_pair(mask, i, "{", "}")
        if end < 0:
            break
        # The head ends at the last thing that closed -- a statement, a body,
        # or an enclosing block's brace. Without the brace, the first function
        # inside a namespace inherits the namespace's own head.
        head_start = max(mask.rfind(";", 0, i), mask.rfind("}", 0, i),
                         mask.rfind("{", 0, i)) + 1
        head = mask[head_start:i]
        name = "<file>"
        name_off = -1
        # A CONTAINER IS NOT A BODY -- descend, or every function inside a
        # namespace, class, impl or mod is attributed to the file. A head with
        # `=` is data; in C a head with a paren is a function returning one.
        fn_at = -1
        if d.fn_word:
            p = head.find(d.fn_word)
            while p >= 0:
                if is_word_at(head, p, d.fn_word):
                    fn_at = p
                p = head.find(d.fn_word, p + 1)
        if fn_at < 0 and "=" not in head and (d.fn_word or ")" not in head):
            if any(w in d.containers for w in re.findall(r"[A-Za-z0-9_]+", head)):
                i += 1
                continue
        if fn_at >= 0:
            k = skip_space(head, fn_at + len(d.fn_word))
            stop = word_end(head, k)
            if stop > k:
                name = head[k:stop]
                name_off = head_start + k
        elif not d.fn_word:
            paren = head.rfind(")")
            if paren >= 0:
                depth = 0
                j = paren
                while j >= 0:
                    if head[j] == ")":
                        depth += 1
                    elif head[j] == "(":
                        depth -= 1
                        if depth == 0:
                            break
                    j -= 1
                if j > 0:
                    k = j - 1
                    while k >= 0 and head[k] in SPACE:
                        k -= 1
                    stop = k
                    while k >= 0 and head[k] in IDENT:
                        k -= 1
                    if k < stop:
                        name = head[k + 1:stop + 1]
                        name_off = head_start + k + 1
                    # A MACRO-DEFINED FUNCTION IS NAMED BY ITS FIRST ARGUMENT.
                    # Every sched_ext op is `BPF_STRUCT_OPS(pandemonium_enqueue, ..)`,
                    # so the identifier before the paren is the macro and collapsing
                    # them all under it would put most of this file in one bucket.
                    if name.isupper():
                        first = head[j + 1:paren].split(",")[0].strip()
                        if first and all(ch in IDENT for ch in first):
                            name = f"{name}:{first}"
        out.append((i, end, name, name_off))
        i = end
    return out


def walk(d, src, mask, start, end, func, stack, rows) -> None:
    """Collect guards in [start, end), recursing so `stack` is the domination
    chain -- the conditions that must hold to reach the region being walked."""
    i = start
    while i < end:
        c = mask[i]
        if d.ternary and c == "?":
            cond = ternary_condition(src, mask, i)
            if cond:
                rows.append(Row(src.count("\n", 0, i) + 1, func, "ternary",
                                len(stack), cond, list(stack)))
            i += 1
            continue
        if c not in IDENT or (i and mask[i - 1] in IDENT):
            i += 1
            continue
        we = word_end(mask, i)
        w = mask[i:we]
        if w not in d.branches:
            i = we
            continue
        if w == "if":
            i = walk_if(d, src, mask, i, end, func, stack, rows)
            continue
        if w == "match":
            i = walk_match(d, src, mask, i, end, func, stack, rows)
            continue
        st, a, b, body = condition(d, mask, we, end)
        if st == 0:
            i = we
            continue
        if st < 0:
            break
        cond = norm(src[a:b])
        rows.append(Row(src.count("\n", 0, i) + 1, func, w, len(stack),
                        cond, list(stack)))
        body_start, body_end, resume = region(mask, body, end)
        walk(d, src, mask, body_start, body_end, func, stack + [cond], rows)
        i = resume


def walk_if(d, src, mask, i, end, func, stack, rows) -> int:
    """One `if`, its body and its whole else chain. Returns where to resume.

    The `else` arm carries the NEGATION as a real guard: for a two-valued
    classifier that arm is half the behaviour, and an audit that only records
    the positive test sees half the code.
    """
    st, a, b, body = condition(d, mask, i + 2, end)
    if st == 0:
        return i + 2
    if st < 0:
        return end
    cond = norm(src[a:b])
    rows.append(Row(src.count("\n", 0, i) + 1, func, "if", len(stack),
                    cond, list(stack)))
    body_start, body_end, resume = region(mask, body, end)
    walk(d, src, mask, body_start, body_end, func, stack + [cond], rows)

    j = skip_space(mask, resume)
    if j >= end or not is_word_at(mask, j, "else"):
        return resume
    neg = f"!({cond})"
    rows.append(Row(src.count("\n", 0, j) + 1, func, "else", len(stack),
                    neg, list(stack)))
    k = skip_space(mask, j + 4)
    if is_word_at(mask, k, "if"):
        return walk_if(d, src, mask, k, end, func, stack + [neg], rows)
    bs, be, resume2 = region(mask, k, end, already_at_body=True)
    walk(d, src, mask, bs, be, func, stack + [neg], rows)
    return resume2


def walk_match(d, src, mask, i, end, func, stack, rows) -> int:
    """A guard on the scrutinee and one per arm on its pattern, each arm's body
    nested under both."""
    st, a, b, body = condition(d, mask, i + 5, end)
    if st == 0:
        return i + 5
    if st < 0:
        return end
    close = match_pair(mask, body, "{", "}")
    if close < 0:
        return end
    scrut = norm(src[a:b])
    rows.append(Row(src.count("\n", 0, i) + 1, func, "match", len(stack),
                    scrut, list(stack)))
    for pa, pb, ba, bb in match_arms(mask, body + 1, close - 1):
        pat = norm(src[pa:pb])
        rows.append(Row(src.count("\n", 0, pa) + 1, func, "arm", len(stack) + 1,
                        pat, stack + [scrut]))
        walk(d, src, mask, ba, bb, func, stack + [scrut, pat], rows)
    return close


def region(mask: str, after: int, end: int,
           already_at_body=False) -> tuple[int, int, int]:
    """(inner_start, inner_end, resume) for a braced block or one statement.

    `resume` is past the closer rather than at it, which is what lets the caller
    look for the `else` that follows.
    """
    j = after if already_at_body else skip_space(mask, after)
    if j < end and mask[j] == "{":
        close = match_pair(mask, j, "{", "}")
        if close > 0:
            return j + 1, min(close - 1, end), close
    semi = mask.find(";", j)
    stop = min(semi + 1, end) if semi >= 0 else end
    return j, stop, stop


def ternary_condition(src: str, mask: str, q: int) -> str:
    """Walk LEFT from `?` to the start of its condition.

    A ternary is a branch and several of this codebase's two-valued decisions are
    written as one, so skipping them would drop exactly the guards worth reading.
    Stops on a statement or argument boundary at paren depth zero.
    """
    depth = 0
    i = q - 1
    while i >= 0:
        c = mask[i]
        if c in ")]":
            depth += 1
        elif c in "([":
            if depth == 0:
                break
            depth -= 1
        elif depth == 0 and (c in ";{}," or (c == "=" and mask[i - 1] not in "!<>=")
                             or c == ":"):
            break
        i -= 1
    cond = norm(src[i + 1:q])
    for lead in ("return ", "case "):
        if cond.startswith(lead):
            cond = cond[len(lead):]
    return cond


def extract(path: Path, lang=None) -> list[Row]:
    d = dialect_for(path, lang)
    src = path.read_text(errors="replace")
    mask = mask_code(src, False, d)                # scanned: literals blanked too
    text = mask_code(src, True, d)                 # sliced: comments gone, code kept
    rows: list[Row] = []
    for body_start, body_end, name, _off in find_functions(mask, d):
        walk(d, text, mask, body_start + 1, body_end - 1, name, [], rows)
    rows.sort(key=lambda r: r.line)
    return rows


class Cfg:
    """One function's basic blocks and edges, built statement by statement.

    `pend` holds the edges waiting for whatever comes next, so a join needs no
    empty block, and code nothing flows into becomes a block with no
    predecessor -- which is how unreachable code shows up at all."""

    def __init__(self, d, src, mask, nl, pp):
        self.d, self.src, self.mask, self.nl, self.pp = d, src, mask, nl, pp
        self.pp_at = 0
        self.alts = []              # [entry, outs, has_else]
        self.blocks = []            # [kind, first, last, text]
        self.edges = []             # (from, to, kind)
        self.open = -1
        self.pend = []
        self.rets = []
        self.ctx = []               # [head, loop, label, brk, cont, saw_default]
        self.label_next = ""
        self.labels = {}
        self.gotos = []

    def line(self, off):
        return bisect.bisect_left(self.nl, off) + 1

    def block(self, kind, off, text=""):
        ln = self.line(off)
        self.blocks.append([kind, ln, ln, text])
        return len(self.blocks) - 1

    def link(self, frm, to, as_=None):
        for f, kind in frm:
            self.edges.append((f, to, as_ or kind))

    def flow(self):
        f = self.pend
        self.pend = []
        if self.open >= 0:
            f.append((self.open, "fall"))
        self.open = -1
        return f

    def node(self, kind, off, text=""):
        f = self.flow()
        bid = self.block(kind, off, text)
        self.link(f, bid)
        return bid

    def try_edge(self, bid, a, b):
        if self.d.ternary or a >= b or "?" not in self.mask[a:b]:
            return
        if not self.rets or self.rets[-1][0] != bid:
            self.rets.append((bid, "try"))

    def stmt(self, a, b):
        while b > a and self.mask[b - 1] in SPACE:
            b -= 1
        if self.open < 0:
            self.open = self.node("stmt", a)
        self.blocks[self.open][2] = self.line(b - 1 if b > a else a)
        self.try_edge(self.open, a, b)

    def jump(self, to, kind):
        to.append((self.open, kind))
        self.open = -1

    def take_label(self):
        lab, self.label_next = self.label_next, ""
        return lab

    def has_code(self, a, b):
        return any(ch not in SPACE for ch in self.mask[a:b])

    def cond(self, a, b):
        m = self.mask
        while a < b and m[a] in SPACE:
            a += 1
        while b > a and m[b - 1] in SPACE:
            b -= 1
        if b > a and m[a] == "(" and match_pair(m, a, "(", ")") == b:
            return self.cond(a + 1, b - 1)
        if not is_word_at(m, a, "let"):
            for op in ("||", "&&"):
                cut = find_depth0(m, a, b, op)
                if cut < 0:
                    continue
                entry, t, f = self.cond(a, cut)
                while cut >= 0:
                    nxt = find_depth0(m, cut + 2, b, op)
                    ne, nt, nf = self.cond(cut + 2, b if nxt < 0 else nxt)
                    if op[0] == "|":
                        self.link(f, ne)
                        f = nf
                        t = t + nt
                    else:
                        self.link(t, ne)
                        t = nt
                        f = f + nf
                    cut = nxt
                return entry, t, f
        bid = self.block("cond", a, norm(self.src[a:b]))
        self.try_edge(bid, a, b)
        return bid, [(bid, "true")], [(bid, "false")]

    def stmt_end(self, i, end):
        m = self.mask
        if not self.d.paren:
            we = word_end(m, i)
            bang = skip_space(m, we)
            br = skip_space(m, bang + 1) if bang < end and m[bang] == "!" else -1
            if we > i and 0 <= br < end and m[br] == "{":
                c = match_pair(m, br, "{", "}")
                if c < 0 or c > end:
                    return end
                s = skip_space(m, c)
                return s + 1 if s < end and m[s] == ";" else c
        s = find_depth0(m, i, end, ";")
        return end if s < 0 else s + 1

    def plain(self, i, end):
        e = self.stmt_end(i, end)
        self.stmt(i, e)
        return e

    def directives_before(self, off):
        """Conditional compilation is a branch between builds: an #else or #elif
        arm follows the #if's entry, and an #if with no #else also keeps the
        path that compiles none of it."""
        while self.pp_at < len(self.pp) and self.pp[self.pp_at][0] < off:
            k = self.pp[self.pp_at][1]
            self.pp_at += 1
            if k == "i":
                f = self.flow()
                self.alts.append([f, [], False])
                self.pend = list(f)
                continue
            if not self.alts:
                continue
            a = self.alts[-1]
            if k != "n":
                a[1] = a[1] + self.flow()
                a[2] = a[2] or k == "e"
                self.pend = list(a[0])
                continue
            f = self.flow() + a[1] + ([] if a[2] else a[0])
            self.alts.pop()
            for x in f:
                if x not in self.pend:
                    self.pend.append(x)

    def seq(self, i, end):
        while True:
            i = skip_space(self.mask, i)
            if i >= end:
                break
            self.directives_before(i)
            i = self.statement(i, end)
        self.directives_before(end)

    def statement(self, i, end):
        m, d = self.mask, self.d
        if i >= end:
            return end
        c = m[i]
        if c == "{":
            close = match_pair(m, i, "{", "}")
            if close < 0 or close - 1 > end:
                self.seq(i + 1, end)
                return end
            self.seq(i + 1, close - 1)
            return close
        if c == ";":
            return i + 1
        if d.lifetimes and c == "'":
            we = word_end(m, i + 1)
            colon = skip_space(m, we)
            if we > i + 1 and colon < end and m[colon] == ":":
                self.label_next = m[i + 1:we]
                return colon + 1
        we = word_end(m, i)
        if we == i:
            return self.plain(i, end)
        w = m[i:we]
        if w == "if":
            return self.parse_if(i, end)
        if w == "while":
            return self.parse_while(i, we, end)
        if w == "for":
            return self.parse_for(i, end) if d.paren else self.parse_while(i, we, end)
        if w == "loop" and not d.paren:
            return self.parse_loop(i, we, end)
        if w == "do" and d.paren:
            return self.parse_do(i, end)
        if w == "switch" and d.paren:
            return self.parse_switch(i, end)
        if w == "match" and not d.paren:
            return self.parse_match(i, end)
        if w == "try" and d.paren:
            return self.parse_try(i, end)
        if w in ("case", "default") and d.paren and self.switch_ctx() is not None:
            return self.parse_case(i, we, end, w == "default")
        if w == "return":
            e = self.plain(i, end)
            self.jump(self.rets, "return")
            return e
        if w in ("break", "continue"):
            return self.parse_jump(i, we, end, w == "break")
        if w == "goto" and d.paren:
            e = self.plain(i, end)
            a = skip_space(m, we)
            self.gotos.append((self.open, m[a:word_end(m, a)]))
            self.open = -1
            return e
        if w == "let" and not d.paren:
            return self.parse_let(i, end)
        after = skip_space(m, we)
        if w in d.block_words and after < end and m[after] == "{":
            return self.statement(after, end)
        if d.paren and after < end and m[after] == ":" and not (after + 1 < len(m) and m[after + 1] == ":"):
            self.open = self.node("label", i, w)
            self.labels[w] = self.open
            return after + 1
        if d.paren and after < end and m[after] == "(":
            pc = match_pair(m, after, "(", ")")
            b = skip_space(m, pc) if pc >= 0 else -1
            if 0 <= b < end and m[b] == "{":
                inflow = self.flow()
                head = self.block("macro", i, norm(self.src[i:pc]))
                self.link(inflow, head)
                self.pend = [(head, "true")]
                self.ctx.append([head, True, self.take_label(), [], [], False])
                resume = self.statement(b, end)
                self.finish_loop(head, [(head, "false")])
                return resume
        return self.plain(i, end)

    def switch_ctx(self):
        for cx in reversed(self.ctx):
            if not cx[1]:
                return cx
        return None

    def finish_loop(self, head, exits):
        self.link(self.flow(), head, "back")
        done = self.ctx.pop()
        self.link(done[4], head)
        self.pend = exits + done[3]

    def parse_if(self, i, end):
        st, a, b, body = condition(self.d, self.mask, i + 2, end)
        if st != 1:
            return self.plain(i, end)
        inflow = self.flow()
        entry, t, f = self.cond(a, b)
        self.link(inflow, entry)
        self.pend = t
        resume = self.statement(skip_space(self.mask, body), end)
        out = self.flow()
        j = skip_space(self.mask, resume)
        if j < end and is_word_at(self.mask, j, "else"):
            self.pend = f
            resume = self.statement(skip_space(self.mask, j + 4), end)
            out = out + self.flow()
        else:
            out = out + f
        self.pend = out
        return resume

    def parse_while(self, i, we, end):
        st, a, b, body = condition(self.d, self.mask, we, end)
        if st != 1:
            return self.plain(i, end)
        inflow = self.flow()
        entry, t, f = self.cond(a, b)
        self.link(inflow, entry)
        self.ctx.append([entry, True, self.take_label(), [], [], False])
        self.pend = t
        resume = self.statement(skip_space(self.mask, body), end)
        self.finish_loop(entry, f)
        return resume

    def parse_for(self, i, end):
        m = self.mask
        popen = skip_space(m, i + 3)
        pclose = match_pair(m, popen, "(", ")") if popen < end and m[popen] == "(" else -1
        if pclose < 0:
            return self.plain(i, end)
        s1 = find_depth0(m, popen + 1, pclose - 1, ";")
        if s1 < 0:
            return self.parse_while(i, i + 3, end)
        s2 = find_depth0(m, s1 + 1, pclose - 1, ";")
        if s2 < 0:
            return self.plain(i, end)
        if self.has_code(popen + 1, s1):
            self.stmt(popen + 1, s1)
        inflow = self.flow()
        if self.has_code(s1 + 1, s2):
            head, t, exits = self.cond(s1 + 1, s2)
            self.link(inflow, head)
            self.pend = t
        else:
            head = self.block("loop", i)
            self.link(inflow, head)
            self.pend = [(head, "fall")]
            exits = []
        self.ctx.append([head, True, self.take_label(), [], [], False])
        resume = self.statement(skip_space(m, pclose), end)
        if self.has_code(s2 + 1, pclose - 1):
            tail = self.flow() + self.ctx[-1][4]
            self.ctx[-1][4] = []
            self.open = self.block("stmt", s2 + 1)
            self.link(tail, self.open)
        self.finish_loop(head, exits)
        return resume

    def parse_do(self, i, end):
        head = self.node("do", i)
        self.pend = [(head, "fall")]
        self.ctx.append([head, True, self.take_label(), [], [], False])
        resume = self.statement(skip_space(self.mask, i + 2), end)
        w = skip_space(self.mask, resume)
        if w < end and is_word_at(self.mask, w, "while"):
            st, a, b, body = condition(self.d, self.mask, w + 5, end)
            if st == 1:
                tail = self.flow()
                done = self.ctx.pop()
                tail = tail + done[4]
                entry, t, f = self.cond(a, b)
                self.link(tail, entry)
                self.link(t, head, "back")
                self.pend = f + done[3]
                semi = skip_space(self.mask, body)
                return semi + 1 if semi < end and self.mask[semi] == ";" else body
        self.finish_loop(head, [])
        return resume

    def parse_loop(self, i, we, end):
        body = skip_space(self.mask, we)
        if body >= end or self.mask[body] != "{":
            return self.plain(i, end)
        head = self.node("loop", i)
        self.pend = [(head, "fall")]
        self.ctx.append([head, True, self.take_label(), [], [], False])
        resume = self.statement(body, end)
        self.finish_loop(head, [])
        return resume

    def parse_switch(self, i, end):
        st, a, b, body = condition(self.d, self.mask, i + 6, end)
        if st != 1:
            return self.plain(i, end)
        head = self.node("switch", i, norm(self.src[a:b]))
        self.ctx.append([head, False, "", [], [], False])
        resume = self.statement(skip_space(self.mask, body), end)
        out = self.flow()
        done = self.ctx.pop()
        out = out + done[3]
        if not done[5]:
            out.append((head, "nomatch"))
        self.pend = out
        return resume

    def parse_case(self, i, we, end, dflt):
        colon = we
        while True:
            colon = find_depth0(self.mask, colon, end, ":")
            if colon < 0:
                return self.plain(i, end)
            if colon + 1 < len(self.mask) and self.mask[colon + 1] == ":":
                colon += 2
                continue
            break
        sw = self.switch_ctx()
        bid = self.node("case", i, "default" if dflt else norm(self.src[we:colon]))
        self.edges.append((sw[0], bid, "default" if dflt else "case"))
        if dflt:
            sw[5] = True
        self.open = bid
        return colon + 1

    def parse_jump(self, i, we, end, brk):
        m = self.mask
        label = ""
        a = skip_space(m, we)
        if self.d.lifetimes and a < end and m[a] == "'":
            label = m[a + 1:word_end(m, a + 1)]
        target = None
        for cx in reversed(self.ctx):
            if (cx[2] != label) if label else (not brk and not cx[1]):
                continue
            target = cx
            break
        e = self.plain(i, end)
        if target is not None:
            self.jump(target[3] if brk else target[4], "break" if brk else "continue")
        return e

    def parse_match(self, i, end):
        st, a, b, body = condition(self.d, self.mask, i + 5, end)
        if st != 1:
            return self.plain(i, end)
        close = match_pair(self.mask, body, "{", "}")
        if close < 0:
            return self.plain(i, end)
        head = self.node("match", i, norm(self.src[a:b]))
        self.try_edge(head, a, b)
        out = []
        arms = match_arms(self.mask, body + 1, close - 1)
        for pa, pb, ba, bb in arms:
            self.open = self.block("arm", pa, norm(self.src[pa:pb]))
            self.edges.append((head, self.open, "arm"))
            self.statement(ba, bb)
            out = out + self.flow()
        if not arms:
            out.append((head, "fall"))
        self.pend = out
        return close

    def parse_let(self, i, end):
        m = self.mask
        e = self.stmt_end(i, end)
        eq = i
        while True:
            eq = find_depth0(m, eq, e, "=")
            if eq < 0:
                return self.plain(i, end)
            prev = m[eq - 1] if eq else " "
            nxt = m[eq + 1] if eq + 1 < len(m) else " "
            if prev in "=<>!" or nxt in "=>":
                eq += 1
                continue
            break
        r = skip_space(m, eq + 1)
        if m[r:word_end(m, r)] in ("if", "match", "loop", "unsafe"):
            self.stmt(i, eq + 1)
            self.statement(r, e)
            return e
        p = eq + 1
        while True:
            p = find_depth0(m, p, e, "else")
            if p < 0:
                break
            if not is_word_at(m, p, "else"):
                p += 1
                continue
            inflow = self.flow()
            entry, t, f = self.cond(i, p)
            self.link(inflow, entry)
            self.pend = f
            self.statement(skip_space(m, p + 4), e)
            out = self.flow()
            self.pend = t + out
            return e
        return self.plain(i, end)

    def parse_try(self, i, end):
        m = self.mask
        b = skip_space(m, i + 3)
        if b >= end or m[b] != "{":
            return self.plain(i, end)
        head = self.node("try", i)
        self.pend = [(head, "fall")]
        resume = self.statement(b, end)
        out = self.flow()
        while True:
            k = skip_space(m, resume)
            if k >= end or not is_word_at(m, k, "catch"):
                break
            p = skip_space(m, k + 5)
            pc = match_pair(m, p, "(", ")") if p < end and m[p] == "(" else -1
            if pc < 0:
                break
            self.open = self.block("handler", k, norm(self.src[p + 1:pc - 1]))
            self.edges.append((head, self.open, "handler"))
            resume = self.statement(skip_space(m, pc), end)
            out = out + self.flow()
        self.pend = out
        return resume

    def build(self, start, end):
        self.pp_at = bisect.bisect_left([o for o, _k in self.pp], start)
        self.block("entry", start)
        self.block("exit", end - 1)
        self.pend = [(0, "fall")]
        self.seq(start + 1, end - 1)
        self.link(self.flow(), 1)
        self.link(self.rets, 1)
        for frm, name in self.gotos:
            to = self.labels.get(name)
            self.edges.append((frm, 1 if to is None else to,
                               "goto-unresolved" if to is None else "goto"))


def extract_cfg(path: Path, lang=None) -> list[str]:
    """B and E rows for one file, without the file index, in artifact order."""
    d = dialect_for(path, lang)
    src = path.read_text(errors="replace")
    pp = []
    mask = mask_code(src, False, d, pp)
    text = mask_code(src, True, d)
    nl = [i for i, ch in enumerate(src) if ch == "\n"]
    rows = []
    for k, (start, end, name, _off) in enumerate(find_functions(mask, d)):
        if name == "<file>":
            continue
        g = Cfg(d, text, mask, nl, pp)
        g.build(start, end)
        rows += [f"B\t{k}\t{name}\t{b}\t{kind}\t{first}\t{last}\t{t}"
                 for b, (kind, first, last, t) in enumerate(g.blocks)]
        rows += [f"E\t{k}\t{name}\t{f}\t{to}\t{kind}" for f, to, kind in g.edges]
    return rows


DECL_KINDS = ("function", "enumerator")


def line_of(mask: str, off: int) -> int:
    return mask.count("\n", 0, off) + 1


def find_enumerators(mask: str) -> list[tuple[int, str, str]]:
    """(offset, kind, name) for every enumerator, by the shape of the list.

    An `enum { ... }` body is a comma-separated identifier list, so the names
    are readable without knowing a single type. An initialiser is skipped to
    the next comma rather than parsed -- its value is not a declaration."""
    out = []
    i = 0
    n = len(mask)
    while i + 4 < n:
        if not is_word_at(mask, i, "enum"):
            i += 1
            continue
        b = mask.find("{", i)
        if b < 0:
            break
        semi = mask.find(";", i)
        if 0 <= semi < b:              # `enum foo x;` -- the brace is elsewhere
            i += 4
            continue
        e = match_pair(mask, b, "{", "}")
        if e < 0:
            break
        j = b + 1
        expect = True
        while j < e:
            c = mask[j]
            if c == ",":
                expect = True
                j += 1
                continue
            if c == "=":
                while j < e and mask[j] != ",":
                    j += 1
                continue
            if expect and c in IDENT and not c.isdigit():
                k = j
                while k < e and mask[k] in IDENT:
                    k += 1
                out.append((j, "enumerator", mask[j:k]))
                expect = False
                j = k
                continue
            j += 1
        i = e
    return out


def find_declarations(mask: str, funcs) -> list[tuple[int, str, str]]:
    """(offset, kind, name), functions in body order then enumerators."""
    out = [(off if off >= 0 else start, "function", name)
           for start, _end, name, off in funcs if name != "<file>"]
    out += find_enumerators(mask)
    return out


def find_references(mask: str, funcs, known: set[str],
                    decl_offsets: set[int]) -> list[tuple[int, str, str]]:
    """(offset, enclosing function, name) wherever a KNOWN name is named again.

    Only names this scan declared: every other identifier is a local, a keyword
    or something outside the set, and none of the three says anything about
    whether what IS in the set is reached."""
    out = []
    i = 0
    n = len(mask)
    while i < n:
        c = mask[i]
        if c not in IDENT or c.isdigit() or (i and mask[i - 1] in IDENT):
            i += 1
            continue
        k = i
        while k < n and mask[k] in IDENT:
            k += 1
        name = mask[i:k]
        if name in known and i not in decl_offsets:
            func = "<file>"
            for start, end, fname, _off in funcs:
                if start <= i <= end:
                    func = fname
                    break
            out.append((i, func, name))
        i = k
    return out


def extract_declared(path: Path, lang=None) -> list[tuple[str, ...]]:
    """D and R rows for one file, in the order the artifact carries them."""
    d = dialect_for(path, lang)
    mask = mask_code(path.read_text(errors="replace"), False, d)
    funcs = find_functions(mask, d)
    decls = find_declarations(mask, funcs)
    known = {name for _off, _kind, name in decls}
    decl_offsets = {off for off, _kind, _name in decls}
    rows = [("D", str(line_of(mask, off)), kind, name)
            for off, kind, name in decls]
    rows += [("R", str(line_of(mask, off)), func, name)
             for off, func, name in find_references(mask, funcs, known,
                                                    decl_offsets)]
    return rows


def keep(row: Row, symbols: list[str]) -> bool:
    if not symbols:
        return True
    hay = row.guard + " " + " ".join(row.path)
    return any(s in hay for s in symbols)


def emit_rows(rows, symbols, out) -> None:
    for r in rows:
        if keep(r, symbols):
            out.write(r.tsv(" >> ".join(r.path) or "-") + "\n")


def emit_tree(rows, symbols, out) -> None:
    for r in rows:
        if keep(r, symbols):
            out.write(f"{r.line:6d}  {'  ' * r.depth}{r.kind} {r.guard}"
                      f"   [{r.func}]\n")


def run_diff(old: Path, new: Path, symbols: list[str]) -> int:
    """Set-difference the two guard sets THROUGH sublimation, never in Python."""
    sub = shutil.which("sublimation")
    if not sub:
        print("sublimation not found -- the diff is its set operations")
        return 2
    with tempfile.TemporaryDirectory() as td:
        paths = {}
        for tag, src in (("old", old), ("new", new)):
            rows = [r for r in extract(src) if keep(r, symbols)]
            f = Path(td) / f"{tag}.keys"
            f.write_text("".join(r.key() + "\n" for r in rows))
            paths[tag] = f
            print(f"{src.name}: {len(rows)} guards")

        for label, verb, stdin_side, arg_side in (
                ("guards only in " + old.name, "subtract", "old", "new"),
                ("guards only in " + new.name, "subtract", "new", "old"),
                ("guards in both", "intersect", "new", "old")):
            res = subprocess.run(
                [sub, verb, str(paths[arg_side])],
                stdin=paths[stdin_side].open("rb"),
                capture_output=True, text=True)
            body = res.stdout.rstrip("\n")
            count = len(body.split("\n")) if body else 0
            print(f"\n● {label}: {count}")
            if body:
                print(body)
    return 0


SELF_TEST_SRC = r'''
#define TIER_BATCH 2
/* if (commented) { } */
static int f(struct task_ctx *tctx)
{
	const char *s = "if (in_a_string) {";
	if (tctx->tier == TIER_BATCH) {
		if (tctx->runnable_count < 8)
			return 0;
	} else {
		return 2;
	}
	int k = (tctx && tctx->tier != TIER_BATCH) ? 1 : 0;
	while (k > 0) {
		k--;
	}
	return k;
}
'''


def self_test() -> int:
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "t.c"
        p.write_text(SELF_TEST_SRC)
        rows = extract(p)
    got = [(r.func, r.kind, r.guard, " >> ".join(r.path)) for r in rows]
    want = [
        ("f", "if", "tctx->tier == TIER_BATCH", ""),
        ("f", "if", "tctx->runnable_count < 8", "tctx->tier == TIER_BATCH"),
        ("f", "else", "!(tctx->tier == TIER_BATCH)", ""),
        ("f", "ternary", "(tctx && tctx->tier != TIER_BATCH)", ""),
        ("f", "while", "k > 0", ""),
    ]
    fails = 0
    if got != want:
        fails += 1
        print("● mismatch:")
        for g in got:
            print("   got  ", g)
        for w in want:
            print("   want ", w)
    checks = [
        ("comment not scanned", not any("commented" in g[2] for g in got)),
        ("string not scanned", not any("in_a_string" in g[2] for g in got)),
        ("macro left unexpanded", any("TIER_BATCH" in g[2] for g in got)),
        ("else negation present", any(g[1] == "else" for g in got)),
        ("nesting recorded", any(g[3] for g in got)),
    ]
    for name, ok in checks:
        print(f"   {'PASS' if ok else 'FAIL'}  {name}")
        fails += 0 if ok else 1
    print(f"\n● self-test: {'PASS' if not fails else str(fails) + ' FAILURE(S)'}")
    return 0 if not fails else 1


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Dominating condition on every branch, and each function's graph.")
    ap.add_argument("files", nargs="*", type=Path)
    ap.add_argument("--tree", action="store_true", help="indented, for reading")
    ap.add_argument("--symbols", default="",
                    help="comma-separated; keep rows whose guard or chain names one")
    ap.add_argument("--diff", nargs=2, type=Path, metavar=("OLD", "NEW"),
                    help="set-difference two guard sets through sublimation")
    ap.add_argument("--declared", action="store_true",
                    help="emit what each file declares and every place a "
                         "declared name is named again, instead of guards")
    ap.add_argument("--cfg", action="store_true",
                    help="emit each function's blocks and edges instead of guards")
    ap.add_argument("--lang", choices=[d.name for d in DIALECTS],
                    help="force a dialect; by default the file's extension picks it")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    symbols = [s for s in args.symbols.split(",") if s]
    if args.self_test:
        return self_test()
    if args.diff:
        return run_diff(args.diff[0], args.diff[1], symbols)
    if not args.files:
        ap.error("give a file, --diff OLD NEW, or --self-test")
    for f in args.files:
        if args.declared:
            for row in extract_declared(f, args.lang):
                sys.stdout.write("\t".join(row) + "\n")
            continue
        if args.cfg:
            for row in extract_cfg(f, args.lang):
                sys.stdout.write(row + "\n")
            continue
        rows = extract(f, args.lang)
        (emit_tree if args.tree else emit_rows)(rows, symbols, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.setrecursionlimit(20000)
    sys.exit(main())
