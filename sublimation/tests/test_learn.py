#!/usr/bin/env python3
"""Byte-parity gate for the shipped sublimation_learn API (learn/detect.c).

Builds libsublimation from the in-tree sources and the C harness test_learn.c
(which touches ONLY the public sublimation_learn API), then proves every
detector matches an independent reference: the statistics against numpy to a
double tolerance, and Half-Space Trees byte-exact against a splitmix64-shared
Python re-implementation. detect.c is held to the zero-warning gate.

Deterministic: seeded numpy corpora, reproducible byte for byte.
"""
import shutil
import subprocess
import sys
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
SUB_ROOT = HERE.parent
SRC_DIR = SUB_ROOT / "src"
BUILD = HERE / "_learn_build"
LIB = BUILD / "libsublimation.a"
CBIN = BUILD / "test_learn"


def note(m):
    print(f"[learn] {m}", flush=True)


def build():
    cc = shutil.which("clang") or shutil.which("cc") or shutil.which("gcc")
    if not cc:
        note("FAIL: no C compiler")
        return False
    std = "-std=c23"
    if subprocess.run([cc, std, "-fsyntax-only", "-x", "c", "-"],
                      input="int main(void){return 0;}", capture_output=True,
                      text=True).returncode != 0:
        std = "-std=c2x"
    BUILD.mkdir(exist_ok=True)
    base = [cc, std, "-O2", "-march=native", "-fPIC",
            "-I", str(SRC_DIR / "include"), "-I", str(SRC_DIR)]
    objs = []
    for s in sorted(str(p) for p in SRC_DIR.rglob("*.c")):
        obj = BUILD / (Path(s).parent.name + "_" + Path(s).stem + ".o")
        extra = ["-Wall", "-Wextra"] if Path(s).name == "detect.c" else []
        r = subprocess.run(base + extra + ["-c", s, "-o", str(obj)],
                           capture_output=True, text=True)
        if r.returncode != 0:
            note(f"FAIL: compile {Path(s).name}")
            sys.stdout.write(r.stderr)
            return False
        if Path(s).name == "detect.c" and r.stderr.strip():
            note("FAIL: detect.c emitted warnings (zero-warning gate):")
            sys.stdout.write(r.stderr)
            return False
        objs.append(str(obj))
    subprocess.run(["ar", "rcs", str(LIB)] + objs, check=True)
    r = subprocess.run([cc, std, "-O2", "-march=native",
                        "-I", str(SRC_DIR / "include"), "-I", str(SRC_DIR),
                        str(HERE / "test_learn.c"), str(LIB), "-lm", "-o", str(CBIN)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        note("FAIL: link harness")
        sys.stdout.write(r.stderr)
        return False
    note(f"built libsublimation.a + harness via {Path(cc).name} "
         f"(detect.c: zero warnings)")
    return True


def run(mode_args, X):
    hdr = f"{X.shape[0]} {X.shape[1]}\n".encode()
    body = " ".join(f"{v:.17g}" for v in X.ravel()).encode()
    r = subprocess.run([str(CBIN), *mode_args], input=hdr + body, capture_output=True)
    if r.returncode != 0:
        raise RuntimeError(f"test_learn {mode_args}: {r.stderr.decode()}")
    return r.stdout.decode().strip().splitlines()


MASK = (1 << 64) - 1


def sm_next(s):
    s[0] = (s[0] + 0x9E3779B97F4A7C15) & MASK
    z = s[0]
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & MASK
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & MASK
    return (z ^ (z >> 31)) & MASK


def sm_double(s):
    return (sm_next(s) >> 11) * (1.0 / 9007199254740992.0)


def hstrees_ref(X, T, H, psi, sl, seed):
    R, D = X.shape
    mn = X.min(axis=0)
    rng_col = X.max(axis=0) - mn
    xn = np.where(rng_col > 0, (X - mn) / np.where(rng_col > 0, rng_col, 1), 0.5)
    nodes = (1 << (H + 1)) - 1
    st = [seed & MASK]
    trees = []
    for _ in range(T):
        q = [0] * nodes
        p = [0.0] * nodes
        wmin = [0.0] * D
        wmax = [0.0] * D
        for j in range(D):
            sq = sm_double(st)
            mg = sq if sq > 1 - sq else 1 - sq
            wmin[j] = sq - 2 * mg
            wmax[j] = sq + 2 * mg

        def build(idx, depth):
            if depth == H:
                return
            qi = sm_next(st) % D
            pi = 0.5 * (wmin[qi] + wmax[qi])
            q[idx] = qi
            p[idx] = pi
            save = wmax[qi]
            wmax[qi] = pi
            build(2 * idx + 1, depth + 1)
            wmax[qi] = save
            save = wmin[qi]
            wmin[qi] = pi
            build(2 * idx + 2, depth + 1)
            wmin[qi] = save
        build(0, 0)
        trees.append({"q": q, "p": p, "r": [0] * nodes, "l": [0] * nodes})
    out = []
    for i in range(R):
        x = xn[i]
        score = 0
        for t in trees:
            idx, depth = 0, 0
            while True:
                rm = t["r"][idx]
                if depth == H or rm <= sl:
                    score += rm << depth
                    break
                idx = 2 * idx + 1 if x[t["q"][idx]] < t["p"][idx] else 2 * idx + 2
                depth += 1
        for t in trees:
            idx, depth = 0, 0
            while True:
                t["l"][idx] += 1
                if depth == H:
                    break
                idx = 2 * idx + 1 if x[t["q"][idx]] < t["p"][idx] else 2 * idx + 2
                depth += 1
        if (i + 1) % psi == 0:
            for t in trees:
                t["r"], t["l"] = t["l"], [0] * nodes
        out.append(score)
    return out


def close(name, got, want, rtol=1e-9, atol=1e-9):
    got = np.asarray(got, float)
    want = np.asarray(want, float)
    ok = got.shape == want.shape and np.allclose(got, want, rtol=rtol, atol=atol)
    note(f"  {name:14s} " + ("ok" if ok else "DIVERGED"))
    return ok


def main():
    if not build():
        return 1
    rng = np.random.default_rng(1729)
    fails = 0

    R, C = 600, 5
    A = rng.normal(size=(C, C))
    cov = A @ A.T + np.eye(C)
    X = rng.multivariate_normal(np.zeros(C), cov, size=R)
    X[50] += 12.0
    X[300, 2] += 20.0
    X[599] -= 15.0

    note("shipped sublimation_learn API vs independent references")
    got = np.array([[float(t) for t in ln.split()] for ln in run(["welford"], X)])
    fails += not close("col_moments", got, np.column_stack([X.mean(0), X.var(0)]))

    got = np.array([[float(t) for t in ln.split()] for ln in run(["standardize"], X)])
    fails += not close("standardize", got, (X - X.mean(0)) / np.sqrt(X.var(0)))

    got = [float(t) for t in run(["mad"], X)]
    med = np.median(X, 0)
    absdev = np.abs(X - med)
    mad = np.median(absdev, 0)
    scale = np.where(mad > 0, mad / 0.6745, 1.2533141373155003 * absdev.mean(0))
    modz = np.where(scale > 0, absdev / np.where(scale > 0, scale, 1), 0.0)
    fails += not close("mad_scores", got, modz.max(1))

    got = [float(t) for t in run(["ewma", "0.3"], X)]
    alpha, eps = 0.3, 1e-12
    level, var, ref = X[0].copy(), np.zeros(C), [0.0]
    for i in range(1, R):
        resid = X[i] - level
        ref.append(float((np.abs(resid) / np.sqrt(var + eps)).max()))
        var = (1 - alpha) * (var + alpha * resid * resid)
        level = level + alpha * resid
    fails += not close("ewma_scores", got, ref)

    got = [float(t) for t in run(["mahalanobis", "1e-3"], X)]
    S = np.cov(X, rowvar=False, bias=True) + 1e-3 * np.eye(C)
    dd = X - X.mean(0)
    ref = np.einsum("ij,jk,ik->i", dd, np.linalg.inv(S), dd)
    fails += not close("mahalanobis", got, ref, rtol=1e-7, atol=1e-7)

    got = [int(t) for t in run(["hstrees", "25", "12", "200", "25", "1729"], X)]
    ref = hstrees_ref(X, 25, 12, 200, 25, 1729)
    ok = got == ref
    note("  hstrees        " + ("byte-exact" if ok else "DIVERGED"))
    fails += not ok

    note("")
    if fails:
        note(f"GATE FAILED: {fails} detector(s) diverged")
        return 1
    note("GATE PASSED: the shipped sublimation_learn API matches every oracle "
         "(stats to 1e-7+, HS-Trees byte-exact)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
