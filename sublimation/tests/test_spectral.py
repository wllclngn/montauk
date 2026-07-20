#!/usr/bin/env python3
"""Gate for the shipped sublimation_spectral API (learn/spectral.c).

Builds libsublimation from the in-tree sources and the C harness test_spectral.c
(which touches ONLY the public sublimation_spectral API), then proves it against
numpy: eigenvalues vs eigvalsh, the reconstruction vs the original (which proves
the eigenvectors, sign- and basis-ambiguous otherwise), effective resistance vs
the numpy pseudoinverse (basis-invariant, so an exact numeric gate), the Fiedler
value and partition count, and spectral clustering behaviorally. spectral.c is
held to the zero-warning bar.

Deterministic: seeded numpy inputs, reproducible byte for byte.
"""
import shutil
import subprocess
import sys
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
SUB_ROOT = HERE.parent
SRC_DIR = SUB_ROOT / "src"
BUILD = HERE / "_spectral_build"
LIB = BUILD / "libsublimation.a"
CBIN = BUILD / "test_spectral"


def note(m):
    print(f"[spectral] {m}", flush=True)


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
        # Zero-warning gate on the learn-lane spectral.c only, not the existing
        # sort-fallback src/spectral.c (whose C23-attribute warnings are benign).
        our = Path(s).name == "spectral.c" and Path(s).parent.name == "learn"
        extra = ["-Wall", "-Wextra"] if our else []
        r = subprocess.run(base + extra + ["-c", s, "-o", str(obj)],
                           capture_output=True, text=True)
        if r.returncode != 0:
            note(f"FAIL: compile {Path(s).name}")
            sys.stdout.write(r.stderr)
            return False
        if our and r.stderr.strip():
            note("FAIL: learn/spectral.c emitted warnings (zero-warning gate):")
            sys.stdout.write(r.stderr)
            return False
        objs.append(str(obj))
    subprocess.run(["ar", "rcs", str(LIB)] + objs, check=True)
    r = subprocess.run([cc, std, "-O2", "-march=native",
                        "-I", str(SRC_DIR / "include"), "-I", str(SRC_DIR),
                        str(HERE / "test_spectral.c"), str(LIB), "-lm", "-o", str(CBIN)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        note("FAIL: link harness")
        sys.stdout.write(r.stderr)
        return False
    note(f"built libsublimation.a + harness via {Path(cc).name} "
         f"(spectral.c: zero warnings)")
    return True


def run(mode_args, M):
    hdr = f"{M.shape[0]} {M.shape[1]}\n".encode()
    body = " ".join(f"{v:.17g}" for v in M.ravel()).encode()
    r = subprocess.run([str(CBIN), *mode_args], input=hdr + body, capture_output=True)
    if r.returncode != 0:
        raise RuntimeError(f"test_spectral {mode_args}: {r.stderr.decode()}")
    return r.stdout.decode().strip().splitlines()


def main():
    if not build():
        return 1
    rng = np.random.default_rng(1729)
    fails = 0

    A = rng.normal(size=(10, 10))
    A = (A + A.T) / 2.0
    note("eigh: eigenvalues vs numpy.linalg.eigvalsh")
    got = np.array([float(t) for t in run(["eigval"], A)])
    ref = np.sort(np.linalg.eigvalsh(A))
    ok = np.allclose(got, ref, rtol=1e-8, atol=1e-8)
    note(f"  eigenvalues {'ok' if ok else 'DIVERGED'} (n={len(got)})")
    fails += not ok

    note("eigh: reconstruction V diag(eval) V^T vs original")
    R = np.array([[float(t) for t in ln.split()] for ln in run(["recon"], A)])
    ok = np.allclose(R, A, rtol=1e-8, atol=1e-8)
    note(f"  reconstruction {'ok' if ok else 'DIVERGED'} (max|d|={np.max(np.abs(R-A)):.1e})")
    fails += not ok

    W = np.abs(rng.normal(size=(9, 9)))
    W = (W + W.T) / 2.0
    np.fill_diagonal(W, 0.0)
    note("effective_resistance vs numpy pseudoinverse")
    got = np.array([[float(t) for t in ln.split()] for ln in run(["reff"], W)])
    L = np.diag(W.sum(1)) - W
    Lp = np.linalg.pinv(L)
    dd = np.diag(Lp)
    ref = dd[:, None] + dd[None, :] - 2 * Lp
    ok = np.allclose(got, ref, rtol=1e-6, atol=1e-6)
    note(f"  effective resistance {'ok' if ok else 'DIVERGED'} (n={W.shape[0]})")
    fails += not ok

    note("fiedler (lambda2, partitions) vs numpy")
    out = run(["fiedler"], W)[0].split()
    lam2, parts = float(out[0]), int(out[1])
    evals = np.sort(np.linalg.eigvalsh(L))
    ref_parts = int(np.argmax(np.diff(evals))) + 1
    ok = abs(lam2 - evals[1]) < 1e-6 and parts == ref_parts
    note(f"  lambda2={lam2:.6g} (ref {evals[1]:.6g}), partitions={parts} "
         f"(ref {ref_parts}) {'ok' if ok else 'DIVERGED'}")
    fails += not ok

    note("spectral_cluster behavioral: two separated blobs split cleanly")
    b0 = rng.normal(loc=[0, 0], scale=0.35, size=(25, 2))
    b1 = rng.normal(loc=[6, 6], scale=0.35, size=(25, 2))
    pts = np.vstack([b0, b1])
    truth = np.array([0] * 25 + [1] * 25)
    d2 = ((pts[:, None, :] - pts[None, :, :]) ** 2).sum(-1)
    sigma = np.sqrt(np.median(d2[d2 > 0]))
    Wc = np.exp(-d2 / (2 * sigma * sigma))
    np.fill_diagonal(Wc, 0.0)
    lab = np.array([int(t) for t in run(["cluster", "2", "1729"], Wc)])
    purity = sum(np.bincount(truth[lab == c]).max() for c in np.unique(lab)) / len(truth)
    ok = purity >= 0.99
    note(f"  purity {purity:.2f} {'ok' if ok else 'FAIL'}")
    fails += not ok

    note("")
    if fails:
        note(f"GATE FAILED: {fails} check(s) diverged")
        return 1
    note("GATE PASSED: the shipped sublimation_spectral API matches numpy "
         "(eigh, effective resistance, Fiedler) and clusters cleanly")
    return 0


if __name__ == "__main__":
    sys.exit(main())
