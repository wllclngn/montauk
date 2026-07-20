#!/usr/bin/env python3
"""Gate for the shipped sublimation_signal API (learn/signal.c).

Builds libsublimation from the in-tree sources and the C harness test_signal.c
(which touches ONLY the public sublimation_signal API), then proves it against
numpy: the FFT vs numpy.fft.fft, and Spectral Residual vs a numpy reference of
the identical steps (saliency to tolerance, anomaly flags byte-exact), plus a
behavioral check that it flags an injected spike. signal.c holds the zero-warning
bar.

Deterministic: seeded numpy signals, reproducible byte for byte.
"""
import shutil
import subprocess
import sys
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
SUB_ROOT = HERE.parent
SRC_DIR = SUB_ROOT / "src"
BUILD = HERE / "_signal_build"
LIB = BUILD / "libsublimation.a"
CBIN = BUILD / "test_signal"


def note(m):
    print(f"[signal] {m}", flush=True)


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
        our = Path(s).name == "signal.c" and Path(s).parent.name == "learn"
        extra = ["-Wall", "-Wextra"] if our else []
        r = subprocess.run(base + extra + ["-c", s, "-o", str(obj)],
                           capture_output=True, text=True)
        if r.returncode != 0:
            note(f"FAIL: compile {Path(s).name}")
            sys.stdout.write(r.stderr)
            return False
        if our and r.stderr.strip():
            note("FAIL: learn/signal.c emitted warnings (zero-warning gate):")
            sys.stdout.write(r.stderr)
            return False
        objs.append(str(obj))
    subprocess.run(["ar", "rcs", str(LIB)] + objs, check=True)
    r = subprocess.run([cc, std, "-O2", "-march=native",
                        "-I", str(SRC_DIR / "include"), "-I", str(SRC_DIR),
                        str(HERE / "test_signal.c"), str(LIB), "-lm", "-o", str(CBIN)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        note("FAIL: link harness")
        sys.stdout.write(r.stderr)
        return False
    note(f"built libsublimation.a + harness via {Path(cc).name} "
         f"(signal.c: zero warnings)")
    return True


def run(mode_args, sig):
    payload = (f"{len(sig)}\n".encode() + " ".join(f"{v:.17g}" for v in sig).encode())
    r = subprocess.run([str(CBIN), *mode_args], input=payload, capture_output=True)
    if r.returncode != 0:
        raise RuntimeError(f"test_signal {mode_args}: {r.stderr.decode()}")
    return r.stdout.decode().strip().splitlines()


def sr_ref(x, q, tau, z):
    n = len(x)
    F = np.fft.fft(x)
    L = np.log(np.maximum(np.abs(F), 1e-8))
    P = np.angle(F)
    hw = q // 2
    AL = np.array([L[max(0, i - hw):min(n - 1, i + hw) + 1].mean() for i in range(n)])
    S = np.abs(np.fft.ifft(np.exp(L - AL) * np.exp(1j * P)))
    flags = np.zeros(n, int)
    for i in range(n):
        lo = max(0, i - z)
        sbar = S[lo:i].mean() if i > lo else S[i]
        flags[i] = 1 if (sbar > 0 and (S[i] - sbar) / sbar > tau) else 0
    return S, flags


def main():
    if not build():
        return 1
    rng = np.random.default_rng(1729)
    fails = 0

    note("fft vs numpy.fft.fft (power-of-two sizes)")
    for n in (256, 1024, 4096):
        x = rng.normal(size=n) + np.sin(np.arange(n) * 0.1)
        got = np.array([[float(t) for t in ln.split()] for ln in run(["fft"], x)])
        ref = np.fft.fft(x)
        ok = (np.allclose(got[:, 0], ref.real, rtol=1e-7, atol=1e-7)
              and np.allclose(got[:, 1], ref.imag, rtol=1e-7, atol=1e-7))
        note(f"  n={n:<5d} {'ok' if ok else 'DIVERGED'}")
        fails += not ok

    note("spectral residual: saliency vs numpy ref + exact flag parity")
    n = 512
    sig = np.sin(np.arange(n) * 0.08) + 0.05 * rng.normal(size=n)
    spike = 300
    sig[spike:spike + 3] += 4.0
    q, tau, z = 3, 3.0, 21
    out = run(["sr", str(q), str(tau), str(z)], sig)
    S = np.array([float(ln.split()[0]) for ln in out])
    flags = np.array([int(ln.split()[1]) for ln in out])
    Sref, fref = sr_ref(sig, q, tau, z)
    ok = np.allclose(S, Sref, rtol=1e-6, atol=1e-9)
    note(f"  saliency {'ok' if ok else 'DIVERGED'} (n={n})")
    fails += not ok
    ok = np.array_equal(flags, fref)
    note(f"  flags {'byte-exact' if ok else 'DIVERGED'} ({int(flags.sum())} anomalies)")
    fails += not ok

    note("behavioral: SR flags the injected spike")
    hit = bool(flags[spike - 2:spike + 5].any())
    note(f"  spike at {spike} {'flagged' if hit else 'MISSED'}")
    fails += not hit

    note("")
    if fails:
        note(f"GATE FAILED: {fails} check(s) diverged")
        return 1
    note("GATE PASSED: the shipped sublimation_signal API matches numpy.fft and "
         "the Spectral Residual reference, and detects the injected spike")
    return 0


if __name__ == "__main__":
    sys.exit(main())
