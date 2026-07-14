#!/usr/bin/env python3
"""Deterministic synthetic .prom archive generator for the population gates.

Emits an archive shaped like a real bench history: V versions x R runs, a
label grid of cells, gauge families plus one histogram family, and ONE
designated family carrying an injected +50% mean shift at a known version
boundary. Everything derives from the seed; no wall clock, no randomness
outside random.Random(seed), so the gates can assert byte-identical reruns.

Used by tests/pop_gate.py, tests/semantic_check.py and tests/perf_gate.py;
runnable standalone for hand experiments:

    python3 tests/gen_synthetic_prom.py OUTDIR [--files N]
"""
import argparse
import random
from pathlib import Path

# The boundary the shifted family jumps at, exposed for the gates' asserts.
SHIFT_AT = 6            # versions >= 1.<SHIFT_AT>.0 carry the +50% shift
SHIFTED_FAMILY = "gate_lat_p99_us"
STABLE_FAMILY = "gate_rss_kb"
HIST_FAMILY = "gate_lat_hist_us"


def write_archive(outdir: Path, versions: int = 10, runs: int = 3,
                  cores: tuple = (2, 4), seed: int = 42) -> int:
    """Write the archive; returns the number of files written."""
    outdir.mkdir(parents=True, exist_ok=True)
    rng = random.Random(seed)
    written = 0
    for vi in range(1, versions + 1):
        ver = f"1.{vi}.0"
        for run in range(runs):
            lines = [
                "# TYPE gate_info gauge",
                f'gate_info{{version="{ver}",git_commit="c{vi:03d}"}} 1',
                f"# TYPE {HIST_FAMILY} histogram",
            ]
            for c in cores:
                base = 100.0 if vi < SHIFT_AT else 150.0
                lat = base * (1 + 0.05 * rng.random()) * (1 + 0.1 * (c == 4))
                lines.append(f'{SHIFTED_FAMILY}{{cores="{c}"}} {lat:.2f}')
                rss = 50.0 * (1 + 0.05 * rng.random())
                lines.append(f'{STABLE_FAMILY}{{cores="{c}"}} {rss:.2f}')
                # A small cumulative-bucket histogram so Path A (--full) has
                # within-run distributions to reconstruct.
                b1 = 10 + rng.randrange(5)
                b2 = b1 + 5 + rng.randrange(5)
                b3 = b2 + 2
                lines.append(f'{HIST_FAMILY}_bucket{{cores="{c}",le="100"}} {b1}')
                lines.append(f'{HIST_FAMILY}_bucket{{cores="{c}",le="200"}} {b2}')
                lines.append(f'{HIST_FAMILY}_bucket{{cores="{c}",le="+Inf"}} {b3}')
            path = outdir / f"{ver}-2026{vi:02d}01-{run:06d}.prom"
            path.write_text("\n".join(lines) + "\n")
            written += 1
    return written


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("outdir", type=Path)
    ap.add_argument("--versions", type=int, default=10)
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()
    n = write_archive(args.outdir, versions=args.versions, runs=args.runs,
                      seed=args.seed)
    print(f"files written: {n}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
