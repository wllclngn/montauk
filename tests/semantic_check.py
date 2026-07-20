#!/usr/bin/env python3
"""Semantic gate: no emitted gauge family may describe itself with a
placeholder or by echoing its own name.

Today this covers the population surface (every montauk_pop_* family must
have real HELP text); it grows to the full analyzer JSON gauge surface when
the GaugeSpec registry lands. The failure this pins: 45 of 75 analyzer
families once shipped with prom_help silently falling back to the family
name, and every population family shipped as the literal "population
analysis" -- descriptions nobody could act on, misreads nobody could catch.

Run:  python3 tests/semantic_check.py   (or via tests/run.py, gate layer)
"""
import os
import sys
import tempfile
from pathlib import Path

import gen_synthetic_prom as gen
import harness

ANALYZE = harness.MONTAUK_ANALYZE
note = harness.logger("semantic")


def main() -> int:
    if harness.missing_bins(ANALYZE):
        note(f"FAIL: missing {ANALYZE} -- build first")
        return 1
    with tempfile.TemporaryDirectory(prefix="montauk-semantic-") as td:
        archive = Path(td) / "arch"
        gen.write_archive(archive, versions=4, runs=2)
        cache = Path(td) / "cache"
        env = dict(os.environ, XDG_CACHE_HOME=str(cache))
        # Emit both surfaces: the pairwise families and the trajectory ones.
        for extra in ([], ["--trajectory"]):
            harness.run_text([str(ANALYZE), str(archive), "--by", "version",
                              "--seed", "1729", *extra], env=env, check=False)
        bad = []
        families = 0
        for prom in (cache / "montauk").glob("analysis-pop-*.prom"):
            for line in prom.read_text().splitlines():
                if not line.startswith("# HELP "):
                    continue
                families += 1
                _, _, rest = line.partition("# HELP ")
                name, _, help_text = rest.partition(" ")
                if help_text.strip() in ("", name, "population analysis"):
                    bad.append(name)
        if families == 0:
            note("FAIL: no HELP lines found (population emit broken?)")
            return 1
        if bad:
            note(f"FAIL: {len(bad)} placeholder/self-echo HELP line(s): "
                 + ", ".join(sorted(set(bad))))
            return 1
        note(f"PASS: {families} HELP line(s), all carry real descriptions")
    return 0


if __name__ == "__main__":
    sys.exit(main())
