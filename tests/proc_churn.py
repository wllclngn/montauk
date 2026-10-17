#!/usr/bin/env python3
"""Spawn short-lived processes fast enough that montauk flags PROC CHURN.

    tests/proc_churn.py [COUNT [DELAY [LIFETIME]]]

COUNT processes (default 64), DELAY seconds apart (default 0.02), each living
LIFETIME seconds (default 0.03). `3000 0.01` is about 100 a second for 30
seconds. Each child is a real exec of sleep(1), so the collectors see a fork,
an exec and an exit apiece; all are reaped before this exits.
"""
import subprocess
import sys
import time


def main():
    args = sys.argv[1:]
    try:
        count = int(args[0]) if len(args) > 0 else 64
        delay = float(args[1]) if len(args) > 1 else 0.02
        lifetime = float(args[2]) if len(args) > 2 else 0.03
    except ValueError:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    children = []
    for _ in range(count):
        children.append(subprocess.Popen(["sleep", str(lifetime)]))
        # Reap what has already exited, so a long run holds no zombie table.
        children = [c for c in children if c.poll() is None]
        time.sleep(delay)
    for c in children:
        c.wait()
    return 0


if __name__ == "__main__":
    sys.exit(main())
