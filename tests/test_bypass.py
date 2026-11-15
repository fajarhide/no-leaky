#!/usr/bin/env python3
"""Runs the guard over every command in bypass_corpus.txt and checks it against the expected outcome.

A `deny` line that the guard allows is a regression. A `gap` line that the guard now denies means the gap
closed: change it to `deny` so it stays closed.

Run: python3 tests/test_bypass.py
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "skills", "no-leaky-secrets", "scripts"))
import detect  # noqa: E402
import guard  # noqa: E402


def load(path):
    cases = []
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            line = line.rstrip("\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            parts = line.split(None, 1)
            if len(parts) != 2 or parts[0] not in ("deny", "gap"):
                sys.exit(f"bypass_corpus.txt line {n}: start with `deny` or `gap`, then the command")
            cases.append((n, parts[0], parts[1]))
    return cases


def main():
    cfg = dict(detect.DEFAULT_CONFIG)
    cases = load(os.path.join(HERE, "bypass_corpus.txt"))
    wrong = []
    for n, expect, cmd in cases:
        denied = bool(guard.check_command(cmd, cfg))
        if expect == "deny" and not denied:
            wrong.append(f"line {n}: allowed, expected deny: {cmd}")
        elif expect == "gap" and denied:
            wrong.append(f"line {n}: now denied, change gap to deny: {cmd}")
    if wrong:
        print("WRONG:", *wrong, sep="\n  ")
        sys.exit(1)
    gaps = sum(1 for c in cases if c[1] == "gap")
    print(f"ok: bypass corpus, {len(cases) - gaps} denied, {gaps} known gaps")


if __name__ == "__main__":
    main()
