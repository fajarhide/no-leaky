#!/usr/bin/env python3
"""Local vault that maps data tokens back to their values, so nl-run can use a value the agent never saw.

Never printed, never read by the agent (the guard denies it). Entries expire 7 days after they were last seen.

Self-check: python3 vault.py --test
"""

import json
import os
import re
import sys
import time

VAULT_PATH = os.path.expanduser("~/.cache/no-leaky/vault.json")
TTL = 7 * 86400
TOKEN_RE = re.compile(r"\[(?:email|phone|nik|npwp|card|ip|account|name): k[0-9a-f]{8}\]")


def _load(path):
    try:
        with open(path) as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


class _Lock:
    def __init__(self, path):
        self.path = path + ".lock"

    def __enter__(self):
        import fcntl
        os.makedirs(os.path.dirname(self.path), mode=0o700, exist_ok=True)
        self.fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(self.fd, fcntl.LOCK_EX)

    def __exit__(self, *a):
        os.close(self.fd)


def remember(pairs, path=VAULT_PATH, now=None):
    """Merge {token: value} into the vault, refresh their expiry, drop expired entries."""
    if not pairs:
        return
    now = time.time() if now is None else now
    with _Lock(path):
        data = {t: e for t, e in _load(path).items() if isinstance(e, dict) and e.get("exp", 0) > now}
        for t, v in pairs.items():
            data[t] = {"v": v, "exp": now + TTL}
        tmp = f"{path}.{os.getpid()}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(data, f)
        os.replace(tmp, path)


def resolve(text, path=VAULT_PATH, now=None):
    """Replace every known token with its value. Returns (text, tokens it could not resolve)."""
    now = time.time() if now is None else now
    data = _load(path)
    missing = []

    def sub(m):
        e = data.get(m.group())
        if isinstance(e, dict) and e.get("exp", 0) > now:
            return e["v"]
        missing.append(m.group())
        return m.group()

    return TOKEN_RE.sub(sub, text), missing


def _writer(path, prefix, start):
    time.sleep(max(0.0, start - time.time()))  # all writers start together
    for i in range(50):
        remember({f"[email: k{prefix}{i:07x}]": f"v{prefix}{i}"}, path)


def test():
    import tempfile
    import threading

    bad = []

    def check(label, cond):
        if not cond:
            bad.append(label)

    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "cache", "vault.json")
        t1, t2 = "[email: k0000aaaa]", "[phone: k0000bbbb]"
        remember({t1: "first value", t2: "second value"}, path, now=1000)
        text, missing = resolve(f"x {t1} y {t2} z", path, now=1000)
        check("round trip", text == "x first value y second value z" and missing == [])
        check("mode 0600", (os.stat(path).st_mode & 0o777) == 0o600)

        unknown = "[nik: k0000cccc]"
        text, missing = resolve(f"a {unknown}", path, now=1000)
        check("unknown kept and listed", text == f"a {unknown}" and missing == [unknown])

        remember({t1: "first value"}, path, now=1000 + 6 * 86400)
        text, missing = resolve(f"{t1} {t2}", path, now=1000 + 8 * 86400)
        check("seen again stays, unseen expires", text.startswith("first value") and missing == [t2])

        check("TOKEN_RE", TOKEN_RE.findall(f"{t1}, [card: k1234abcd] [secret: openai, fp 1a2b3c4d]")
              == [t1, "[card: k1234abcd]"])

        shared = os.path.join(tmp, "shared.json")
        start = time.time() + 0.2
        writers = [threading.Thread(target=_writer, args=(shared, p, start)) for p in "abcdef01"]
        for w in writers:
            w.start()
        for w in writers:
            w.join()
        toks = " ".join(f"[email: k{p}{i:07x}]" for p in "abcdef01" for i in range(50))
        check("test tokens are real tokens", len(TOKEN_RE.findall(toks)) == 400)
        _, missing = resolve(toks, shared)
        check(f"concurrent writers keep all 400 ({400 - len(missing)} kept)", missing == [])

    if bad:
        print("WRONG:", *bad, sep="\n  ")
        sys.exit(1)
    print("ok: vault self-check passed")


if __name__ == "__main__":
    if "--test" in sys.argv:
        test()
