#!/usr/bin/env python3
"""Shared secret detectors for scan, the output filter and the prompt guard.

Values are held in memory only to match them. Nothing here prints, logs or
writes a value; callers get spans, kinds and fingerprints.

Self-check: python3 detect.py --test
"""

import hashlib
import json
import random
import re
import string
import sys
from collections import namedtuple

Finding = namedtuple("Finding", "kind tier start end fp name")
TIER_RANK = {"certain": 0, "likely": 1, "public": 2}

# (kind, tier, pattern, group holding the value). Order breaks ties at equal span.
VENDOR = [
    ("anthropic", "certain", r"\bsk-ant-[A-Za-z0-9_\-]{20,}", 0),
    ("openai", "certain", r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{20,}", 0),
    ("aws", "certain", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", 0),
    ("github", "certain", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{60,}\b", 0),
    ("google", "certain", r"\bAIza[0-9A-Za-z_\-]{35}", 0),
    ("slack", "certain", r"\bxox[abposr]-[A-Za-z0-9-]{10,}", 0),
    ("npm", "certain", r"\bnpm_[A-Za-z0-9]{36}\b", 0),
    ("stripe", "certain", r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}", 0),
    ("stripe_publishable", "public", r"\bpk_(?:live|test)_[A-Za-z0-9]{16,}", 0),
    ("private_key", "certain",
     r"-----BEGIN [A-Z ]*PRIVATE KEY-----(?:.*?-----END [A-Z ]*PRIVATE KEY-----|.*\Z)", 0),
    ("jwt", "likely", r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}", 0),
    ("url_password", "likely", r"\b[a-z][a-z0-9+.-]*://[^\s:/@\"']+:([^\s@/\"']{8,})@", 1),
    ("bearer", "likely", r"(?i)\bbearer\s+([A-Za-z0-9._~+/-]{16,}=*)", 1),
]
VENDOR = [(k, t, re.compile(p, re.S), g) for k, t, p, g in VENDOR]

# A sensitive name, a separator, then a literal value. Code on the right is rejected in _code_like.
ASSIGN = re.compile(
    r"(?<![A-Za-z0-9_])(?P<name>[A-Za-z0-9_]*(?i:key|token|secret|passwd|password)[A-Za-z0-9_]*)"
    r"(?:\\?[\"'])?[ \t]*[:=][ \t]*(?:\\?[\"'])?(?P<val>[A-Za-z0-9_\-./+=:@!#$%^&*]{16,})"
)
NAME_BEFORE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)(?:\\?[\"'])?[ \t]*[:=][ \t]*(?:\\?[\"'])?$")
PUBLIC_NAME = re.compile(r"^(?:PUBLIC_|NEXT_PUBLIC_|VITE_|EXPO_PUBLIC_)|PUBLISHABLE|ANON|VAPID_PUBLIC|CLIENT_ID", re.I)
PLACEHOLDER = re.compile(r"changeme|example|placeholder|dummy|your_|your-|xxxx|<|>|\$\{", re.I)
FIXTURE = re.compile(r"example|sample|test|fixture|mock", re.I)
DOTTED = re.compile(r"^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+$")
WORDS = re.compile(r"^[A-Za-z_]+$")


def fingerprint(value):
    return hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()[:8]


def is_placeholder(value):
    return bool(PLACEHOLDER.search(value)) or value == "user:pass" or len(set(value)) == 1


def is_fixture_path(path):
    return any(FIXTURE.search(part) for part in re.split(r"[/\\]", path))


def _code_like(text, val, end):
    nxt = text[end:end + 1]
    return (nxt in ("(", "[") or val[0] in "/~$=" or val.startswith("./") or val.isdigit()
            or bool(DOTTED.match(val)) or bool(WORDS.match(val)))


def _name_before(text, start):
    m = NAME_BEFORE.search(text[max(0, start - 100):start])
    return m.group(1) if m else None


def find(text, known=frozenset()):
    cands = []  # (start, end, kind, tier, name, order)
    for order, (kind, tier, rx, group) in enumerate(VENDOR):
        for m in rx.finditer(text):
            s, e = m.span(group)
            if is_placeholder(text[s:e]):
                continue
            cands.append((s, e, kind, tier, None, order))
    for m in ASSIGN.finditer(text):
        s, e = m.span("val")
        val = m.group("val")
        if _code_like(text, val, e) or is_placeholder(val):
            continue
        cands.append((s, e, "assignment", "likely", m.group("name"), len(VENDOR)))
    cands.sort(key=lambda c: (-(c[1] - c[0]), TIER_RANK[c[3]], c[5]))
    taken = []
    for c in cands:
        if all(c[1] <= t[0] or c[0] >= t[1] for t in taken):
            taken.append(c)
    out = []
    for s, e, kind, tier, name, _ in sorted(taken):
        name = name or _name_before(text, s)
        if name and PUBLIC_NAME.search(name):
            tier = "public"
        out.append(Finding(kind, tier, s, e, fingerprint(text[s:e]), name))
    return out


def redact(text, known=frozenset()):
    findings = find(text, known)
    parts, last = [], 0
    for f in findings:
        if f.tier == "public":
            continue
        parts.append(text[last:f.start])
        parts.append(f"[secret: {f.kind}, fp {f.fp}]")
        last = f.end
    parts.append(text[last:])
    return "".join(parts), findings


def rand(n, alphabet=string.ascii_letters + string.digits):
    """Random test value that always mixes letters and digits."""
    chars = [random.choice(alphabet) for _ in range(n)]
    chars[0] = random.choice([c for c in alphabet if c.isalpha()] or alphabet)
    chars[-1] = random.choice(string.digits)
    return "".join(chars)


def fake(kind):
    """A generated value of the given kind, for tests only."""
    upper = string.ascii_uppercase + string.digits
    return {
        "aws": lambda: "AKIA" + rand(16, upper),
        "github": lambda: "ghp_" + rand(36),
        "anthropic": lambda: "sk-ant-api03-" + rand(40),
        "openai": lambda: "sk-proj-" + rand(40),
        "google": lambda: "AIza" + rand(35),
        "slack": lambda: "xoxb-" + rand(12, string.digits) + "-" + rand(24),
        "npm": lambda: "npm_" + rand(36),
        "stripe": lambda: "sk_live_" + rand(24),
        "jwt": lambda: "eyJ" + rand(20) + ".eyJ" + rand(30) + "." + rand(40),
        "private_key": lambda: "-----BEGIN OPENSSH PRIVATE KEY-----\n" + "\n".join(rand(64) for _ in range(3))
        + "\n-----END OPENSSH PRIVATE KEY-----",
    }[kind]()


def test():
    bad = []

    def check(label, cond):
        if not cond:
            bad.append(label)

    certain = ["aws", "github", "anthropic", "openai", "google", "slack", "npm", "stripe"]
    wrappers = [
        "KEY={v}",
        'KEY = "{v}"',
        "-FIREBASE_KEY = {v}",
        '+  "key": "{v}",',
        "JSON",
        'api_key: "{v}"',
        "Authorization: Bearer {v}",
    ]
    for kind in certain:
        v = fake(kind)
        for w in wrappers:
            text = json.dumps({"content": 'API_KEY="' + v + '"'}) if w == "JSON" else w.format(v=v)
            found = [f for f in find(text) if f.tier != "public"]
            label = f"{kind} in {w}"
            check(label + ": one finding", len(found) == 1)
            if found:
                f = found[0]
                check(label + ": kind", f.kind == kind)
                check(label + ": tier", f.tier == "certain")
                check(label + ": span", text[f.start:f.end] == v)
                check(label + ": fp", f.fp == fingerprint(v))
            new, _ = redact(text)
            check(label + ": redacted", v not in new and f"[secret: {kind}, fp {fingerprint(v)}]" in new)
        twice = find(f"a {v} b {v}")
        check(kind + ": twice", len(twice) == 2 and twice[0].fp == twice[1].fp)

    jwt = fake("jwt")
    found = find(f"Got {jwt} back")
    check("jwt bare", len(found) == 1 and found[0].kind == "jwt" and found[0].tier == "likely")

    pw = rand(20)
    text = f"DATABASE_URL=postgres://user:{pw}@db.internal:5432/app"
    found = find(text)
    check("url password one", len(found) == 1 and found[0].kind == "url_password")
    new, _ = redact(text)
    check("url password kept around", pw not in new and new.startswith("DATABASE_URL=postgres://user:[secret: url_password")
          and new.endswith("]@db.internal:5432/app"))

    pw = rand(20)
    found = find(f'DB_PASSWORD="{pw}"')
    check("assignment", len(found) == 1 and found[0].kind == "assignment" and found[0].name == "DB_PASSWORD"
          and found[0].tier == "likely")

    pem = fake("private_key")
    body = pem.splitlines()[1]
    text = json.dumps({"stdout": "before\n" + pem + "\nafter"})
    found = find(text)
    check("pem in json one", len(found) == 1 and found[0].kind == "private_key")
    new, _ = redact(text)
    check("pem in json redacted", body not in new and "before" in new and "after" in new)

    found = find(f"postgres://user:{jwt}@host/db")
    check("jwt inside url password: one finding", len(found) == 1)

    v = rand(24)
    found = find(f"NEXT_PUBLIC_API_KEY={v}")
    check("next public tier", len(found) == 1 and found[0].tier == "public")
    check("next public untouched", redact(f"NEXT_PUBLIC_API_KEY={v}")[0] == f"NEXT_PUBLIC_API_KEY={v}")
    pk = "pk_live_" + rand(24)
    found = find(f"STRIPE_PUBLISHABLE={pk}")
    check("pk_live public", len(found) == 1 and found[0].tier == "public")
    g = fake("google")
    found = find(f"NEXT_PUBLIC_MAPS_KEY={g}")
    check("vendor key under public name is public", len(found) == 1 and found[0].tier == "public")

    unchanged = [
        "SECRET_NAME = re.compile(",
        'API_TOKEN = re.compile(r"x")',
        "TOKEN_PATTERNS = [",
        "token = token.strip()",
        "TOKEN_LIMIT = 100000",
        'api_key = os.environ["API_KEY"]',
        "PASSWORD_FILE=/etc/app/pw",
        "openai==2.9.0",
        "DATABASE_URL=postgres://localhost:5432/app",
        "DATABASE_URL=postgres://user:pass@localhost/db",
        'KEY = ""',
        "key={item}",
        "SECRET_KEY_PATTERN = some_module.build_pattern_for_keys(x)",
        "AUTH_TOKEN = self.config.auth_token_value",
        "firstToken === 'abcdefghijklmnopqrstuv'",
        "api_key: str = field(default_factory=load_api_key)",
        "API_KEY=changeme",
        "API_KEY=user:pass",
        "API_KEY=xxxxxxxxxxxxxxxxxxxx",
        "API_KEY=<your-token-here-please>",
        "API_KEY=${API_KEY}",
        "API_KEY=your_api_key_goes_here",
        "export TOKEN=$(cat ~/.token-file-somewhere)",
    ]
    for text in unchanged:
        check("unchanged: " + text, redact(text)[0] == text)

    check("placeholder changeme", is_placeholder("changeme-now-please-1234"))
    check("placeholder repeated", is_placeholder("a" * 30))
    check("not placeholder", not is_placeholder(rand(24)))
    check("fixture path", is_fixture_path("/repo/tests/fixtures/keys.txt"))
    check("fixture example env", is_fixture_path("/repo/.env.example"))
    check("not fixture", not is_fixture_path("/repo/app/.env"))
    check("fp shape", len(fingerprint("x")) == 8 and all(c in "0123456789abcdef" for c in fingerprint("x")))

    if bad:
        print("WRONG:", *bad, sep="\n  ")
        sys.exit(1)
    print("ok: detect self-check passed")


if __name__ == "__main__":
    if "--test" in sys.argv:
        test()
