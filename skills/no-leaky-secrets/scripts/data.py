#!/usr/bin/env python3
"""Personal and business data as keyed tokens: [email: k3f9a01c].

The agent sees the token, never the value. The fingerprint is an HMAC under a key that never leaves this
machine, because an email or a phone number is guessable and a plain hash of it could be reversed.

Self-check: python3 data.py --test
"""

import hashlib
import hmac
import os
import random
import re
import sys
import time
from collections import namedtuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import detect  # noqa: E402

KEY_PATH = os.path.expanduser("~/.config/no-leaky/data.key")
DataFinding = namedtuple("DataFinding", "kind start end token")
PRIORITY = ["email", "account", "npwp", "nik", "card", "phone", "ip", "name"]

EMAIL = re.compile(r"(?<![\w.%+-])([A-Za-z0-9._%+-]+)@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.([A-Za-z]{2,24}))(?![\w-])")
SKIP_TLD = {"local", "internal", "invalid", "test", "example", "localhost", "png", "jpg", "jpeg", "gif", "svg",
            "webp", "js", "ts", "css", "py", "md", "json"}
SKIP_DOMAIN = {"example.com", "example.org", "example.net"}
PHONE_INTL = re.compile(r"(?<![\w+-])\+\d(?:[ -]?\d){6,14}(?![\w-])")
PHONE_ID = re.compile(r"(?<![\w+-])08[1-9](?:[ -]?\d){7,10}(?![\w-])")
DIGITS16 = re.compile(r"(?<![\w-])\d{16}(?![\w-])")
NPWP_FMT = re.compile(r"(?<!\d)\d{2}\.\d{3}\.\d{3}\.\d-\d{3}\.\d{3}(?!\d)")
NPWP_BARE = re.compile(r"(?<![\w-])\d{15,16}(?![\w-])")
CARD = re.compile(r"(?<![\w-])(?:\d{13,19}|\d{4}(?:[ -]\d{4}){2}[ -]\d{1,7}|\d{4}[ -]\d{6}[ -]\d{4,5})(?![\w-])")
IP = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\d|\.\d)")
ACCOUNT = re.compile(r"(?<![\w-])\d{12}(?![\w-])")
ACCOUNT_NEAR = re.compile(r"(?i)arn:|account|owner")
LONG_DIGITS = re.compile(r"\d{7}|\d{3,4}[ -]\d{3,4}[ -]\d{3,4}|\+\d|\d{4}[ -]\d{6}|\d{3}\.\d-\d{3}")
DOTTED_DIGITS = re.compile(r"\d\.\d{1,3}\.\d")
VERSION_NEAR = re.compile(r"version|==|>=|<=|~=", re.I)
PROVINCES = {11, 12, 13, 14, 15, 16, 17, 18, 19, 21, 31, 32, 33, 34, 35, 36, 51, 52, 53, 61, 62, 63, 64, 65,
             71, 72, 73, 74, 75, 76, 81, 82, 91, 92, 93, 94, 95, 96, 97}
CARD_PREFIX = re.compile(r"^(?:4|5[1-5]|2(?:22[1-9]|2[3-9]\d|[3-6]\d\d|7[01]\d|720)|3[457]|6011|65)")
DOC_NETS = ("192.0.2.", "198.51.100.", "203.0.113.")


def _read_key(path):
    with open(path, "rb") as f:
        key = f.read()
    if len(key) != 32:
        raise ValueError(f"no-leaky: {path} is damaged; delete it to make a new one")
    return key


def load_key(path=KEY_PATH):
    """The local HMAC key, created on first use with mode 0600. A damaged key raises instead of turning
    protection off quietly."""
    try:
        return _read_key(path)
    except FileNotFoundError:
        pass
    import tempfile
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path))  # 0600
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(os.urandom(32))
            f.flush()
            os.fsync(f.fileno())
        try:
            os.link(tmp, path)  # atomic and never overwrites: a reader sees no key or a whole one
        except FileExistsError:
            pass
    finally:
        os.unlink(tmp)
    return _read_key(path)


def normalize(kind, value):
    if kind in ("email", "name"):
        return value.lower()
    if kind == "phone":
        d = re.sub(r"\D", "", value)
        return "+" + ("62" + d[1:] if d.startswith("0") else d)
    if kind == "ip":
        return value
    return re.sub(r"\D", "", value)


def token(kind, value, key):
    h = hmac.new(key, normalize(kind, value).encode(), hashlib.sha256).hexdigest()[:12]
    return f"[{kind}: k{h}]"


def _luhn(d):
    total = 0
    for i, c in enumerate(reversed(d)):
        n = int(c)
        if i % 2:
            n = n * 2 - 9 if n > 4 else n * 2
        total += n
    return total % 10 == 0


def _nik(d):
    if len(d) != 16 or int(d[:2]) not in PROVINCES or d[2:4] == "00" or d[4:6] == "00" or d[12:] == "0000":
        return False
    day, month = int(d[6:8]), int(d[8:10])
    return (1 <= day <= 31 or 41 <= day <= 71) and 1 <= month <= 12


TARGET_WORDS = {"ssh", "scp", "sftp", "mosh", "ping", "ping6", "telnet", "nc", "ncat", "host", "hostname", "curl",
                "wget", "dig", "nslookup", "traceroute", "mtr", "rsync", "psql", "mysql", "redis-cli"}


def _target(text, s):
    """True when the word before the token holding the match is a command that connects to it (owner decision:
    command targets stay readable so ssh and curl keep working)."""
    a = s
    while a > 0 and not text[a - 1].isspace():
        a -= 1
    b = a
    while b > 0 and text[b - 1].isspace() and text[b - 1] != "\n":
        b -= 1
    end = b
    while b > 0 and not text[b - 1].isspace():
        b -= 1
    return os.path.basename(text[b:end].strip("$#>`'\"(").lower()) in TARGET_WORDS


def _in_path(text, s, e):
    """True when the match sits in a path, URL, git remote or user@host: token."""
    a = s
    while a > 0 and not text[a - 1].isspace() and text[a - 1] not in "\"'`(<":
        a -= 1
    b = e
    while b < len(text) and not text[b].isspace() and text[b] not in "\"'`)>":
        b += 1
    word = text[a:b]
    return "/" in word or word.startswith("~") or "://" in word or bool(re.match(r"\S+@\S+:", word))


def _candidates(text, cfg):
    has_long = LONG_DIGITS.search(text) is not None
    if "@" in text:
        yield from _emails(text)
    if has_long:
        yield from _numbers(text)
    if "." in text and DOTTED_DIGITS.search(text):
        yield from _ips(text)
    if cfg.get("internal_names"):
        yield from _names(text, cfg)


def _emails(text):
    for m in EMAIL.finditer(text):
        local, domain, tld = m.group(1), m.group(2).lower(), m.group(3).lower()
        if tld in SKIP_TLD or domain in SKIP_DOMAIN or local.lower().startswith(("noreply", "no-reply")):
            continue
        if re.match(r":[\w~./-]", text[m.end():m.end() + 2]):  # git@host:org/repo is a remote, not an address
            continue
        yield "email", m.start(), m.end()


NUM_RUN = re.compile(r"\+?\d[\d .-]{5,}\d")


def _numbers(text):
    """Number kinds, searched only inside runs of digits and separators: one sweep over a large output
    instead of seven."""
    has_npwp = "npwp" in text.lower()
    for w in NUM_RUN.finditer(text):
        s, e = w.start(), min(len(text), w.end() + 1)  # one char past the run so lookaheads see it
        for rx in (PHONE_INTL, PHONE_ID):
            for m in rx.finditer(text, s, e):
                yield "phone", m.start(), m.end()
        for m in DIGITS16.finditer(text, s, e):
            if _nik(m.group()):
                yield "nik", m.start(), m.end()
        for m in NPWP_FMT.finditer(text, s, e):
            yield "npwp", m.start(), m.end()
        if has_npwp:
            for m in NPWP_BARE.finditer(text, s, e):
                if "npwp" in text[max(0, m.start() - 20):m.start()].lower():
                    yield "npwp", m.start(), m.end()
        for m in CARD.finditer(text, s, e):
            d = re.sub(r"\D", "", m.group())
            if 13 <= len(d) <= 19 and CARD_PREFIX.match(d) and _luhn(d) and not _nik(d):
                yield "card", m.start(), m.end()
        for m in ACCOUNT.finditer(text, s, e):
            if ACCOUNT_NEAR.search(text[max(0, m.start() - 40):m.start()]):
                yield "account", m.start(), m.end()


def _ips(text):
    for m in IP.finditer(text):
        parts = m.group().split(".")
        if any(int(p) > 255 for p in parts):
            continue
        ip = m.group()
        if ip.startswith("127.") or ip in ("0.0.0.0", "255.255.255.255") or ip.startswith(DOC_NETS):
            continue
        before = text[max(0, m.start() - 10):m.start()]
        if before[-1:] in ("v", "V", "@") or VERSION_NEAR.search(before):
            continue
        if not _in_path(text, m.start(), m.end()) and not _target(text, m.start()):
            yield "ip", m.start(), m.end()


def _names(text, cfg):
    for name in cfg.get("internal_names") or []:
        if not name:
            continue
        for m in re.finditer(r"(?<![A-Za-z0-9])" + re.escape(name) + r"(?![A-Za-z0-9])", text, re.I):
            if not _in_path(text, m.start(), m.end()) and not _target(text, m.start()):
                yield "name", m.start(), m.end()


def find_data(text, cfg, key, skip=()):
    """Non-overlapping data findings, sorted by position."""
    allow = {normalize(k, a) for a in cfg.get("data_allow") or [] for k in PRIORITY}
    cands = sorted(_candidates(text, cfg), key=lambda c: (c[1], -(c[2] - c[1]), PRIORITY.index(c[0])))
    out, last = [], -1
    for kind, s, e in cands:
        if s < last or any(s < b and e > a for a, b in skip):
            continue
        value = text[s:e]
        if normalize(kind, value) in allow:
            continue
        out.append(DataFinding(kind, s, e, token(kind, value, key)))
        last = e
    return out


def tokenize(text, cfg, key, skip=()):
    """Replace every finding with its token. Returns (new text, findings, {token: value as written})."""
    found = find_data(text, cfg, key, skip)
    if not found:
        return text, [], {}
    parts, pos, pairs = [], 0, {}
    for f in found:
        parts += [text[pos:f.start], f.token]
        pairs[f.token] = text[f.start:f.end]
        pos = f.end
    parts.append(text[pos:])
    return "".join(parts), found, pairs


def fake_data(kind):
    """A random value of a kind, valid enough to be detected. For tests and benches only."""
    r = random.SystemRandom()
    digits = lambda n: "".join(r.choice("0123456789") for _ in range(n))  # noqa: E731
    if kind == "email":
        return detect.rand(8).lower() + "@" + detect.rand(6).lower() + ".co.id"
    if kind == "phone":
        return "081" + digits(9)
    if kind == "nik":
        day = r.randint(1, 28) + r.choice((0, 40))
        return (f"{r.choice(sorted(PROVINCES))}{r.randint(1, 70):02d}{r.randint(1, 40):02d}{day:02d}"
                f"{r.randint(1, 12):02d}{r.randint(0, 99):02d}{r.randint(1, 9999):04d}")
    if kind == "npwp":
        d = digits(15)
        return f"{d[:2]}.{d[2:5]}.{d[5:8]}.{d[8]}-{d[9:12]}.{d[12:]}"
    if kind == "card":
        body = "4" + digits(14)
        for c in "0123456789":
            if _luhn(body + c):
                return body + c
    if kind == "ip":
        return f"10.{r.randint(0, 255)}.{r.randint(0, 255)}.{r.randint(1, 254)}"
    if kind == "account":
        return str(r.randint(1, 9)) + digits(11)
    raise ValueError(kind)


def test():
    bad = []

    def check(label, cond):
        if not cond:
            bad.append(label)

    key = os.urandom(32)
    cfg = dict(detect.DEFAULT_CONFIG, internal_names=["orgx"])
    tok = re.compile(r"^\[(email|phone|nik|npwp|card|ip|account|name): k[0-9a-f]{12}\]$")
    v = {k: fake_data(k) for k in ("email", "phone", "nik", "npwp", "card", "ip", "account")}

    text = (f"contact {v['email']} or {v['phone']}, nik {v['nik']}, npwp {v['npwp']}, card {v['card']}, "
            f"server {v['ip']} refused, arn:aws:iam::{v['account']}:role/x, by the orgx team")
    new, found, pairs = tokenize(text, cfg, key)
    check("every kind found", {f.kind for f in found} == {"email", "phone", "nik", "npwp", "card", "ip", "account", "name"})
    check("tokens well formed", all(tok.match(f.token) for f in found))
    check("no value left", not any(x in new for x in v.values()) and "orgx" not in new)
    check("pairs map tokens back", all(pairs[f.token] in text for f in found))
    check("rest kept", new.startswith("contact [email: k") and new.endswith(" team"))

    for clean in ('user_email = row["email"]', "phone_number = models.CharField(max_length=20)",
                  "requests==2.31.0", "release v1.2.3.4", "order 4111111111111112", "ts 1731400000000",
                  "icon x@2x.png", "alice@example.com", "203.0.113.10 and 127.0.0.1",
                  '"sessionId":"3f2a8c41-4123-5678-9012-1234567890ab"', "trace 0812-3456-7890-abcd-ef",
                  "id 9b1e-4532-0151-1283-0366-f00d", "uuid 00000000-4539-1488-0343-646700000000"):
        check(f"left alone: {clean}", find_data(clean, cfg, key) == [])

    body = "41234567890123"
    d15 = next(body + c for c in "0123456789" if _luhn(body + c))
    uuid = f'"sessionId":"8c41e{d15[:3]}-{d15[3:7]}-{d15[7:11]}-{d15[11:]}abcdef12"'
    check("Luhn-valid digits inside a UUID are not a card", find_data(uuid, cfg, key) == [])

    local, domain = v["email"].split("@")
    check("email case", token("email", v["email"], key) == token("email", local.upper() + "@" + domain.upper(), key))
    d = v["phone"][1:]
    spaced = f"+62 {d[:3]} {d[3:7]} {d[7:]}"
    dashed = f"0{d[:3]}-{d[3:7]}-{d[7:]}"
    found_spaced = find_data(f"call {spaced} now", cfg, key)
    found_dashed = find_data(f"call {dashed} now", cfg, key)
    check("phone spellings agree", found_spaced and found_dashed and found_spaced[0].token == found_dashed[0].token
          == token("phone", v["phone"], key))
    c = v["card"]
    grouped = " ".join(c[i:i + 4] for i in range(0, 16, 4))
    fg = find_data(f"paid with {grouped} today", cfg, key)
    check("card spellings agree", fg and fg[0].token == token("card", c, key))

    check("prefilter skips dates", not LONG_DIGITS.search("2026-11-12T10:00:00Z took 12ms"))
    amex = "378282246310005"
    check("amex grouped found", [f.kind for f in find_data(f"amex {amex[:4]} {amex[4:10]} {amex[10:]} ok", cfg, key)] == ["card"])

    # review 6, 8, 9
    ip = v["ip"]
    check("ip at a sentence end found", [f.kind for f in find_data(f"connect to {ip}.", cfg, key)] == ["ip"])
    check("email before a colon found", [f.kind for f in find_data(f"user={v['email']}: login failed", cfg, key)] == ["email"])
    for target in (f"ssh {ip}", f"Host {ip}", "ping orgx-db", f"curl {ip}:8080"):
        check(f"command target left alone: {target}", find_data(target, cfg, key) == [])
    with __import__("tempfile").TemporaryDirectory() as tmp:
        empty = os.path.join(tmp, "data.key")
        open(empty, "w").close()
        try:
            load_key(empty)
            check("short key refused", False)
        except ValueError:
            pass

    owner = fake_data("email")
    allow_cfg = dict(cfg, data_allow=[owner.upper()])
    check("owner allowed", find_data(f"Author: Owner <{owner}>", allow_cfg, key) == [])

    check("other key, other token", token("email", v["email"], os.urandom(32)) != token("email", v["email"], key))

    marker = f"[secret: openai, fp 1a2b3c4d] {v['email']}"
    skipped, _, _ = tokenize(marker, cfg, key, skip=[(0, len(marker))])
    check("skip span untouched", skipped == marker)

    for t, want in (("deployed by the orgx team", True), ("orgx-db is down", True),
                    ("cd ~/project/orgx-app", False), ("git@github.com:orgx/app.git", False),
                    (f"{v['ip']} refused", True), (f"ssh://{v['ip']}/x", False)):
        check(f"path rule: {t}", bool(find_data(t, cfg, key)) == want)

    lines = []
    for i in range(20000):
        extra = f" user={fake_data('email')}" if i % 50 == 0 else ""
        lines.append(f"2026-11-12T10:00:{i % 60:02d}Z INFO req id=a{i} path=/api/v1/orders/{i} status=200 took={i % 97}ms{extra}")
    blob = "\n".join(lines)
    blob = (blob * (2_000_000 // len(blob) + 1))[:2_000_000]
    t0 = time.time()
    tokenize(blob, cfg, key)
    took = time.time() - t0
    check(f"2 MB in under 1 s (took {took:.2f} s)", took < 1.0)

    with __import__("tempfile").TemporaryDirectory() as tmp:
        p = os.path.join(tmp, "sub", "data.key")
        k1 = load_key(p)
        check("key created 0600, 32 bytes", len(k1) == 32 and (os.stat(p).st_mode & 0o777) == 0o600)
        check("key stable", load_key(p) == k1)

    if bad:
        print("WRONG:", *bad, sep="\n  ")
        sys.exit(1)
    print("ok: data self-check passed")


if __name__ == "__main__":
    if "--test" in sys.argv:
        test()
