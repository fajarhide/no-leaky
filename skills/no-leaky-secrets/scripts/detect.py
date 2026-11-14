#!/usr/bin/env python3
"""Shared secret detectors for scan, the output filter and the prompt guard.

Values are held in memory only to match them. Nothing here prints, logs or
writes a value; callers get spans, kinds and fingerprints.

Self-check: python3 detect.py --test
"""

import hashlib
import json
import os
import random
import re
import string
import sys
import time
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
     r"-----BEGIN [A-Z ]*PRIVATE KEY-----(?:(?:\\+[rn]|\s)+[A-Za-z0-9+/=]{16,})+"
     r"(?:(?:(?:\\+[rn]|\s)+[A-Za-z0-9+/=]{1,15})?(?:\\+[rn]|\s)*-----END [A-Z ]*PRIVATE KEY-----)?", 0),
    ("jwt", "likely", r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}", 0),
    ("url_password", "likely", r"\b[a-z][a-z0-9+.-]*://[^\s:/@\"']+:([^\s@/\"']{8,})@", 1),
    ("bearer", "likely", r"(?i)\bbearer\s+([A-Za-z0-9._~+/-]{16,}=*)", 1),
]
VENDOR = [(k, t, re.compile(p, re.S), g) for k, t, p, g in VENDOR]
# One cheap pass that every VENDOR pattern needs to hit first.
QUICK = re.compile(r"AKIA|ASIA|gh[pousr]_|github_pat_|sk-|AIza|xox|npm_|[srp]k_|-----BEGIN|eyJ|://|[Bb][Ee][Aa][Rr][Ee][Rr]")

# A sensitive name, a separator, then a literal value. Code on the right is rejected in _code_like.
ASSIGN = re.compile(
    r"(?:(?<=\\[nrt])|(?<![A-Za-z0-9_\\]))(?P<name>[A-Za-z0-9_]*(?i:key|token|secret|passwd|password)[A-Za-z0-9_]*)"
    r"(?:\\?[\"'])?[ \t]*[:=][ \t]*(?:\\?[\"'])?(?P<val>[A-Za-z0-9_\-./+=:@!#$%^&*]{16,})"
)
SENSITIVE_WORD = re.compile(r"(?i)key|token|secret|passw")
NAME_BEFORE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)(?:\\?[\"'])?[ \t]*[:=][ \t]*(?:\\?[\"'])?$")
PUBLIC_NAME = re.compile(
    r"^(?:PUBLIC_|NEXT_PUBLIC_|VITE_|EXPO_PUBLIC_)|(?:^|_)(?:PUBLISHABLE|ANON|VAPID_PUBLIC|CLIENT_?ID)(?:_|$)", re.I)
# A public-looking name never makes a secret-only key format public (a real key in VITE_ is a leak).
PUBLIC_BY_NAME = {"google", "jwt", "assignment", "known"}
PLACEHOLDER = re.compile(r"changeme|example|placeholder|dummy|your_|your-|xxxx|<|>|\$\{", re.I)
FIXTURE = re.compile(r"^(?:tests?|testdata|spec|fixtures?|examples?|samples?|mocks?|__mocks__|__fixtures__)$"
                     r"|\.(?:example|sample|template|dist)(?:\.[\w-]+)?$", re.I)
DOTTED = re.compile(r"^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+$")
WORDS = re.compile(r"^[A-Za-z_]+$")
MODEL_NAME = re.compile(r"(?:^|_)MODEL(?:_ID|_NAME)?$", re.I)  # OPENAI_MODEL=gpt-...: a model name, not a credential
EMAIL_VALUE = re.compile(r"^[\w.%+-]+@[\w-]+(?:\.[\w-]+)+$")  # an address is data, not a credential


def fingerprint(value):
    return hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()[:8]


def is_placeholder(value):
    return bool(PLACEHOLDER.search(value)) or value == "user:pass" or len(set(value)) == 1


def is_fixture_path(path):
    return any(FIXTURE.search(part) for part in re.split(r"[/\\]", path))


# Words next to key/token/secret that make the name describe something else (tokenUrl, cache_key).
AFTER_WORD = set("""url uri urls name names id ids path file source src ref type estimate count limit len length
    prefix header field env var policy endpoint ttl expiry expires timeout arn version kind label mode format
    store dir location provider manager required enabled error errors tests test redacted hash line""".split())
BEFORE_WORD = set("""cache sort primary foreign partition idempotency object row map lookup public max min next page
    gateway dedupe dedup unique composite hash range shard cursor index storage translation query group routing
    network i18n existing topology spawn file""".split())
# A name that starts like a boolean flag (hasSavedKey, is_token_valid) holds a flag, not the secret.
FLAG_FIRST = {"has", "have", "needs", "need", "is", "should", "use", "uses", "can", "show", "require", "requires"}
NAME_WORDS = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+")
SLUG = re.compile(r"^(?:[a-z]+\d*|\d+)(?:[-_:.](?:[a-z]+\d*|\d+)){2,}$")


def _weak_name(name):
    words = [w.lower() for w in NAME_WORDS.findall(name)]
    hits = [i for i, w in enumerate(words) if w in ("key", "token", "secret", "passwd", "password")]
    if not hits or words == ["key"]:
        return True
    i = hits[-1]
    return words[0] in FLAG_FIRST or (i + 1 < len(words) and words[i + 1] in AFTER_WORD) or (i > 0 and words[i - 1] in BEFORE_WORD)


def _code_like(text, val, end):
    nxt = text[end:end + 1]
    return (nxt in ("(", "[") or val[0] in "/~$=" or val.startswith("./") or val.isdigit() or "://" in val
            or bool(DOTTED.match(val)) or bool(WORDS.match(val)) or bool(SLUG.match(val)))


def _assignments(text):
    """ASSIGN matches, run only on lines that hold a sensitive word."""
    done = -1
    for hit in SENSITIVE_WORD.finditer(text):
        if hit.start() < done:
            continue
        lo = text.rfind("\n", 0, hit.start()) + 1
        hi = text.find("\n", hit.end())
        done = hi = len(text) if hi < 0 else hi
        yield from ASSIGN.finditer(text, lo, hi)


def _name_before(text, start):
    m = NAME_BEFORE.search(text[max(0, start - 100):start])
    return m.group(1) if m else None


CONFIG_PATH = os.path.expanduser("~/.config/no-leaky/config.json")
CACHE_PATH = os.path.expanduser("~/.cache/no-leaky/known.json")
KNOWN_FORMAT = 5  # bump when _source_values changes, so caches built by older rules are rebuilt
DEFAULT_CONFIG = {"scan_roots": [], "extra_credential_globs": [], "safe_paths": [], "ignore": [],
                  "internal_names": [], "data_allow": [], "data_hosts": []}
HOME_SOURCES = [".npmrc", ".aws/credentials", ".config/gh/hosts.yml", ".docker/config.json"]
SKIP_DIRS = {"node_modules", ".git", "vendor", ".venv", "venv", "__pycache__"}
TOKEN = re.compile(r"[A-Za-z0-9_\-./+=:@!#$%^&*~]{16,}")


def load_config(path=CONFIG_PATH):
    cfg = dict(DEFAULT_CONFIG)
    try:
        with open(path) as f:
            data = json.load(f)
        cfg.update({k: v for k, v in data.items() if k in DEFAULT_CONFIG})
    except FileNotFoundError:
        pass
    except (ValueError, OSError, AttributeError):
        sys.stderr.write(f"no-leaky: ignoring unreadable config {path}\n")
    return cfg


def known_sources(cfg, home=None):
    home = home or os.path.expanduser("~")
    roots = cfg.get("scan_roots") or [os.getcwd()] + [os.path.join(home, d) for d in ("project", "code", "src")]
    found = []
    for root in roots:
        root = os.path.expanduser(root)
        base = root.rstrip(os.sep).count(os.sep)
        for dirpath, dirnames, filenames in os.walk(root):
            if dirpath.count(os.sep) - base >= 4:
                dirnames[:] = []
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for name in filenames:
                path = os.path.join(dirpath, name)
                if (name == ".env" or name.startswith(".env.")) and not is_fixture_path(path):
                    found.append(path)
    found += [p for p in (os.path.join(home, s) for s in HOME_SOURCES) if os.path.isfile(p)]
    return sorted(set(found))


class Known(dict):
    """{sha256 hex: variable name}, plus the value lengths so find() hashes only pieces that could match."""

    def __init__(self, *args, **kw):
        super().__init__(*args, **kw)
        self.lengths = set()


TEMPLATE_SUFFIXES = (".example", ".sample", ".template", ".dist")


def _pairs(path):
    """(name, value) for each assignment in an env or config file; nothing when it cannot be read."""
    try:
        with open(path, errors="replace") as f:
            lines = f.read().splitlines()
    except OSError:
        return
    for line in lines:
        line = re.sub(r"^\s*export\s+", "", line).strip()
        seps = [i for i in (line.find("="), line.find(": ")) if i > 0]
        if line.startswith("#") or not seps:
            continue
        cut = min(seps)
        name = line[:cut].strip().strip("\"'")
        val = line[cut + 1:].strip().rstrip(",").strip().strip("\"'")
        if val:
            yield name, val


def _templates(path):
    """The shared templates beside an env file (.env.example and the like)."""
    d, base = os.path.dirname(path), os.path.basename(path)
    names = {".env" + s for s in TEMPLATE_SUFFIXES} | {base + s for s in TEMPLATE_SUFFIXES}
    return sorted(p for p in (os.path.join(d, n) for n in names) if os.path.isfile(p))


def _source_values(path):
    """{sha256 hex: [variable name, value length]} for the secret-looking values in one source file."""
    out = {}
    # A value the template also holds was written to be shared, so it is a default, not a secret.
    shared = {v for t in _templates(path) for _, v in _pairs(t)}
    for name, val in _pairs(path):
        if (val in shared or len(val) < 16 or is_placeholder(val) or PUBLIC_NAME.search(name) or val[0] in "/~$"
                or (MODEL_NAME.search(name) and _weak_name(name))
                or val.isdigit() or DOTTED.match(val) or WORDS.match(val) or EMAIL_VALUE.match(val)
                or ("://" in val and not re.search(r"://[^/@\s]+:[^/@\s]+@", val))):
            continue
        out[hashlib.sha256(val.encode()).hexdigest()] = [name.rsplit("/", 1)[-1].lstrip(":"), len(val)]
    return out


def load_known(cfg, cache=CACHE_PATH, home=None, max_age=None):
    """{sha256 hex: variable name} of values on this machine. The cache holds hashes only.

    With max_age (seconds), a cache younger than that is used as is, without walking the
    source folders: hooks run on every tool call and the walk takes most of a second.
    """
    if max_age is not None:
        try:
            if time.time() - os.stat(cache).st_mtime < max_age:
                with open(cache) as f:
                    stored = json.load(f)
                if all(e.get("format") == KNOWN_FORMAT for e in stored.values()):  # an older format is rebuilt now
                    return _known_from(stored)
        except (OSError, ValueError, TypeError, AttributeError):
            pass
    try:
        with open(cache) as f:
            stored = json.load(f)
    except (OSError, ValueError):
        stored = {}
    fresh, changed = {}, False
    for path in known_sources(cfg, home):
        try:
            mtime = max(os.stat(p).st_mtime for p in [path] + _templates(path))  # a template edit changes what is learned
        except OSError:
            continue
        entry = stored.get(path)
        if not entry or entry.get("mtime") != mtime or entry.get("format") != KNOWN_FORMAT:
            entry, changed = {"mtime": mtime, "format": KNOWN_FORMAT, "values": _source_values(path)}, True
        fresh[path] = entry
    if changed or set(fresh) != set(stored):
        import tempfile
        os.makedirs(os.path.dirname(cache), exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(cache), prefix=".known-")  # mode 0600
        with os.fdopen(fd, "w") as f:
            json.dump(fresh, f)
        os.replace(tmp, cache)
    elif os.path.exists(cache):
        os.utime(cache, None)  # the walk found nothing new; start the max_age window again
    return _known_from(fresh)


def _known_from(entries):
    known = Known()
    for entry in entries.values():
        for h, (name, length) in entry["values"].items():
            known[h] = name
            known.lengths.add(length)
    return known


def _candidates(token):
    """(offset, text) pieces of a token that could be a whole known value."""
    pieces = [(0, token)] + [(m.start(), m.group()) for m in re.finditer(r"[^@/]+", token)]
    for off, piece in pieces:
        yield off, piece
        for i, c in enumerate(piece):
            if c in "=:":
                yield off + i + 1, piece[i + 1:]


def find(text, known=frozenset()):
    cands = []  # (start, end, kind, tier, name, order)
    if known:
        seen = {}
        lengths = getattr(known, "lengths", None)
        for m in TOKEN.finditer(text):
            for off, piece in _candidates(m.group()):
                if len(piece) >= 16 and (lengths is None or len(piece) in lengths):
                    h = seen.get(piece)
                    if h is None:
                        h = seen[piece] = hashlib.sha256(piece.encode("utf-8", "surrogatepass")).hexdigest()
                    if h in known:
                        s = m.start() + off
                        name = known.get(h) if isinstance(known, dict) else None
                        cands.append((s, s + len(piece), "known", "certain", name, len(VENDOR) + 1))
    for order, (kind, tier, rx, group) in enumerate(VENDOR if QUICK.search(text) else ()):
        for m in rx.finditer(text):
            s, e = m.span(group)
            if is_placeholder(text[s:e]):
                continue
            cands.append((s, e, kind, tier, None, order))
    for m in _assignments(text):
        s, e = m.span("val")
        val = m.group("val")
        if _code_like(text, val, e) or is_placeholder(val) or _weak_name(m.group("name")):
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
        if name and kind in PUBLIC_BY_NAME and PUBLIC_NAME.search(name):
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
    for kind in ("stripe", "anthropic", "aws", "github"):
        found = find(f"VITE_KEY={fake(kind)}")
        check(f"real {kind} under a public name stays certain", len(found) == 1 and found[0].tier == "certain")
    found = find(f"CANONICAL_KEY={rand(24)}")
    check("CANONICAL is not ANON", len(found) == 1 and found[0].tier == "likely")
    found = find(f"SUPABASE_ANON_KEY={fake('jwt')}")
    check("anon jwt is public", len(found) == 1 and found[0].tier == "public")

    pem = fake("private_key")
    lines = pem.splitlines()
    short = "AbC1=="
    pem_short = "\n".join(lines[:-1] + [short, lines[-1]])
    new, _ = redact(pem_short)
    check("pem short last line redacted", short not in new and "END OPENSSH" not in new)
    double = json.dumps(json.dumps({"private_key": pem}))
    new, found = redact(double)
    check("pem double escaped", len(found) == 1 and lines[1] not in new)

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
        'local_network_gateway_key = "lng-office-prod-gateway01"',
        'apiKeyUrl = "https://api.acmecorp.io/v1/keys/rotate"',
        'ig_cache_key = "ig:feed:user:12345:page:2"',
        'secret_source = "vault-kv-prod-apps-main-01"',
        'tokenUrl: "https://auth.acmecorp.io/oauth/token2"',
        'secretName: "app-db-credentials-prod-2"',
        "token_estimate = 1234567890123456",
        f'key = "{rand(24)}"',
        f'"Key": "{rand(24)}"',
        'partitionKey: "tenant-0001-orders-2026-11"',
        'idempotency_key = "order-2026-11-10-000123"',
        "SECRET_ARN=arn:aws:secretsmanager:reg1:000000000000:secret:app-db-AbC123",
        "The header looks like -----BEGIN OPENSSH PRIVATE KEY----- and then the body follows",
        f'topologyKey: "kubernetes.io/{rand(12)}"',
        f'hasSavedOpenaiKey = "{rand(24)}"',
        f'tokenRequired: "{rand(20)}"',
        f'existingSecret: "{rand(20)}"',
        f'local_auth_token_hash = "{rand(64)}"',
        f'project_key_tests = "{rand(40)}"',
        "AR_ENCRYPTION_KEY=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab",
    ]
    v = rand(24)
    text = json.dumps({"stdout": f"line one\nDB_PASSWORD={v}\n"})
    found = find(text)
    check("name after an escaped newline", len(found) == 1 and found[0].name == "DB_PASSWORD")
    for text in ("refresh_token = \"{v}\"", "STRIPE_SECRET_KEY={v}", "apiKey: '{v}'", "client_secret={v}",
                 "accessToken = \"{v}\"", "DB_PASSWORD={v}", "token: {v}"):
        v = rand(32)
        found = find(text.format(v=v))
        check("still likely: " + text, len(found) == 1 and found[0].tier == "likely")
    for text in unchanged:
        check("unchanged: " + text, redact(text)[0] == text)

    check("placeholder changeme", is_placeholder("changeme-now-please-1234"))
    check("placeholder repeated", is_placeholder("a" * 30))
    check("not placeholder", not is_placeholder(rand(24)))
    check("fixture path", is_fixture_path("/repo/tests/fixtures/keys.txt"))
    check("fixture example env", is_fixture_path("/repo/.env.example"))
    check("not fixture", not is_fixture_path("/repo/app/.env"))
    for path in ("/project/latest-api/.env", "/x/contest/.env", "/x/attestation/a.yml", "/x/hammock/.env"):
        check("not fixture: " + path, not is_fixture_path(path))
    for path in ("/repo/test/keys.txt", "/repo/spec/fixtures/a.json", "/repo/__mocks__/x.js", "/r/examples/.env",
                 "/r/app/.env.sample", "/r/app/config.template.yml"):
        check("fixture: " + path, is_fixture_path(path))
    check("fp shape", len(fingerprint("x")) == 8 and all(c in "0123456789abcdef" for c in fingerprint("x")))

    test_known(check)
    test_speed(check)

    if bad:
        print("WRONG:", *bad, sep="\n  ")
        sys.exit(1)
    print("ok: detect self-check passed")


def test_speed(check):
    import time

    known = {hashlib.sha256(rand(24).encode()).hexdigest(): f"VAR_{i}" for i in range(500)}
    line = "2026-11-10T10:00:00Z INFO request served path=/api/v1/items/12345 status=200 dur_ms=12.5 user_agent=curl/8.4\n"
    lines = [line] * (2_000_000 // len(line))
    planted = [fake(random.choice(["aws", "github", "google", "stripe", "npm"])) for _ in range(50)]
    step = len(lines) // 50
    for i, v in enumerate(planted):
        lines[i * step] = f"2026-11-10T10:00:01Z WARN loaded key {v} from env\n"
    text = "".join(lines)
    t0 = time.perf_counter()
    new, findings = redact(text, known)
    took = time.perf_counter() - t0
    check(f"speed: 2 MB in under 1 s (took {took:.2f} s)", took < 1.0)
    check("speed: 50 findings", len(findings) == 50)
    markers = sum(len(f"[secret: {f.kind}, fp {f.fp}]") for f in findings)
    check("speed: no other byte lost", len(new) == len(text) - sum(len(v) for v in planted) + markers)


def test_known(check):
    import tempfile
    import time

    with tempfile.TemporaryDirectory() as tmp:
        root = os.path.join(tmp, "proj")
        os.makedirs(os.path.join(root, "app"))
        os.makedirs(os.path.join(root, "node_modules", "x"))
        home = os.path.join(tmp, "home")
        os.makedirs(home)
        value, short, example, nested = rand(24), rand(8), rand(24), rand(24)
        email = rand(10).lower() + "@" + rand(8).lower() + ".co.id"
        model, model_key = "gemini-" + rand(12).lower() + "-preview", rand(24)
        shared = "ghcr.io/acme/" + rand(10).lower() + ":v2"
        env = os.path.join(root, "app", ".env")
        with open(env, "w") as f:
            f.write(f"MY_VAR={value}\nSHORT={short}\nAPP_URL=https://app.acmecorp.io/path/to\n"
                    f"DB_HOST=db.internal.acmecorp\nNEXT_PUBLIC_KEY={rand(24)}\nexport QUOTED=\"{nested}\"\n"
                    f"SIGNUP_ALLOWLIST={email}\nOPENAI_MODEL={model}\nMODEL_API_KEY={model_key}\n"
                    f"APP_IMAGE={shared}\n")
        with open(os.path.join(root, "app", ".env.example"), "w") as f:
            f.write(f"EX_VAR={example}\nAPP_IMAGE={shared}\n")
        with open(os.path.join(root, "node_modules", "x", ".env"), "w") as f:
            f.write(f"DEP_VAR={rand(24)}\n")
        npmrc_value = rand(36)
        with open(os.path.join(home, ".npmrc"), "w") as f:
            f.write(f"//registry.npmjs.org/:_authToken={npmrc_value}\n")
        cfg = dict(DEFAULT_CONFIG, scan_roots=[root])
        cache = os.path.join(tmp, "cache", "known.json")

        srcs = known_sources(cfg, home=home)
        check("sources: env found", env in srcs)
        check("sources: example skipped", not any(p.endswith(".env.example") for p in srcs))
        check("sources: node_modules skipped", not any("node_modules" in p for p in srcs))
        check("sources: npmrc found", os.path.join(home, ".npmrc") in srcs)

        known = load_known(cfg, cache=cache, home=home)
        h = hashlib.sha256(value.encode()).hexdigest()
        check("known: value", known.get(h) == "MY_VAR")
        check("known: quoted export", hashlib.sha256(nested.encode()).hexdigest() in known)
        check("known: npmrc", hashlib.sha256(npmrc_value.encode()).hexdigest() in known)
        check("known: short skipped", hashlib.sha256(short.encode()).hexdigest() not in known)
        check("known: example skipped", hashlib.sha256(example.encode()).hexdigest() not in known)
        check("known: email skipped", hashlib.sha256(email.encode()).hexdigest() not in known)
        check("known: model name skipped", hashlib.sha256(model.encode()).hexdigest() not in known)
        check("known: key under a model name kept", known.get(hashlib.sha256(model_key.encode()).hexdigest()) == "MODEL_API_KEY")
        check("known: value also in the template skipped", hashlib.sha256(shared.encode()).hexdigest() not in known)
        check("known: only real values", len(known) == 4)
        with open(cache) as f:
            blob = f.read()
        check("cache: no value", value not in blob and npmrc_value not in blob)
        check("cache: mode 0600", (os.stat(cache).st_mode & 0o777) == 0o600)

        for wrap in ("x {v} y", "KEY={v}", '"k":"{v}"', "postgres://u:{v}@h/db", "Authorization: {v}"):
            text = wrap.format(v=value)
            found = [f for f in find(text, known) if f.kind == "known"]
            check("known in " + wrap, len(found) == 1 and text[found[0].start:found[0].end] == value
                  and found[0].name == "MY_VAR" and found[0].tier == "certain")
            check("known redacted in " + wrap, value not in redact(text, known)[0])

        fresh = rand(24)
        with open(env, "w") as f:
            f.write(f"MY_VAR={fresh}\n")
        later = time.time() + 10
        os.utime(env, (later, later))
        known = load_known(cfg, cache=cache, home=home)
        check("refresh: new", hashlib.sha256(fresh.encode()).hexdigest() in known)
        check("refresh: old gone", h not in known)

        os.utime(cache, None)
        real_sources = known_sources
        globals()["known_sources"] = lambda *a, **k: (_ for _ in ()).throw(AssertionError("walked"))
        try:
            quick = load_known(cfg, cache=cache, home=home, max_age=600)
            check("max_age: no walk, same values", hashlib.sha256(fresh.encode()).hexdigest() in quick
                  and quick.lengths == known.lengths)
        except AssertionError:
            check("max_age: no walk", False)
        finally:
            globals()["known_sources"] = real_sources

        old_hash = hashlib.sha256(rand(24).encode()).hexdigest()
        with open(cache, "w") as f:  # a young cache built by older rules, holding a value they no longer learn
            json.dump({env: {"mtime": os.stat(env).st_mtime, "format": KNOWN_FORMAT - 1,
                             "values": {old_hash: ["OLD", 24]}}}, f)
        quick = load_known(cfg, cache=cache, home=home, max_age=600)
        check("max_age: older format rebuilt", old_hash not in quick
              and hashlib.sha256(fresh.encode()).hexdigest() in quick)

        stale = time.time() - 3600
        os.utime(cache, (stale, stale))
        load_known(cfg, cache=cache, home=home, max_age=600)
        check("walk with no change refreshes cache age", time.time() - os.stat(cache).st_mtime < 60)

        bad_cfg = os.path.join(tmp, "config.json")
        with open(bad_cfg, "w") as f:
            f.write("{not json")
        real_err, sys.stderr = sys.stderr, open(os.devnull, "w")
        try:
            check("config: invalid gives defaults", load_config(bad_cfg) == DEFAULT_CONFIG)
        finally:
            sys.stderr.close()
            sys.stderr = real_err
        check("config: missing gives defaults", load_config(os.path.join(tmp, "none.json")) == DEFAULT_CONFIG)
        with open(bad_cfg, "w") as f:
            json.dump({"scan_roots": ["/x"]}, f)
        check("config: merged", load_config(bad_cfg)["scan_roots"] == ["/x"] and load_config(bad_cfg)["ignore"] == [])


if __name__ == "__main__":
    if "--test" in sys.argv:
        test()
