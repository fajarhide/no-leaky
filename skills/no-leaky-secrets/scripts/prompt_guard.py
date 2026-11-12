#!/usr/bin/env python3
"""UserPromptSubmit guard: a prompt that carries a secret is not sent to the model.

Resend it starting with `secret-ok:` to send it anyway. Claude Code still writes one
copy of a blocked prompt into the local transcript; the block keeps it away from the
model and the provider.

Self-check: python3 prompt_guard.py --test
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import data  # noqa: E402
import detect  # noqa: E402

PREFIX = "secret-ok:"


DATA_REASON = (
    "This message holds personal or business data ({kinds}, {n} values). It was not sent to the model, but Claude "
    "Code keeps one local copy in the transcript. Put the rows in a file and point me at the path: I will see them as "
    "tokens and can still use them. To send it anyway, resend starting with " + PREFIX)


def decide(prompt, known, cfg=None, key=None):
    """Block output for a prompt holding a secret, or (with cfg and key) personal data, else None."""
    if prompt.lstrip().startswith(PREFIX):
        return None
    hits = [f for f in detect.find(prompt, known) if f.tier != "public"]
    if not hits:
        found = data.find_data(prompt, cfg, key) if cfg is not None and key else []
        if not found:
            return None
        kinds = ", ".join(sorted({f.kind for f in found}))
        return {"decision": "block", "reason": DATA_REASON.format(kinds=kinds, n=len(found))}
    seen = ", ".join(f"{f.name or f.kind} ({f.kind}, fp {f.fp})" for f in hits[:5])
    return {"decision": "block", "reason": (
        f"This message looks like it carries a secret: {seen}. It was not sent to the model. "
        "Claude Code still keeps one copy in the local transcript; rotate it if it matters. "
        "Better: put it in a file or an env var and tell the agent where it is. "
        f"To send it anyway, resend starting with {PREFIX}")}


def main():
    try:
        payload = json.load(sys.stdin)
        cfg = detect.load_config()
        out = decide(payload.get("prompt") or "", detect.load_known(cfg, max_age=600), cfg, data.load_key())
    except Exception:  # never stop the user from typing because of a guard bug
        return
    if out:
        json.dump(out, sys.stdout)


def test():
    bad = []

    def check(label, cond):
        if not cond:
            bad.append(label)

    key = detect.fake("anthropic")
    out = decide(f"here is my key {key} can you set it up", {})
    check("blocks", out and out.get("decision") == "block")
    reason = (out or {}).get("reason", "")
    check("reason names kind and fp", "anthropic" in reason and detect.fingerprint(key) in reason)
    check("reason gives the resend line", "To send it anyway, resend starting with secret-ok:" in reason)
    check("reason says a local copy stays", "local transcript" in reason)
    check("reason has no value", key not in reason)
    check("prefix passes", decide(f"secret-ok: here is my key {key}", {}) is None)
    check("prefix after spaces passes", decide(f"  secret-ok: {key}", {}) is None)
    check("public passes", decide(f"NEXT_PUBLIC_API_KEY={detect.rand(24)}", {}) is None)
    check("code passes", decide("why does SECRET_NAME = re.compile( fail and token = token.strip() too", {}) is None)
    v = detect.rand(24)
    known = detect.Known({__import__("hashlib").sha256(v.encode()).hexdigest(): "MY_VAR"})
    known.lengths = {len(v)}
    out = decide(f"the value is {v}", known)
    check("known value blocks", out and "MY_VAR" in out["reason"] and v not in out["reason"])

    import data
    dkey = os.urandom(32)
    dcfg = dict(detect.DEFAULT_CONFIG)
    a, b = data.fake_data("email"), data.fake_data("email")
    out = decide(f"why do {a} and {b} get no receipt", {}, dcfg, dkey)
    reason = (out or {}).get("reason", "")
    check("data blocks", out and out.get("decision") == "block")
    check("data reason exact", reason == "This message holds personal or business data (email, 2 values). It was not "
          "sent to the model, but Claude Code keeps one local copy in the transcript. Put the rows in a file and point "
          "me at the path: I will see them as tokens and can still use them. To send it anyway, resend starting with "
          "secret-ok:")
    check("data reason has no value", a not in reason and b not in reason)
    check("owner email passes", decide(f"I am {a}", {}, dict(dcfg, data_allow=[a]), dkey) is None)
    check("data prefix passes", decide(f"secret-ok: {a}", {}, dcfg, dkey) is None)
    check("no cfg, no data check", decide(f"mail {a}", {}) is None)

    if bad:
        print("WRONG:", *bad, sep="\n  ")
        sys.exit(1)
    print("ok: prompt guard self-check passed")


if __name__ == "__main__":
    if "--test" in sys.argv:
        test()
    else:
        main()
