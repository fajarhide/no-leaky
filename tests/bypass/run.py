#!/usr/bin/env python3
"""Bypass corpus runner for no-leaky.

Replays known and suspected ways an agent can get a secret into its transcript, through the
real guard (before the tool) and the real filter (after it). Nothing is executed: each case
carries the command and the output that command would print, with {S} standing for a fake
secret. The runner asks two questions per case: did the guard deny it, and if not, did the
filter remove the secret from the output?

Files (JSON lines, one case per line):
  commands.jsonl    shell commands and tool calls, checked end to end
  transforms.jsonl  a secret rewritten before it is printed (base64, split up, ...), filter only
  pii.jsonl         personal data from many countries, checked against the data detector

Run:
  python3 tests/bypass/run.py              # report, exit 1 on any regression or stale gap
  python3 tests/bypass/run.py --markdown   # known-gap tables for the README
  python3 tests/bypass/run.py --layers     # cases where only the filter stood between key and model
  python3 tests/bypass/run.py -k docker    # only cases whose id or command contains "docker"
"""

import argparse
import base64
import collections
import hashlib
import json
import os
import random
import signal
import sys
import tempfile
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.normpath(os.path.join(HERE, "..", "..", "skills", "no-leaky-secrets", "scripts"))
sys.path.insert(0, SCRIPTS)

import data  # noqa: E402
import detect  # noqa: E402
import guard  # noqa: E402
import filter as nl_filter  # noqa: E402
import vault  # noqa: E402

SECRET_FLAVORS = ["vendor", "opaque-known", "opaque-unknown"]
# What each flavor stands for:
#   vendor          a key in a published vendor format (the filter can recognise it by shape)
#   opaque-known    no recognisable shape, but the value sits in an .env on this machine (the filter knows its hash)
#   opaque-unknown  no recognisable shape and not in any local file (only the guard can protect it)

TRANSFORMS = {
    "raw": lambda s: s,
    "quoted": lambda s: '"' + s + '"',
    "json": lambda s: json.dumps({"value": s}),
    "percent-encoded": lambda s: urllib.parse.quote(s, safe=""),
    "base64": lambda s: base64.b64encode(s.encode()).decode(),
    "hex": lambda s: s.encode().hex(),
    "upper": lambda s: s.upper(),
    "lower": lambda s: s.lower(),
    "reversed": lambda s: s[::-1],
    "spaced": lambda s: " ".join(s),
    "split-lines": lambda s: s[: len(s) // 2] + "\n" + s[len(s) // 2:],
    "split-concat": lambda s: '"' + s[: len(s) // 2] + '" + "' + s[len(s) // 2:] + '"',
}


def load(name):
    path = os.path.join(HERE, name)
    cases = []
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if line and not line.startswith("#"):
                try:
                    cases.append(json.loads(line))
                except ValueError as e:
                    sys.exit(f"{name}:{n}: not valid JSON ({e})")
    return cases


class Sandbox:
    """Fresh fake secrets and a private vault, so a run never touches the real config or cache."""

    def __init__(self, seed=1337):
        self.seed = seed
        random.seed(seed)  # fake secrets come from the random module, so a seed makes a failure repeatable
        self.tmp = tempfile.TemporaryDirectory()
        guard.VAULT = os.path.join(self.tmp.name, "vault.json")
        vault.VAULT_PATH = guard.VAULT
        self.cfg = dict(detect.DEFAULT_CONFIG)
        self.key = os.urandom(32)

    def secret(self, flavor):
        """(value, known) for a flavor. `known` is what load_known would hold after reading a local .env."""
        # A fresh value that happens to contain "xxxx" is mistaken for a placeholder (see x-placeholder-substring in
        # transforms.jsonl). That gap has its own fixed cases, so random values skip it and a run stays repeatable.
        for _ in range(50):
            value = self._draw(flavor)
            if not detect.is_placeholder(value):
                break
        known = detect.Known()
        if flavor == "opaque-known":
            known[hashlib.sha256(value.encode()).hexdigest()] = "APP_KEY"
            known.lengths.add(len(value))
        return value, known

    @staticmethod
    def _draw(flavor):
        if flavor == "vendor":
            return detect.fake("stripe")
        if flavor in ("opaque-known", "opaque-unknown"):
            return detect.rand(24)
        if flavor in ("private_key", "jwt", "aws", "github", "anthropic", "openai", "google", "slack", "npm", "stripe"):
            return detect.fake(flavor)
        raise ValueError(flavor)

    def close(self):
        self.tmp.cleanup()


def tool_payload(case, output):
    tool = case.get("tool", "Bash")
    if tool == "Bash":
        inp = {"command": case["command"]}
        resp = {"stdout": output, "stderr": "", "interrupted": False, "isImage": False, "noOutputExpected": False}
    elif tool == "Read":
        inp = {"file_path": case["path"]}
        resp = {"type": "text", "file": {"filePath": case["path"], "content": output, "numLines": 1,
                                           "startLine": 1, "totalLines": 1}}
    elif tool == "Grep":
        inp = {k: v for k, v in case.items() if k in ("pattern", "path", "glob", "output_mode")}
        resp = {"mode": "content", "content": output, "numFiles": 1, "filenames": [], "numLines": 1}
    else:
        raise ValueError(f"unknown tool {tool}")
    return {"tool_name": tool, "tool_input": inp, "tool_response": resp}


def evaluate(sb, case, flavor):
    """One case against one secret flavor. Returns (outcome, layer): blocked | redacted | leaked | allowed | denied."""
    secret, known = sb.secret(flavor)
    output = case.get("output", "").replace("{S}", secret)
    if case.get("output_transform"):
        output = TRANSFORMS[case["output_transform"]](output)
    payload = tool_payload(case, output)
    hit = guard.check({"tool_name": payload["tool_name"], "tool_input": payload["tool_input"]}, sb.cfg)
    if case.get("expect") == "allow":
        return ("denied", "guard") if hit else ("allowed", None)
    if case.get("expect") == "deny":
        return ("blocked", "guard") if hit else ("leaked", None)
    if hit:
        return "blocked", "guard"
    carries = "{S}" in case.get("output", "")
    out = nl_filter.rewrite(payload, known)
    if out is None:
        return ("leaked", None) if carries else ("allowed", None)
    final = json.dumps(out["hookSpecificOutput"]["updatedToolOutput"])
    transformed = bool(case.get("output_transform"))
    leaked = secret in final or (transformed and output in final.replace("\\n", "\n"))
    return ("leaked", None) if leaked else ("redacted", "filter")


def expected_leaks(case):
    leaks = case.get("leaks", [])
    return set(SECRET_FLAVORS) if leaks == "all" else set(leaks)


def run_commands(sb, cases):
    rows = []
    for case in cases:
        mode = case.get("expect", "safe")
        flavors = [None] if mode in ("allow", "deny") else case.get("flavors", SECRET_FLAVORS)
        leaks = expected_leaks(case)
        for flavor in flavors:
            outcome, layer = evaluate(sb, case, flavor or "vendor")
            if mode == "allow":
                status = "OK" if outcome == "allowed" else "FALSE-POSITIVE"
            elif mode == "deny":
                status = "OK" if outcome == "blocked" else "REGRESSION"
            else:
                leaked = outcome == "leaked"
                should_leak = flavor in leaks
                status = "OK" if leaked == should_leak else ("REGRESSION" if leaked else "FIXED")
            rows.append({"case": case, "flavor": flavor, "outcome": outcome, "layer": layer, "status": status})
    return rows


def survives(shown, final, width=12):
    """True when any run of `width` characters of the printed value still reaches the model.
    A half-redacted value counts as a leak: the other half is still there."""
    return any(shown[i:i + width] in final for i in range(0, max(1, len(shown) - width + 1), 3))


def run_transforms(sb, cases):
    """A secret is rewritten before it is printed. It leaked when the rewritten text reaches the model unchanged.

    A case lists random `kinds`, fixed values under `fixed` ({label: [parts]}, joined at run time so the repository
    never holds a string that looks like a live key), or both."""
    rows = []
    for case in cases:
        leaks = case.get("leaks", [])
        subjects = [(k, *sb.secret(k)) for k in case.get("kinds", [])]
        subjects += [(label, "".join(parts), detect.Known()) for label, parts in case.get("fixed", {}).items()]
        for kind, secret, known in subjects:
            shown = TRANSFORMS[case["transform"]](secret)
            payload = {"tool_name": "Bash", "tool_input": {"command": "run"},
                       "tool_response": {"stdout": f"result: {shown}\n"}}
            out = nl_filter.rewrite(payload, known)
            final = out["hookSpecificOutput"]["updatedToolOutput"]["stdout"] if out else payload["tool_response"]["stdout"]
            leaked = survives(shown, final)
            should = leaks == "all" or kind in leaks
            status = "OK" if leaked == should else ("REGRESSION" if leaked else "FIXED")
            rows.append({"case": case, "kind": kind, "leaked": leaked, "status": status})
    return rows


def run_pii(sb, cases):
    rows = []
    for case in cases:
        text = case.get("context", "record: {V} end").replace("{V}", case["value"])
        start = text.index(case["value"])
        end = start + len(case["value"])
        found = data.find_data(text, sb.cfg, sb.key)
        hit = [f for f in found if f.start < end and f.end > start]
        detected = bool(hit)
        mode = case.get("expect", "tokenized")
        should = mode == "tokenized"
        status = "OK" if detected == should else ("REGRESSION" if should else
                                                  ("FALSE-POSITIVE" if mode == "ignored" else "FIXED"))
        rows.append({"case": case, "detected": detected, "kind": hit[0].kind if hit else None, "status": status})
    return rows


def label_of(case):
    return case.get("command") or case.get("path") or case.get("pattern") or case.get("value") or case.get("transform") or ""


def md_code(text):
    text = text.splitlines()[0] if text else ""
    text = text.replace("|", "\\|")
    return "`` " + text + " ``" if "`" in text else "`" + text + "`"


def short(text, n=70):
    text = text.replace("\n", "\\n")
    return text if len(text) <= n else text[: n - 1] + "…"


def report(cmd_rows, tr_rows, pii_rows, args):
    bad = [r for r in cmd_rows + tr_rows + pii_rows if r["status"] != "OK"]
    stdout = sys.stdout

    # Commands: how the layers share the work.
    safe_rows = [r for r in cmd_rows if r["case"].get("expect", "safe") == "safe"]
    by_outcome = collections.Counter(r["outcome"] for r in safe_rows)
    cases_safe = len({r["case"]["id"] for r in safe_rows})
    print(f"Commands: {len(cmd_rows)} checks over {len({r['case']['id'] for r in cmd_rows})} cases")
    print(f"  stopped by the guard:             {by_outcome['blocked']}")
    print(f"  passed the guard, filter redacted: {by_outcome['redacted']}")
    print(f"  leaked (documented gaps):          {by_outcome['leaked']}")
    print(f"  ({cases_safe} read and dump cases, each tried with up to {len(SECRET_FLAVORS)} kinds of secret)")

    if tr_rows:
        n_leak = sum(1 for r in tr_rows if r["leaked"])
        print(f"Transforms: {len(tr_rows)} checks, {n_leak} leak (all documented), the rest are redacted")
    if pii_rows:
        n_ok = sum(1 for r in pii_rows if r["case"].get("expect", "tokenized") == "tokenized" and r["detected"])
        n_gap = sum(1 for r in pii_rows if r["case"].get("expect") == "gap" and not r["detected"])
        print(f"Personal data: {n_ok} formats tokenized, {n_gap} documented gaps, "
              f"{len(pii_rows) - n_ok - n_gap} negatives and others")

    if args.layers:
        print("\nGuard misses that the filter caught (the guard could learn these):")
        seen = set()
        for r in safe_rows:
            if r["outcome"] == "redacted" and r["case"]["id"] not in seen:
                seen.add(r["case"]["id"])
                print(f"  {r['case']['id']:<8} {short(label_of(r['case']), 80)}")

    if bad:
        print(f"\nProblems (seed {args.seed_used}; rerun with --seed {args.seed_used}):")
        for r in bad:
            c = r["case"]
            what = r.get("flavor") or r.get("kind") or ""
            label = label_of(c)
            hint = {"REGRESSION": "was safe, now leaks",
                    "FIXED": "documented as a gap, now safe: remove it from `leaks`",
                    "FALSE-POSITIVE": "should be allowed or ignored, was flagged"}.get(r["status"], r["status"])
            print(f"  {r['status']:<14} {c['id']:<8} [{what}] {short(str(label), 60)}: {hint}")
    else:
        print("\nAll cases match what the corpus says.")
    return 1 if bad and not args.lenient else 0


def markdown(cmd_rows, tr_rows, pii_rows):
    gaps = collections.OrderedDict()
    for r in cmd_rows:
        if r["outcome"] == "leaked" and r["case"].get("expect", "safe") == "safe":
            gaps.setdefault(r["case"]["id"], (r["case"], []))[1].append(r["flavor"])
    flavor_sets = {tuple(f) for _, f in gaps.values()}
    print("### Commands that still leak\n")
    if len(flavor_sets) == 1:
        print("Each row leaks only for a secret of this kind: " + ", ".join(next(iter(flavor_sets))) + ".\n")
        print("| id | command | why |")
        print("| --- | --- | --- |")
        for cid, (c, _) in gaps.items():
            print(f"| {cid} | {md_code(label_of(c))} | {c.get('note', '')} |")
    else:
        print("| id | command | leaks when the secret is | why |")
        print("| --- | --- | --- | --- |")
        for cid, (c, flavors) in gaps.items():
            print(f"| {cid} | {md_code(label_of(c))} | {', '.join(flavors)} | {c.get('note', '')} |")
    print("\n### Output rewrites the filter does not recognise\n")
    kinds_by_transform = collections.defaultdict(list)
    for r in tr_rows:
        if r["leaked"]:
            kinds_by_transform[r["case"]["transform"]].append(r["kind"])
    print("| transform | not caught for |")
    print("| --- | --- |")
    for t, kinds in kinds_by_transform.items():
        print(f"| {t} | {', '.join(kinds)} |")
    print("\n### Personal data formats not detected\n")
    print("| country | kind | example |")
    print("| --- | --- | --- |")
    for r in pii_rows:
        c = r["case"]
        if c.get("expect") == "gap" and not r["detected"]:
            print(f"| {c['country']} | {c['kind']} | `{c['value']}` |")


def main():
    if hasattr(signal, "SIGPIPE"):
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)  # `run.py | head` should end quietly
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-k", help="only cases whose id or command contains this text")
    ap.add_argument("--markdown", action="store_true", help="print the known-gap tables for the README")
    ap.add_argument("--layers", action="store_true", help="list cases only the filter stopped")
    ap.add_argument("--seed", default="1337", help="seed for the fake secrets; `random` picks one and prints it (fuzzing)")
    ap.add_argument("--lenient", action="store_true", help="exit 0 even when a documented gap turns out to be fixed")
    args = ap.parse_args()

    def pick(cases):
        if not args.k:
            return cases
        return [c for c in cases if args.k in c["id"] or args.k in json.dumps(c)]

    seed = random.SystemRandom().randrange(1 << 32) if args.seed == "random" else int(args.seed)
    sb = Sandbox(seed)
    try:
        cmd_rows = run_commands(sb, pick(load("commands.jsonl")))
        tr_rows = run_transforms(sb, pick(load("transforms.jsonl")))
        pii_rows = run_pii(sb, pick(load("pii.jsonl")))
    finally:
        sb.close()
    args.seed_used = seed
    if args.markdown:
        markdown(cmd_rows, tr_rows, pii_rows)
        return 0
    return report(cmd_rows, tr_rows, pii_rows, args)


if __name__ == "__main__":
    sys.exit(main())
