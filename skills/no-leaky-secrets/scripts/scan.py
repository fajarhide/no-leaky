#!/usr/bin/env python3
"""Find secrets that already reached coding agent transcripts.

Prints kinds, routes, dates and fingerprints. Never a value.

Usage: python3 scan.py [--agent claude|codex|gemini|all] [--since YYYY-MM-DD]
                       [--session FILE] [--report PATH] [--source-dir DIR ...]
Exit: 0 clean, 1 a real finding that is not ignored, 2 usage error.
Self-check: python3 scan.py --test
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import detect  # noqa: E402

AGENTS = ("claude", "codex", "gemini")
FIX = {
    "aws": "Deactivate the key in IAM, create a new one, check CloudTrail for its access key id.",
    "github": "Revoke it under GitHub Settings > Developer settings > Tokens, check the security log.",
    "anthropic": "Rotate it in the Anthropic Console under API keys, check usage for the key.",
    "openai": "Rotate it in the OpenAI dashboard under API keys, check usage for the key.",
    "google": "Regenerate it in Google Cloud Console > Credentials, restrict it, check API metrics.",
    "slack": "Revoke it in the Slack app's OAuth settings, check access logs.",
    "npm": "Revoke it on npmjs.com under Access Tokens, check publish history.",
    "stripe": "Roll it in the Stripe Dashboard under Developers > API keys, check request logs.",
    "private_key": "Replace the key pair, remove the old public key everywhere it is trusted.",
}
GENERIC_FIX = "Rotate it where it was issued, then add its fingerprint to ignore with the date."
PASTED = "you pasted it"
BLOCKED = "you pasted it, blocked before sending (local copy only)"


def _claude_files(home, config_dir):
    dirs = {os.path.realpath(os.path.join(d, "projects"))
            for d in (config_dir, os.path.join(home, ".claude")) if d}
    files = []
    for d in sorted(dirs):
        for root, _, names in os.walk(d):
            files += [os.path.join(root, n) for n in names if n.endswith(".jsonl")]
    return sorted(set(files)), any(os.path.isdir(d) for d in dirs)


def _glob(base, exts):
    files = []
    for root, _, names in os.walk(base):
        files += [os.path.join(root, n) for n in names if n.endswith(exts)]
    return sorted(files), os.path.isdir(base)


def agent_files(agent, home, config_dir):
    if agent == "claude":
        return _claude_files(home, config_dir)
    if agent == "codex":
        return _glob(os.path.join(home, ".codex", "sessions"), (".jsonl",))
    return _glob(os.path.join(home, ".gemini", "tmp"), (".json", ".jsonl"))


def _lines(path, stats):
    with open(path, "rb") as f:
        for raw in f:
            try:
                yield json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                stats["bad_lines"] += 1


def _blocks(content):
    return content if isinstance(content, list) else [{"type": "text", "text": content}]


def claude_events(path, stats):
    """(session, date, route, text) for each part of a Claude Code transcript that can carry a value."""
    tools = {}
    session = os.path.splitext(os.path.basename(path))[0]
    for e in _lines(path, stats):
        if not isinstance(e, dict):
            continue
        sid = e.get("sessionId") or session
        date = (e.get("timestamp") or "")[:10]
        msg = e.get("message") if isinstance(e.get("message"), dict) else {}
        kind = e.get("type")
        if kind == "assistant":
            for b in _blocks(msg.get("content") or []):
                if isinstance(b, dict) and b.get("type") == "tool_use":
                    inp = b.get("input") or {}
                    arg = inp.get("command") or inp.get("file_path") or inp.get("pattern") or inp.get("url") or ""
                    tools[b.get("id")] = f"{b.get('name')}: {str(arg)[:60]}".rstrip(": ")
            yield sid, date, "the agent wrote it", json.dumps(msg.get("content"))
        elif kind == "user":
            results = [b for b in _blocks(msg.get("content") or "") if isinstance(b, dict) and b.get("type") == "tool_result"]
            if results:
                for b in results:
                    route = tools.get(b.get("tool_use_id"), "a tool call")
                    yield sid, date, route, json.dumps(b.get("content"))
            else:
                text = json.dumps(msg.get("content"))
                route = ("context injected by a hook or command" if e.get("isMeta")
                         else "you ran it with !" if "<bash-stdout>" in text else PASTED)
                yield sid, date, route, text
        elif kind == "system" and "blocked by hook" in str(e.get("content")):
            yield sid, date, BLOCKED, json.dumps(e.get("content"))
        elif kind in DUPLICATE_TYPES:
            continue
        else:
            yield sid, date, "transcript metadata", json.dumps(e)


def generic_events(path, stats):
    session = os.path.splitext(os.path.basename(path))[0]
    if path.endswith(".jsonl"):
        for e in _lines(path, stats):
            date = str((e.get("timestamp") or "") if isinstance(e, dict) else "")[:10]
            yield session, date, "unknown", json.dumps(e)
    else:
        try:
            with open(path, "rb") as f:
                yield session, "", "unknown", f.read().decode("utf-8", "replace")
        except OSError:
            stats["bad_lines"] += 1


def known_with_sources(cfg, home):
    """{sha256: (name, source path)} read fresh from the source files."""
    out = {}
    for path in detect.known_sources(cfg, home):
        for h, (name, length) in detect._source_values(path).items():
            out.setdefault(h, (name, path, length))
    return out


# Request copies of messages already scanned above; on 2.1.322 they make up a quarter of the bytes.
DUPLICATE_TYPES = {"api-request", "api-request-blob", "api-request-shape", "last-prompt"}
ROUTE_RANK = {"transcript metadata": 3, "the agent wrote it": 2, "context injected by a hook or command": 1}


POOL_MIN = 8


def _scan_file(job):
    """One transcript file -> (distinct finding rows, bad line count). Runs in a worker process."""
    is_claude, path, since, names, lengths = job
    known = detect.Known(names)
    known.lengths = lengths
    stats = {"bad_lines": 0}
    rows = set()
    try:
        for sid, date, route, text in (claude_events if is_claude else generic_events)(path, stats):
            if since and date and date < since:
                continue
            for f in detect.find(text, known):
                rows.add((f.fp, f.kind, f.tier, f.name, sid, date, route))
    except OSError:
        stats["bad_lines"] += 1
    return rows, stats["bad_lines"]


def _map(fn, jobs):
    """Process pool over files when there are many; plain map for a few or when workers are unavailable."""
    if len(jobs) < POOL_MIN:
        return map(fn, jobs)
    try:
        import multiprocessing
        pool = multiprocessing.get_context("spawn").Pool(max(1, (os.cpu_count() or 2) - 1))
    except (OSError, ImportError, ValueError):
        return map(fn, jobs)
    with pool:
        return pool.map(fn, sorted(jobs, key=lambda j: -_size(j[1])), chunksize=1)


def _size(path):
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def run_scan(agent, since, session, cfg, home, config_dir):
    known_src = known_with_sources(cfg, home)
    known = detect.Known({h: v[0] for h, v in known_src.items()})
    known.lengths = {v[2] for v in known_src.values()}
    by_fp = {h[:8]: v[:2] for h, v in known_src.items()}  # fingerprint is the first 8 hex of the same hash
    stats = {"bad_lines": 0}
    coverage, sources = {}, []
    if session:
        coverage["session"] = "covered (1 files)"
        sources.append((claude_events, session))
    else:
        for a in AGENTS if agent == "all" else (agent,):
            files, exists = agent_files(a, home, config_dir)
            coverage[a] = f"covered ({len(files)} files)" if files or exists else "not found"
            reader = claude_events if a == "claude" else generic_events
            sources += [(reader, p) for p in files]
    jobs = [(reader is claude_events, path, since, dict(known), known.lengths) for reader, path in sources]
    leaks = {}
    for part, bad in _map(_scan_file, jobs):
        stats["bad_lines"] += bad
        for (fp, kind, tier, name, sid, date, route) in part:
            lk = leaks.setdefault(fp, {"fp": fp, "kind": kind, "tier": tier, "name": name, "sessions": set(),
                                       "first": date, "last": date, "route": route, "source": None})
            lk["sessions"].add(sid)
            if kind == "known" and fp in by_fp:
                lk["name"], lk["source"] = by_fp[fp]
            if date:
                lk["first"] = min(filter(None, (lk["first"], date)))
                lk["last"] = max(filter(None, (lk["last"], date)))
            if ROUTE_RANK.get(route, 0) < ROUTE_RANK.get(lk["route"], 0):
                lk["route"] = route
            lk["name"] = lk["name"] or name
    ignored = {(i.get("fp") if isinstance(i, dict) else i) for i in cfg.get("ignore", [])}
    for lk in leaks.values():
        lk["ignored"] = lk["fp"] in ignored
        lk["fix"] = FIX.get(lk["kind"], GENERIC_FIX)
        lk["stopped_by"] = ("prompt guard" if lk["route"].startswith(PASTED)
                            else "command guard or output filter" if ":" in lk["route"] else "-")
    return {"leaks": leaks, "coverage": coverage, "bad_lines": stats["bad_lines"]}


def render(res):
    cols = ["what", "tier", "sessions", "first", "last", "route", "fp", "would stop it", "fix"]

    def row(lk):
        what = f"{lk['kind']} {lk['name']}" if lk["name"] else lk["kind"]
        if lk.get("source"):
            what += f" ({lk['source']})"
        cells = [what, lk["tier"], str(len(lk["sessions"])), lk["first"] or "?", lk["last"] or "?",
                 lk["route"], lk["fp"], lk["stopped_by"], lk["fix"]]
        return "| " + " | ".join(c.replace("|", "/") for c in cells) + " |"

    head = "| " + " | ".join(cols) + " |\n|" + "---|" * len(cols)
    groups = [
        ("Certain, act on these", lambda lk: lk["tier"] == "certain" and not lk["ignored"]),
        ("Likely, check these", lambda lk: lk["tier"] == "likely" and not lk["ignored"]),
        ("Ignored", lambda lk: lk["ignored"]),
        ("Public by design, no action", lambda lk: lk["tier"] == "public" and not lk["ignored"]),
    ]
    out = ["# no-leaky scan", ""]
    out += [f"- {a}: {c}" for a, c in res["coverage"].items()]
    if res["bad_lines"]:
        out.append(f"- skipped {res['bad_lines']} unreadable lines (a session still being written, or damaged)")
    out.append("- values are never shown; fp is the first 8 hex of SHA-256 of the value")
    order = lambda lk: (lk["tier"] != "certain", -len(lk["sessions"]), lk["fp"])  # noqa: E731
    for title, keep in groups:
        rows = sorted((lk for lk in res["leaks"].values() if keep(lk)), key=order)
        out += ["", f"## {title} ({len(rows)})", ""]
        out += [head] + [row(lk) for lk in rows] if rows else ["None."]
    return "\n".join(out) + "\n"


def main(argv, cfg=None, home=None, config_dir=None):
    import argparse

    ap = argparse.ArgumentParser(prog="scan.py")
    ap.add_argument("--agent", default="all")
    ap.add_argument("--since")
    ap.add_argument("--session")
    ap.add_argument("--report", default="no-leaky-report.md")
    ap.add_argument("--source-dir", action="append", default=[])
    try:
        args = ap.parse_args(argv)
    except SystemExit:
        return 2
    if args.agent not in AGENTS + ("all",):
        sys.stderr.write(f"scan.py: unknown agent {args.agent}\n")
        return 2
    cfg = cfg if cfg is not None else detect.load_config()
    if args.source_dir:
        cfg = dict(cfg, scan_roots=(cfg.get("scan_roots") or []) + args.source_dir)
    home = home or os.path.expanduser("~")
    if config_dir is None:
        config_dir = os.environ.get("CLAUDE_CONFIG_DIR") or os.path.join(home, ".claude")
    res = run_scan(args.agent, args.since, args.session, cfg, home, config_dir)
    text = render(res)
    sys.stdout.write(text)
    with open(args.report, "w") as f:
        f.write(text)
    print(f"\nreport: {args.report}")
    return 1 if any(lk["tier"] != "public" and not lk["ignored"] for lk in res["leaks"].values()) else 0


def test():
    import contextlib
    import io
    import shutil
    import tempfile

    bad = []

    def check(label, cond):
        if not cond:
            bad.append(label)

    with tempfile.TemporaryDirectory() as tmp:
        home = os.path.join(tmp, "home")
        cfgdir = os.path.join(home, ".claude")
        proj = os.path.join(tmp, "work")
        os.makedirs(proj)
        known_value = detect.rand(24)
        with open(os.path.join(proj, ".env"), "w") as f:
            f.write(f"APP_SECRET={known_value}\n")
        pasted, diff_key, public = detect.fake("github"), detect.fake("google"), detect.rand(24)

        def line(**kw):
            base = {"sessionId": "s-1", "timestamp": "2026-11-01T10:00:00.000Z", "cwd": proj}
            base.update(kw)
            return json.dumps(base)

        lines = [
            line(type="user", message={"role": "user", "content": f"use this token {pasted} please"}),
            line(type="assistant", message={"role": "assistant", "content": [
                {"type": "tool_use", "id": "t1", "name": "Bash", "input": {"command": "cat .env"}}]}),
            line(type="user", message={"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "t1", "content": f"APP_SECRET={known_value}\n"}]},
                 toolUseResult={"stdout": f"APP_SECRET={known_value}\n", "stderr": ""}),
            line(type="assistant", message={"role": "assistant", "content": [
                {"type": "tool_use", "id": "t2", "name": "Bash",
                 "input": {"command": "gh api repos/acme/app/compare/aaa...bbb --jq '.files[].patch'"}}]}),
            line(type="user", timestamp="2026-11-02T09:00:00.000Z", message={"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "t2", "content": f"-FIREBASE_KEY = {diff_key}\n"}]}),
            line(type="user", message={"role": "user", "content": f"NEXT_PUBLIC_API_KEY={public}"}),
        ]
        body = "\n".join(lines) + "\n"
        for folder in ("p-one", "p-two"):
            d = os.path.join(cfgdir, "projects", folder)
            os.makedirs(d)
            with open(os.path.join(d, "s-1.jsonl"), "w") as f:
                f.write(body)
        with open(os.path.join(cfgdir, "projects", "p-one", "s-2.jsonl"), "wb") as f:
            f.write(line(sessionId="s-2", type="user", message={"role": "user", "content": "hi"}).encode() + b"\n")
            f.write(b'{"type": "user", "message": {"content": "caf\xe9 \xff"}}\n')
            f.write(b'{"type": "assistant", "message": {"content": [{"type": "te')

        cfg = dict(detect.DEFAULT_CONFIG, scan_roots=[proj])
        out = io.StringIO()
        report = os.path.join(tmp, "report.md")
        with contextlib.redirect_stdout(out):
            code = main(["--report", report], cfg=cfg, home=home, config_dir=cfgdir)
        text = out.getvalue()
        with open(report) as f:
            rep = f.read()
        res = run_scan("all", None, None, cfg, home, cfgdir)
        real = [lk for lk in res["leaks"].values() if lk["tier"] != "public"]
        check("three real findings", len(real) == 3)
        check("each in one session", all(len(lk["sessions"]) == 1 for lk in real))
        routes = sorted(lk["route"] for lk in real)
        check("route pasted", "you pasted it" in routes)
        check("route cat .env", "Bash: cat .env" in routes)
        check("route gh compare", any(r.startswith("Bash: gh api repos/acme/app/compare") and len(r) <= 66 for r in routes))
        known_leak = [lk for lk in real if lk["kind"] == "known"]
        check("known names variable and source", known_leak and known_leak[0]["name"] == "APP_SECRET"
              and known_leak[0]["source"] == os.path.join(proj, ".env"))
        check("public listed apart", any(lk["tier"] == "public" for lk in res["leaks"].values()))
        check("dates", any(lk["first"] == "2026-11-02" for lk in real))
        check("bad lines counted", res["bad_lines"] == 2)
        check("claude covered", res["coverage"]["claude"].startswith("covered (3 files"))
        check("codex not found", res["coverage"]["codex"] == "not found")
        check("gemini not found", res["coverage"]["gemini"] == "not found")
        for v in (known_value, pasted, diff_key, public):
            check("no value in stdout", v not in text)
            check("no value in report", v not in rep)
        for lk in real:
            check("fp in report " + lk["kind"], lk["fp"] in rep and lk["fp"] in text)
        check("exit 1 on real", code == 1)
        check("certain section first", "## Certain, act on these (3)" in rep and "## Likely, check these (0)" in rep
              and rep.index("## Certain") < rep.index("## Likely"))

        cfg_ign = dict(cfg, ignore=[{"fp": lk["fp"], "reason": "rotated", "date": "2026-11-10"} for lk in real])
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            check("exit 0 when ignored", main(["--report", report], cfg=cfg_ign, home=home, config_dir=cfgdir) == 0)
            check("exit 0 after since", main(["--since", "2026-11-05", "--report", report], cfg=cfg, home=home,
                                              config_dir=cfgdir) == 0)
            check("exit 2 on bad agent", main(["--agent", "nope"], cfg=cfg, home=home, config_dir=cfgdir) == 2)

        global POOL_MIN
        serial = run_scan("all", None, None, cfg, home, cfgdir)
        POOL_MIN = 1
        try:
            pooled = run_scan("all", None, None, cfg, home, cfgdir)
        finally:
            POOL_MIN = 8
        check("pool gives the same result", pooled == serial)

        one = os.path.join(cfgdir, "projects", "p-one", "s-1.jsonl")
        res = run_scan("all", None, one, cfg, home, cfgdir)
        check("session flag reads one file", res["coverage"] == {"session": "covered (1 files)"})
        shutil.rmtree(cfgdir)

    if bad:
        print("WRONG:", *bad, sep="\n  ")
        sys.exit(1)
    print("ok: scan self-check passed")


if __name__ == "__main__":
    if "--test" in sys.argv:
        test()
    else:
        sys.exit(main(sys.argv[1:]))
