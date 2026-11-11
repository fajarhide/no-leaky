#!/usr/bin/env python3
"""PostToolUse filter: replace secrets in Bash, Read and Grep output before the model sees it.

A safety net behind guard.py. Claude Code runs hooks on one event in parallel and keeps
the rewrite that finishes last, so another rewriter on the same tools must run through
this one: `filter.py --after '<their command>'`.

Self-check: python3 filter.py --test
"""

import json
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import detect  # noqa: E402

TOOLS = {"Bash", "Read", "Grep"}
LOG = os.path.expanduser("~/.cache/no-leaky/filter.log")


def _redact_tree(x, known, found):
    if isinstance(x, str):
        new, hits = detect.redact(x, known)
        found.extend(f for f in hits if f.tier != "public")
        return new
    if isinstance(x, list):
        return [_redact_tree(i, known, found) for i in x]
    if isinstance(x, dict):
        return {k: _redact_tree(v, known, found) for k, v in x.items()}
    return x


def rewrite(payload, known):
    """The hook output that replaces secrets in this tool response, or None when nothing changes."""
    if payload.get("tool_name") not in TOOLS:
        return None
    path = (payload.get("tool_input") or {}).get("file_path") or ""
    if path and detect.is_fixture_path(path):
        return None
    found = []
    resp = _redact_tree(payload.get("tool_response"), known, found)
    if not found:
        return None
    return {"hookSpecificOutput": {"hookEventName": "PostToolUse", "updatedToolOutput": resp}}


def _log(line, log):
    try:
        os.makedirs(os.path.dirname(log), exist_ok=True)
        with open(log, "a") as f:
            f.write(time.strftime("%Y-%m-%dT%H:%M:%S ") + line + "\n")
    except OSError:
        pass


def _their(raw, after, timeout, tool, log):
    """Run the wrapped hook. Returns (parsed JSON or None, its stdout). Any failure counts as no output."""
    try:
        proc = subprocess.run(after, shell=True, input=raw, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as e:
        _log(f"{tool} after {type(e).__name__}", log)
        return None, ""
    if proc.returncode != 0:
        # Its stdout and stderr may carry the raw value, so neither is passed on.
        _log(f"{tool} after exit {proc.returncode}", log)
        return None, ""
    if not proc.stdout.strip():
        return None, ""
    try:
        parsed = json.loads(proc.stdout)
    except ValueError:
        _log(f"{tool} after non-JSON output", log)
        return None, ""
    return (parsed, proc.stdout) if isinstance(parsed, dict) else (None, "")


def run(raw, known=None, log=LOG, after=None, timeout=50):
    """Hook entry. Never blocks work: on any error it logs the error type and passes output through.

    timeout stays under Claude Code's default 60 s hook limit so this hook is not killed first.
    """
    their_out = ""
    tool = "?"
    try:
        payload = json.loads(raw)
        tool = str(payload.get("tool_name"))
        their = None
        if after:
            their, their_out = _their(raw, after, timeout, tool, log)
        base = payload.get("tool_response")
        if their is not None:
            base = (their.get("hookSpecificOutput") or {}).get("updatedToolOutput", base)
        if known is None:
            known = detect.load_known(detect.load_config(), max_age=600)
        ours = rewrite(dict(payload, tool_response=base), known)
        if ours and their is not None:
            their.setdefault("hookSpecificOutput", {}).update(ours["hookSpecificOutput"])
            json.dump(their, sys.stdout)
        elif ours:
            json.dump(ours, sys.stdout)
        else:
            sys.stdout.write(their_out)
    except Exception as e:  # a filter bug must never stop work; the log names the type only
        _log(f"{tool} {type(e).__name__}", log)
        sys.stdout.write(their_out)
    return 0


def test():
    import contextlib
    import io
    import tempfile

    bad = []

    def check(label, cond):
        if not cond:
            bad.append(label)

    key = detect.fake("github")
    bash = {"hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_input": {"command": "cat config"},
            "tool_response": {"stdout": f"a=1\nTOKEN={key}\nb=2\n", "stderr": "", "interrupted": False,
                              "isImage": False, "noOutputExpected": False}}
    out = rewrite(bash, {})
    resp = out and out["hookSpecificOutput"]["updatedToolOutput"]
    check("bash rewritten", resp and key not in json.dumps(resp) and "[secret: github" in resp["stdout"])
    check("bash other lines kept", resp and resp["stdout"].startswith("a=1\nTOKEN=") and resp["stdout"].endswith("\nb=2\n"))
    check("bash shape kept", resp and set(resp) == set(bash["tool_response"]) and resp["interrupted"] is False)
    check("event name", out and out["hookSpecificOutput"]["hookEventName"] == "PostToolUse")

    read = {"hook_event_name": "PostToolUse", "tool_name": "Read", "tool_input": {"file_path": "/app/config.yml"},
            "tool_response": {"type": "text", "file": {"filePath": "/app/config.yml", "content": f"key: {key}\n",
                                                       "numLines": 1, "startLine": 1, "totalLines": 1}}}
    out = rewrite(read, {})
    check("read rewritten", out and key not in json.dumps(out))
    check("read numbers kept", out and out["hookSpecificOutput"]["updatedToolOutput"]["file"]["numLines"] == 1)

    grep = {"hook_event_name": "PostToolUse", "tool_name": "Grep", "tool_input": {"pattern": "TOKEN"},
            "tool_response": {"mode": "content", "content": f"app/.env:2:TOKEN={key}", "numFiles": 1,
                              "filenames": [], "numLines": 1}}
    out = rewrite(grep, {})
    check("grep rewritten", out and key not in json.dumps(out))

    fixture = dict(read, tool_input={"file_path": "/app/tests/fixtures/keys.yml"})
    check("fixture left alone", rewrite(fixture, {}) is None)
    clean = dict(bash, tool_response=dict(bash["tool_response"], stdout="nothing here\n"))
    check("clean returns None", rewrite(clean, {}) is None)
    other = dict(bash, tool_name="WebFetch")
    check("other tools untouched", rewrite(other, {}) is None)

    with tempfile.TemporaryDirectory() as tmp:
        log = os.path.join(tmp, "filter.log")
        real = detect.redact

        def boom(*a, **k):
            raise RuntimeError("inner " + key)

        detect.redact = boom
        stdout = io.StringIO()
        try:
            with contextlib.redirect_stdout(stdout):
                code = run(json.dumps(bash), known={}, log=log)
        finally:
            detect.redact = real
        check("crash exits 0", code == 0)
        check("crash prints nothing", stdout.getvalue() == "")
        with open(log) as f:
            logged = f.read()
        check("crash logged", "RuntimeError" in logged and "Bash" in logged and key not in logged)

        other_hook = os.path.join(tmp, "other.py")
        with open(other_hook, "w") as f:
            f.write("import json,sys\np=json.load(sys.stdin)\nr=dict(p['tool_response'])\n"
                    "r['stdout']=r['stdout'].replace('a=1','A=ONE')\n"
                    "json.dump({'hookSpecificOutput':{'hookEventName':'PostToolUse','updatedToolOutput':r},"
                    "'systemMessage':'other ran'},sys.stdout)\n")
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            run(json.dumps(bash), known={}, log=log, after=f"{sys.executable} {other_hook}")
        chained = json.loads(stdout.getvalue())
        so = chained["hookSpecificOutput"]["updatedToolOutput"]["stdout"]
        check("after: their rewrite kept", so.startswith("A=ONE"))
        check("after: secret redacted", key not in so and "[secret: github" in so)
        check("after: their other fields kept", chained.get("systemMessage") == "other ran")

        cases = {
            "non-JSON stdout": "import sys\nsys.stdin.read()\nprint('not json')\n",
            "exit 2 with the value on stderr": "import sys\nsys.stderr.write(sys.stdin.read())\nsys.exit(2)\n",
            "timeout": "import sys,time\nsys.stdin.read()\ntime.sleep(5)\n",
        }
        for label, body in cases.items():
            hook = os.path.join(tmp, "h.py")
            with open(hook, "w") as f:
                f.write(body)
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = run(json.dumps(bash), known={}, log=log, after=f"{sys.executable} {hook}", timeout=1)
            out = stdout.getvalue()
            check(f"{label}: exit 0", code == 0)
            check(f"{label}: still redacted", "[secret: github" in out and key not in out + stderr.getvalue())
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
            code = run(json.dumps(bash), known={}, log=log, after=os.path.join(tmp, "missing-binary"))
        check("missing binary: still redacted", code == 0 and "[secret: github" in stdout.getvalue())

        silent = os.path.join(tmp, "silent.py")
        with open(silent, "w") as f:
            f.write("import sys\nsys.stdin.read()\n")
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            run(json.dumps(clean), known={}, log=log, after=f"{sys.executable} {silent}")
        check("after: nothing to do prints nothing", stdout.getvalue() == "")

    if bad:
        print("WRONG:", *bad, sep="\n  ")
        sys.exit(1)
    print("ok: filter self-check passed")


if __name__ == "__main__":
    if "--test" in sys.argv:
        test()
    else:
        after = sys.argv[sys.argv.index("--after") + 1] if "--after" in sys.argv else None
        sys.exit(run(sys.stdin.read(), after=after))
