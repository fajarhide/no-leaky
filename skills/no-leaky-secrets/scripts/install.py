#!/usr/bin/env python3
"""Wire the no-leaky hooks into Claude Code settings.json, or take them out again.

Usage: python3 install.py [--config-dir DIR] [--dry-run] [--uninstall] [--no-wrap TEXT ...]
Self-check: python3 install.py --test
"""

import json
import re
import shutil
import os
import shlex
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = ("Bash", "Read", "Grep")
FILTER_TOOLS = TOOLS + ("mcp__.*",)
GUARD_TOOLS = TOOLS + ("Edit", "Write")  # Edit and Write: a data token must not be written into a real file  # MCP output is rewritable too (measured), so the filter covers it
OURS = ("guard.py", "filter.py", "prompt_guard.py")
REPORT = "no-leaky-report.md"
BIN_DIR = os.path.expanduser("~/.local/bin")
CLAUDE_HOME = os.path.expanduser("~/.claude")
PYTHON = None
SHIM_MARK = "# no-leaky shim"


def _version_ok(exe):
    try:
        out = subprocess.run([exe, "-c", "import sys; print(sys.version_info >= (3, 9))"], capture_output=True,
                             text=True, timeout=10).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return False
    return out == "True"


def _python(which=shutil.which, version_ok=_version_ok):
    """The interpreter the hooks run with. python3 on PATH (such as /opt/homebrew/bin/python3) survives a minor
    upgrade that removes the versioned path this installer may run from; a shim or a venv does not, and a pyenv shim
    can pick another version per directory."""
    exe = which("python3")
    if exe and not re.search(r"/(?:shims|\.pyenv|\.asdf|\.?venv|virtualenvs)/", exe) and version_ok(exe):
        return exe
    if sys.prefix != sys.base_prefix:  # running inside a venv: use the interpreter it was made from
        base = os.path.join(sys.base_prefix, "bin", f"python{sys.version_info[0]}.{sys.version_info[1]}")
        if os.path.exists(base):
            return base
    return sys.executable


def _py():
    global PYTHON
    if PYTHON is None:
        PYTHON = _python()
    return PYTHON


def _cmd(script, *extra):
    return " ".join(shlex.quote(x) for x in (_py(), os.path.join(HERE, script)) + extra)


def _tokens(command):
    try:
        return shlex.split(command)
    except ValueError:
        return command.split()


def _ours(command, script=None):
    names = (script,) if script else OURS
    return any(os.path.join(HERE, n) in _tokens(command) for n in names)


def _overlaps(matcher, tools=TOOLS):
    import re
    """The subset of TOOLS a hook matcher fires on."""
    if matcher in (None, "", "*"):
        return set(tools)
    try:
        return {t for t in tools if re.fullmatch(matcher, t)}
    except re.error:
        return {t for t in tools if t in matcher}


def _commands(groups):
    return [h for g in groups for h in g.get("hooks", []) if h.get("type") == "command"]


def install(s, no_wrap=()):
    """Add the hooks to settings dict s in place. Returns a list of changes made.

    Hooks whose command contains a no_wrap substring stay as they are. Safe for hooks that never
    rewrite output (an empty {} finishing last does not undo our rewrite), and needed for hooks
    that read their parent pid or are rewritten by the app that owns them.
    """
    hooks = s.setdefault("hooks", {})
    changes = []
    pre = hooks.setdefault("PreToolUse", [])
    guard_matcher = "|".join(GUARD_TOOLS)
    ours = [g for g in pre if any(h.get("type") == "command" and _ours(h.get("command", ""), "guard.py")
                                  for h in g.get("hooks", []))]
    if not ours:
        pre.append({"matcher": guard_matcher, "hooks": [{"type": "command", "command": _cmd("guard.py")}]})
        changes.append(f"PreToolUse: added guard.py on {guard_matcher}")
    for g in ours:
        if g.get("matcher") != guard_matcher:
            g["matcher"] = guard_matcher
            changes.append(f"PreToolUse: guard.py now also on Edit and Write")
    post = hooks.setdefault("PostToolUse", [])
    covered = set()
    for g in post:
        tools = _overlaps(g.get("matcher"), FILTER_TOOLS)
        if not tools:
            continue
        for h in g.get("hooks", []):
            if h.get("type") != "command" or any(n in h["command"] for n in no_wrap):
                continue
            if not _ours(h["command"], "filter.py"):
                # Hooks on one event run in parallel and the last rewrite wins, so run theirs through ours.
                h["command"] = _cmd("filter.py", "--after", h["command"])
                changes.append(f"PostToolUse: {g.get('matcher')!r} hook now runs through filter.py --after")
            covered |= tools
    missing = [t for t in FILTER_TOOLS if t not in covered]
    if missing:
        post.append({"matcher": "|".join(missing), "hooks": [{"type": "command", "command": _cmd("filter.py")}]})
        changes.append(f"PostToolUse: added filter.py on {'|'.join(missing)}")
    ups = hooks.setdefault("UserPromptSubmit", [])
    if not any(_ours(h["command"], "prompt_guard.py") for h in _commands(ups)):
        ups.append({"hooks": [{"type": "command", "command": _cmd("prompt_guard.py")}]})
        changes.append("UserPromptSubmit: added prompt_guard.py")
    return changes


def uninstall(s):
    """Remove our hooks and unwrap --after hooks in settings dict s in place."""
    hooks = s.get("hooks") or {}
    for event in list(hooks):
        groups = []
        for g in hooks[event]:
            kept = []
            for h in g.get("hooks", []):
                if h.get("type") == "command" and _ours(h.get("command", "")):
                    t = _tokens(h["command"])
                    if "--after" in t and t.index("--after") + 1 < len(t):
                        kept.append(dict(h, command=t[t.index("--after") + 1]))
                    continue
                kept.append(h)
            if kept:
                groups.append(dict(g, hooks=kept))
        if groups:
            hooks[event] = groups
        else:
            del hooks[event]
    if "hooks" in s and not hooks:
        del s["hooks"]


def _write(path, text, mode_from=None):
    """Atomic write through a symlink (dotfile managers), keeping the mode of mode_from or of the file."""
    target = os.path.realpath(path)
    tmp = target + ".no-leaky-tmp"
    with open(tmp, "w") as f:
        f.write(text)
    src = mode_from or target
    if os.path.exists(src):
        os.chmod(tmp, os.stat(src).st_mode & 0o777)
    os.replace(tmp, target)


def _shim(dry=False, remove=False):
    """Put nl-run on PATH as a tiny sh shim, or take ours away. Returns a line for the user, or None."""
    path = os.path.join(BIN_DIR, "nl-run")
    ours = os.path.exists(path) and SHIM_MARK in open(path, errors="replace").read()
    if remove:
        if ours and not dry:
            os.remove(path)
        return f"removed {path}" if ours else None
    if os.path.exists(path) and not ours:
        return f"{path} exists and is not ours; left alone. Call {os.path.join(HERE, 'nl_run.py')} directly."
    text = f'#!/bin/sh\n{SHIM_MARK}\nexec {shlex.quote(_py())} {shlex.quote(os.path.join(HERE, "nl_run.py"))} "$@"\n'
    if ours and open(path).read() == text:
        return None
    if dry:
        return f"would add the nl-run command at {path}"
    os.makedirs(BIN_DIR, exist_ok=True)
    with open(path, "w") as f:
        f.write(text)
    os.chmod(path, 0o755)
    line = f"added the nl-run command at {path}"
    if BIN_DIR not in os.environ.get("PATH", "").split(os.pathsep):
        line += f"; {BIN_DIR} is not on PATH, add it so nl-run works"
    return line


def _gitignore():
    if not os.path.isdir(".git"):
        return
    lines = open(".gitignore").read().splitlines() if os.path.exists(".gitignore") else []
    if REPORT not in lines:
        with open(".gitignore", "a") as f:
            f.write(("\n" if lines and lines[-1] else "") + REPORT + "\n")
        print(f"- .gitignore: added {REPORT}")


def _same_settings(a, b):
    """Equal once the order of hook groups is ignored (Orca moves its own groups to the end when it re-copies)."""
    def norm(path):
        with open(path) as f:
            s = json.load(f)
        hooks = s.get("hooks")
        if isinstance(hooks, dict):
            s["hooks"] = {ev: sorted((json.dumps(g, sort_keys=True) for g in groups), key=str)
                          for ev, groups in hooks.items() if isinstance(groups, list)}
        return s
    try:
        return norm(a) == norm(b)
    except (OSError, ValueError):
        return False


def _mirrors_home(cfgdir):
    """True when the config dir links into ~/.claude (skills, projects, hooks): a profile an app builds from it."""
    home = os.path.realpath(CLAUDE_HOME)
    try:
        names = os.listdir(cfgdir)
    except OSError:
        return False
    for n in names:
        full = os.path.join(cfgdir, n)
        if os.path.islink(full) and os.path.realpath(full).startswith(home + os.sep):
            return True
    return False


def _targets(cfgdir):
    """The config dirs to change. An app that keeps a profile (Orca does) re-copies ~/.claude/settings.json over the
    profile's own; then the hooks go into the source as well, or the next copy wipes them."""
    a, b = os.path.join(cfgdir, "settings.json"), os.path.join(CLAUDE_HOME, "settings.json")
    if os.path.realpath(cfgdir) == os.path.realpath(CLAUDE_HOME) or not os.path.isfile(b):
        return [cfgdir]
    if os.path.isfile(a) and os.path.samefile(a, b):
        return [cfgdir]
    if (os.path.isfile(a) and _same_settings(a, b)) or _mirrors_home(cfgdir):
        return [CLAUDE_HOME, cfgdir]
    return [cfgdir]


def _installed_copy(command, script):
    """Our script from any copy of no-leaky (repo, npx install), for --check."""
    return [t for t in _tokens(command) if t.replace(os.sep, "/").endswith("no-leaky-secrets/scripts/" + script)]


def _check(targets):
    """Problems with the installed hooks, as lines for the user. Empty means healthy."""
    problems = []
    for d in targets:
        path = os.path.join(d, "settings.json")
        try:
            with open(path) as f:
                s = json.load(f)
        except FileNotFoundError:
            problems.append(f"{path} does not exist")
            continue
        except ValueError:
            problems.append(f"{path} is not valid JSON")
            continue
        hooks = s.get("hooks") or {}
        for event, script in (("PreToolUse", "guard.py"), ("PostToolUse", "filter.py"),
                              ("UserPromptSubmit", "prompt_guard.py")):
            cmds = [h.get("command", "") for g in hooks.get(event, []) for h in g.get("hooks", [])
                    if h.get("type") == "command" and _installed_copy(h.get("command", ""), script)]
            if not cmds:
                problems.append(f"{path}: {script} is not installed ({event})")
            for c in cmds:
                exe = _tokens(c)[0]
                if not (os.path.isfile(exe) and os.access(exe, os.X_OK)):
                    problems.append(f"{path}: {script} runs {exe}, which no longer exists; run install.py again")
                for sp in _installed_copy(c, script):
                    if not os.path.isfile(sp):
                        problems.append(f"{path}: {sp} no longer exists; run install.py again")
    if not os.path.exists(os.path.join(BIN_DIR, "nl-run")):
        problems.append(f"{os.path.join(BIN_DIR, 'nl-run')} is missing, so the agent cannot use data tokens")
    return problems


def _uninstall_one(cfgdir, dry):
    path = os.path.join(cfgdir, "settings.json")
    raw = open(path).read() if os.path.exists(path) else None
    try:
        new = json.loads(raw) if raw else {}
    except ValueError:
        print(f"{path} is not valid JSON; fix it first, nothing changed.")
        return 1
    uninstall(new)
    backups = sorted(n for n in os.listdir(cfgdir) if n.startswith("settings.json.no-leaky-backup-")) \
        if os.path.isdir(cfgdir) else []
    text = json.dumps(new, indent=2) + "\n"
    if backups:
        with open(os.path.join(cfgdir, backups[-1])) as f:
            kept = f.read()
        try:
            if json.loads(kept or "{}") == new:
                text = kept
        except ValueError:
            pass
    if dry:
        print("would remove the no-leaky hooks from " + path)
        return 0
    _write(path, text)
    print(f"removed the no-leaky hooks from {path}")
    return 0


def _install_one(cfgdir, no_wrap, dry):
    """Returns (exit code, changed)."""
    path = os.path.join(cfgdir, "settings.json")
    raw = open(path).read() if os.path.exists(path) else None
    try:
        old = json.loads(raw) if raw else {}
    except ValueError:
        print(f"{path} is not valid JSON; fix it first, nothing changed.")
        return 1, False
    new = json.loads(json.dumps(old))
    changes = install(new, no_wrap)
    if not changes:
        print(f"already installed in {path}")
        return 0, False
    if dry:
        print("would change " + path + ":", *changes, sep="\n- ")
        return 0, False
    os.makedirs(cfgdir, exist_ok=True)
    if raw is not None:
        backup = f"{path}.no-leaky-backup-{time.strftime('%Y%m%d-%H%M%S')}"
        _write(backup, raw, mode_from=path)
        print(f"backup: {backup}")
    _write(path, json.dumps(new, indent=2) + "\n")
    print("changed " + path + ":", *changes, sep="\n- ")
    return 0, True


def main(argv, run_tests=True):
    import argparse
    import copy

    ap = argparse.ArgumentParser(prog="install.py")
    ap.add_argument("--config-dir")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--uninstall", action="store_true")
    ap.add_argument("--check", action="store_true", help="report whether the hooks are installed and can run")
    ap.add_argument("--no-wrap", action="append", default=[], metavar="TEXT",
                    help="leave PostToolUse hooks whose command contains TEXT unwrapped")
    args = ap.parse_args(argv)
    cfgdir = os.path.expanduser(args.config_dir or os.environ.get("CLAUDE_CONFIG_DIR") or CLAUDE_HOME)
    targets = _targets(cfgdir)
    if args.check:
        problems = _check(targets)
        for line in problems:
            print("- " + line)
        if not problems:
            print("ok: the no-leaky hooks are installed in " + " and ".join(os.path.join(d, "settings.json") for d in targets))
        return 1 if problems else 0
    if len(targets) > 1:
        print(f"{os.path.join(cfgdir, 'settings.json')} is a copy of {os.path.join(CLAUDE_HOME, 'settings.json')}, which an "
              "app re-copies over it; changing both so the hooks survive the next copy.")

    if args.uninstall:
        code = max(_uninstall_one(d, args.dry_run) for d in targets)
        if not args.dry_run:
            shim = _shim(remove=True)
            if shim:
                print(shim)
        return code

    if run_tests:
        for script in OURS + ("detect.py",):
            r = subprocess.run([sys.executable, os.path.join(HERE, script), "--test"], capture_output=True, text=True)
            if r.returncode != 0:
                print(f"{script} --test failed; nothing changed.\n{r.stdout[-2000:]}")
                return 1
    code, changed = 0, False
    for d in targets:
        c, ch = _install_one(d, args.no_wrap, args.dry_run)
        code, changed = max(code, c), changed or ch
    shim = _shim(dry=args.dry_run)
    if shim:
        print(shim)
    if changed:
        _gitignore()
    return code

def test():
    import contextlib
    import io
    import tempfile

    bad = []

    def check(label, cond):
        if not cond:
            bad.append(label)

    global BIN_DIR, CLAUDE_HOME
    real_bin, real_home = BIN_DIR, CLAUDE_HOME
    tmp_bin = tempfile.mkdtemp()
    BIN_DIR = os.path.join(tmp_bin, "bin")  # never touch the real ~/.local/bin from a self-check
    CLAUDE_HOME = os.path.join(tmp_bin, "home-claude")  # nor the real ~/.claude
    other_post = "other-rewriter --post-hook"
    original = {
        "env": {"SOME_FLAG": "1"},
        "hooks": {
            "PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "python3 /x/other-guard.py"}]}],
            "PostToolUse": [{"matcher": "Bash|Read|Grep|WebFetch", "hooks": [{"type": "command", "command": other_post}]},
                            {"matcher": "Edit", "hooks": [{"type": "command", "command": "fmt-hook"}]}],
        },
    }
    with tempfile.TemporaryDirectory() as tmp:
        cfgdir = os.path.join(tmp, "claude")
        os.makedirs(cfgdir)
        settings = os.path.join(cfgdir, "settings.json")
        raw = json.dumps(original, indent=2) + "\n"
        with open(settings, "w") as f:
            f.write(raw)
        with contextlib.redirect_stdout(io.StringIO()):
            code = main(["--config-dir", cfgdir], run_tests=False)
        check("install exit 0", code == 0)
        backups = [n for n in os.listdir(cfgdir) if n.startswith("settings.json.no-leaky-backup-")]
        check("one backup", len(backups) == 1)
        with open(settings) as f:
            s = json.load(f)
        hooks = s["hooks"]
        pre = [h["command"] for g in hooks["PreToolUse"] for h in g["hooks"]]
        check("old pre hook kept", "python3 /x/other-guard.py" in pre)
        check("guard added with matcher", any(g["matcher"] == "Bash|Read|Grep|Edit|Write" and "guard.py" in g["hooks"][0]["command"]
                                             for g in hooks["PreToolUse"]))
        check("guard path absolute", all(os.path.isabs(shlex.split(c)[1]) for c in pre if "guard.py" in c))
        post = hooks["PostToolUse"]
        wrapped = post[0]["hooks"][0]["command"]
        check("other rewriter wrapped in place", post[0]["matcher"] == "Bash|Read|Grep|WebFetch"
              and "filter.py" in wrapped and shlex.split(wrapped)[-2:] == ["--after", other_post])
        check("unrelated post hook untouched", post[1]["hooks"][0]["command"] == "fmt-hook")
        check("only MCP gets its own filter entry when the rest is wrapped",
              [g["matcher"] for g in post if any("filter.py" in h["command"] and "--after" not in h["command"]
                                                 for h in g["hooks"])] == ["mcp__.*"])
        check("prompt guard added", any("prompt_guard.py" in h["command"] for g in hooks["UserPromptSubmit"] for h in g["hooks"]))
        check("other keys kept", s["env"] == {"SOME_FLAG": "1"})

        with open(settings) as f:
            once = f.read()
        with contextlib.redirect_stdout(io.StringIO()):
            main(["--config-dir", cfgdir], run_tests=False)
        with open(settings) as f:
            check("idempotent", f.read() == once)

        shim_path = os.path.join(BIN_DIR, "nl-run")
        shim_ok = os.path.exists(shim_path) and (os.stat(shim_path).st_mode & 0o777) == 0o755
        check("nl-run shim created 0755 with the marker", shim_ok and SHIM_MARK in open(shim_path).read()
              and "nl_run.py" in open(shim_path).read())

        with contextlib.redirect_stdout(io.StringIO()):
            main(["--config-dir", cfgdir, "--uninstall"], run_tests=False)
        with open(settings) as f:
            check("uninstall restores byte for byte", f.read() == raw)
        check("uninstall removes our shim", not os.path.exists(shim_path))

        with open(shim_path, "w") as f:
            f.write("#!/bin/sh\necho someone else's tool\n")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            main(["--config-dir", cfgdir], run_tests=False)
        check("foreign nl-run left alone and reported", "someone else" in open(shim_path).read()
              and "not ours" in out.getvalue())
        with contextlib.redirect_stdout(io.StringIO()):
            main(["--config-dir", cfgdir, "--uninstall"], run_tests=False)
        check("uninstall keeps a foreign nl-run", os.path.exists(shim_path))
        os.remove(shim_path)

        bare = os.path.join(tmp, "bare")
        os.makedirs(bare)
        old_env = os.environ.get("CLAUDE_CONFIG_DIR")
        os.environ["CLAUDE_CONFIG_DIR"] = bare
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                main([], run_tests=False)
        finally:
            if old_env is None:
                os.environ.pop("CLAUDE_CONFIG_DIR")
            else:
                os.environ["CLAUDE_CONFIG_DIR"] = old_env
        with open(os.path.join(bare, "settings.json")) as f:
            s = json.load(f)
        check("env config dir used, filter added on its own",
              any(g.get("matcher") == "Bash|Read|Grep|mcp__.*" and "filter.py" in g["hooks"][0]["command"]
                  for g in s["hooks"]["PostToolUse"]))

        partial = os.path.join(tmp, "partial")
        os.makedirs(partial)
        real_file = os.path.join(tmp, "dotfiles-settings.json")
        with open(real_file, "w") as f:
            json.dump({"hooks": {"PostToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "x"}]}]}}, f)
        os.chmod(real_file, 0o600)
        os.symlink(real_file, os.path.join(partial, "settings.json"))
        with contextlib.redirect_stdout(io.StringIO()):
            main(["--config-dir", partial], run_tests=False)
        with open(real_file) as f:
            s = json.load(f)
        post = s["hooks"]["PostToolUse"]
        check("partial overlap: Bash wrapped", "filter.py" in post[0]["hooks"][0]["command"])
        check("partial overlap: Read and Grep get their own filter",
              any(g.get("matcher") == "Read|Grep|mcp__.*" and "filter.py" in g["hooks"][0]["command"] for g in post))
        check("symlink kept", os.path.islink(os.path.join(partial, "settings.json")))
        bk = [n for n in os.listdir(partial) if "no-leaky-backup" in n]
        check("backup keeps 0600", bk and (os.stat(os.path.join(partial, bk[0])).st_mode & 0o777) == 0o600)

        repo = os.path.join(tmp, "repo")
        os.makedirs(os.path.join(repo, ".git"))
        with open(os.path.join(repo, ".gitignore"), "w") as f:
            f.write("node_modules/")
        here = os.getcwd()
        os.chdir(repo)
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                _gitignore()
                _gitignore()
        finally:
            os.chdir(here)
        with open(os.path.join(repo, ".gitignore")) as f:
            check("gitignore gains the report once", f.read() == "node_modules/\n" + REPORT + "\n")

        status = {"hooks": {"PostToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "status-hook --pid"}]}]}}
        nw = os.path.join(tmp, "nowrap")
        os.makedirs(nw)
        with open(os.path.join(nw, "settings.json"), "w") as f:
            json.dump(status, f)
        with contextlib.redirect_stdout(io.StringIO()):
            main(["--config-dir", nw, "--no-wrap", "status-hook"], run_tests=False)
        with open(os.path.join(nw, "settings.json")) as f:
            post = json.load(f)["hooks"]["PostToolUse"]
        check("no-wrap: hook left as is", post[0]["hooks"][0]["command"] == "status-hook --pid")
        check("no-wrap: filter added on its own",
              any(g.get("matcher") == "Bash|Read|Grep|mcp__.*" and "filter.py" in g["hooks"][0]["command"] for g in post))

        if os.path.exists(shim_path):
            os.remove(shim_path)  # earlier installs in this check put it there
        with open(settings, "w") as f:
            f.write(raw)
        with contextlib.redirect_stdout(io.StringIO()):
            code = main(["--config-dir", cfgdir, "--dry-run"], run_tests=False)
        with open(settings) as f:
            check("dry run writes nothing", f.read() == raw and code == 0 and not os.path.exists(shim_path))

    # v0.2.3: a profile whose settings.json an app re-copies from ~/.claude/settings.json (Orca does)
    base = {"hooks": {"PostToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "status-hook"}]}]}}
    os.makedirs(CLAUDE_HOME, exist_ok=True)
    profile = os.path.join(tmp_bin, "profile")
    os.makedirs(profile)
    text = json.dumps(base, indent=2) + "\n"
    for d in (CLAUDE_HOME, profile):
        with open(os.path.join(d, "settings.json"), "w") as f:
            f.write(text)
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        main(["--config-dir", profile, "--no-wrap", "status-hook"], run_tests=False)
    src, cp = (json.load(open(os.path.join(d, "settings.json"))) for d in (CLAUDE_HOME, profile))
    has_guard = lambda s: any("guard.py" in h["command"] for g in s["hooks"].get("PreToolUse", []) for h in g["hooks"])  # noqa: E731
    check("synced profile: hooks go into the source too", has_guard(src) and has_guard(cp))
    check("synced profile: the user is told why", "copy" in out.getvalue())
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = main(["--config-dir", profile, "--check"], run_tests=False)
    check("check passes on a healthy install", code == 0 and "ok" in out.getvalue())
    src["hooks"]["PreToolUse"] = []
    with open(os.path.join(CLAUDE_HOME, "settings.json"), "w") as f:
        json.dump(src, f)
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = main(["--config-dir", CLAUDE_HOME, "--check"], run_tests=False)
    check("check fails and names the missing hook", code == 1 and "guard.py" in out.getvalue())
    broken = json.load(open(os.path.join(profile, "settings.json")))
    for g in broken["hooks"]["UserPromptSubmit"]:
        for h in g["hooks"]:
            h["command"] = h["command"].replace(shlex.split(h["command"])[0], "/nonexistent/python3", 1)
    with open(os.path.join(profile, "settings.json"), "w") as f:
        json.dump(broken, f)
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = main(["--config-dir", profile, "--check"], run_tests=False)
    check("check fails when the interpreter is gone", code == 1 and "/nonexistent/python3" in out.getvalue())

    # Orca rewrites the copy with its own hook groups moved to the end: same content, other order.
    two = {"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "app-hook"}]},
                                    {"matcher": "Bash", "hooks": [{"type": "command", "command": "user-hook"}]}]}}
    swapped = {"hooks": {"PreToolUse": list(reversed(two["hooks"]["PreToolUse"]))}}
    reordered = os.path.join(tmp_bin, "reordered")
    os.makedirs(reordered)
    with open(os.path.join(CLAUDE_HOME, "settings.json"), "w") as f:
        json.dump(two, f)
    with open(os.path.join(reordered, "settings.json"), "w") as f:
        json.dump(swapped, f)
    check("a reordered copy is still a copy", _targets(reordered) == [CLAUDE_HOME, reordered])
    # A profile that mirrors ~/.claude through symlinks is managed by an app even if its settings drifted.
    mirrored = os.path.join(tmp_bin, "mirrored")
    os.makedirs(mirrored)
    os.makedirs(os.path.join(CLAUDE_HOME, "skills"), exist_ok=True)
    os.symlink(os.path.join(CLAUDE_HOME, "skills"), os.path.join(mirrored, "skills"))
    with open(os.path.join(mirrored, "settings.json"), "w") as f:
        f.write('{"model": "drifted"}\n')
    check("a profile with symlinks into ~/.claude counts as a copy", _targets(mirrored) == [CLAUDE_HOME, mirrored])

    lone = os.path.join(tmp_bin, "lone")
    os.makedirs(lone)
    with open(os.path.join(lone, "settings.json"), "w") as f:
        f.write('{"model": "x"}\n')
    before = open(os.path.join(CLAUDE_HOME, "settings.json")).read()
    with contextlib.redirect_stdout(io.StringIO()):
        main(["--config-dir", lone], run_tests=False)
    check("a profile that is not a copy leaves the source alone",
          open(os.path.join(CLAUDE_HOME, "settings.json")).read() == before)

    # the interpreter written into hooks survives upgrades and is never a shim or a venv
    ok_version = lambda exe: True  # noqa: E731
    check("python3 on PATH is preferred", _python(lambda n: "/usr/local/bin/python3", ok_version) == "/usr/local/bin/python3")
    for shim in ("/home/u/.pyenv/shims/python3", "/home/u/.asdf/shims/python3", "/w/app/.venv/bin/python3"):
        check(f"not a shim or venv: {shim}", _python(lambda n, s=shim: s, ok_version) != shim)
    check("an old python3 is skipped", _python(lambda n: "/usr/bin/python3", lambda exe: False) != "/usr/bin/python3")
    check("no python3 on PATH falls back", bool(_python(lambda n: None, ok_version)))

    BIN_DIR, CLAUDE_HOME = real_bin, real_home
    __import__("shutil").rmtree(tmp_bin, ignore_errors=True)

    # Every SKILL.md must parse as YAML front matter, or skill installers skip it without a word.
    import glob
    for f in glob.glob(os.path.join(HERE, "..", "..", "*", "SKILL.md")):
        head = open(f).read().split("---")[1]
        for line in head.strip().splitlines():
            key, _, val = line.partition(": ")
            if val and not val.startswith(('"', "'")) and (": " in val or " #" in val):
                bad.append(f"{os.path.basename(os.path.dirname(f))} SKILL.md {key} needs quotes")
        # !`...` in a skill body is a shell command Claude Code runs when the skill loads.
        if "!`" in open(f).read():
            bad.append(f"{os.path.basename(os.path.dirname(f))} SKILL.md holds a !` command directive")

    if bad:
        print("WRONG:", *bad, sep="\n  ")
        sys.exit(1)
    print("ok: install self-check passed")


if __name__ == "__main__":
    if "--test" in sys.argv:
        test()
    else:
        sys.exit(main(sys.argv[1:]))
