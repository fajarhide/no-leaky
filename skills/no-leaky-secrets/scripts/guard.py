#!/usr/bin/env python3
"""PreToolUse guard: credential sources never reach the transcript, whatever their format.

Decides by where bytes come from, never by what they look like. Using a secret stays
allowed: `. file`, `$(cat file)`, `jq --rawfile`, a pipe into curl or ssh, or a
redirect to a file. Printing it does not, and neither does a home-made filter on it.

Self-check: python3 guard.py --test
"""

import base64
import fnmatch
import json
import os
import re
import shlex
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import detect  # noqa: E402
import vault  # noqa: E402


# Top-level dotfiles under a home directory are secret unless listed here. A new token
# file is then covered from the day it appears, and a false alarm costs one reword.
SAFE_DOTFILES = {
    ".bash_history", ".bash_logout", ".bash_profile", ".bashrc", ".cache", ".claude",
    ".editorconfig", ".gitconfig", ".gitignore", ".gitignore_global",
    ".hushlogin", ".local", ".npm", ".nvm", ".pnpm-state", ".profile", ".rustup",
    ".cargo", ".tmux.conf", ".viminfo", ".vimrc", ".zprofile", ".zsh_history",
    ".zshenv", ".zshrc", ".config", ".ssh", ".aws", ".kube", ".docker", ".cloudflared",
    ".gnupg", ".DS_Store", ".Trash", ".bun", ".codex", ".gemini",
}
HOME_FILE = re.compile(r"^(?:~|\$HOME|\$\{HOME\}|/root|/home/[^/]+|/Users/[^/]+)/(\.[^/]+)(/.*)?$")
SECRET_SUBPATH = re.compile(
    r"(?:^|/)(?:\.aws/credentials|\.kube/config|\.docker/config\.json|\.config/gh/hosts\.yml"
    r"|\.config/rclone/rclone\.conf|\.cloudflared/[^/]+|\.gnupg/.+"
    r"|\.cache/no-leaky/vault\.json|\.config/no-leaky/data\.key)$"
    r"|(?:^|/)\.ssh/(?!.*\.pub$)(?!config$|known_hosts|authorized_keys)[^/]+$"
)
SECRET_DIR = re.compile(r"^/etc/wireguard/|^/etc/shadow$|^/proc/[^/]+/environ$")
CODE_EXT = re.compile(r"\.(?:py|rb|rs|js|ts|tsx|jsx|go|md|sh|erb|html|css|lock|snap|txt)$")
SAFE_ENV = re.compile(r"\.(?:example|sample|template|dist)$")
SECRET_NAME = re.compile(
    r"^\.env(?:\..+)?$|\.env$|secrets?(?:\.[\w-]+)?$|credentials?(?:\.\w+)?$"
    r"|passw(?:or)?d|\.(?:pem|key|pw|p12|pfx|age)$|^(?:id_rsa|id_ed25519|id_ecdsa)$|\.ghcr-pat"
)

READERS = {
    "awk", "base64", "bat", "cat", "column", "cut", "egrep", "fgrep", "grep", "head", "jq",
    "less", "more", "nl", "od", "paste", "rev", "rg", "sed", "sort", "strings", "tac", "tail",
    "tr", "uniq", "vim", "view", "xxd", "yq",
}
# Commands that print secrets with no file argument.
SECRET_COMMANDS = [
    (re.compile(r"\bcrontab\s+-l\b"), "crontab -l"),
    (re.compile(r"\bsystemctl\s+(?:show|cat)\b"), "systemctl show or cat"),
    (re.compile(r"\b(?:docker|podman)\s+inspect\b(?!.*(?:\.State|\.Image|\.RestartCount|\.NetworkSettings|\.Name|\.Mounts))"), "docker inspect"),
    (re.compile(r"\bprintenv\b|(?:^|\s)env\s*$"), "printenv or env"),
    (re.compile(r"\bexport\s+-p\b|\bdeclare\s+-[a-zA-Z]*[xp]|(?:^|\s)(?:set|export|declare|typeset)\s*$"),
     "export -p, set or declare"),
    (re.compile(r"\bps\b[^|;&]*(?:\baux\b|-ef\b|-eo\s+\S*args|-o\s+\S*(?:args|command))"), "ps with arguments"),
    (re.compile(r"\bsecurity\s+find-[\w-]*password\b.*\s-w\b"), "security find-generic-password -w"),
    (re.compile(r"\bgh\s+auth\s+token\b"), "gh auth token"),
    (re.compile(r"\bpgrep\b[^|;&]*(?:\s-[A-Za-z]*a[A-Za-z]*\b|--list-full)"), "pgrep with arguments"),
    (re.compile(r"\bkubectl\s+get\s+secrets?\b.*-o\b"), "kubectl get secret -o"),
    (re.compile(r"\bvault\s+(?:kv\s+)?(?:get|read)\b"), "vault read"),
    (re.compile(r"\bsecretsmanager\s+get-secret-value\b|\bkeyvault\s+secret\s+show\b"), "cloud secret read"),
]
# A pipeline ending in one of these does not show the bytes to the model.
SINKS = {
    "cmp", "curl", "docker", "gh", "kubectl", "md5", "md5sum", "scp", "security", "sha1sum",
    "sha256sum", "shasum", "ssh", "wc", "wrangler", "kamal", "npx",
}
WRAPPERS = {"bash", "doas", "eval", "kamal", "kubectl", "nl-run", "sh", "ssh", "sudo", "timeout", "watch", "zsh",
            "docker", "X"}
ADVICE = (
    "Do not retry with another filter, and do not redact it yourself: that is how it leaked "
    "often. Use it without printing: `. file`, `\"$(cat file)\"`, `jq --rawfile`, a pipe "
    "into the command that needs it, or a redirect to a file. To inspect: `wc -l`, `stat`, "
    "`shasum`, `cmp`, `grep -c`, and prove it works by its effect (HTTP status). If this is "
    "a false alarm, say so and ask the user to run it with `!`."
)


# Commands that search or query by a value: given a token they match its text and quietly return nothing.
VAULT = vault.VAULT_PATH
LOOKUP_WRAPPERS = {"sudo", "doas", "env", "command", "xargs", "timeout", "nice", "nohup", "time", "stdbuf"}
PS_ADVICE = (
    "Blocked: `ps` with arguments prints every process's command line, and those often carry tokens and passwords. "
    "To find a process, run `pgrep -f <name or script>`: it prints only PIDs and matches the full command line, so it "
    "finds `python3 worker.py` too. Then `ps -o pid,etime,comm -p <pid>` for its age. If you need the arguments it "
    "was started with, ask the user to look.")


def _known(text):
    """True when the text holds a token minted on this machine. A token-shaped string the vault never saw (a test
    fixture, a doc example) stands for no data, so writing or searching it harms nothing."""
    toks = vault.TOKEN_RE.findall(text or "")
    if not toks:
        return False
    _, missing = vault.resolve(" ".join(toks), VAULT)
    return len(missing) < len(toks)


def _lookup_tool(stage):
    words = list(stage)
    while words and os.path.basename(words[0]) in LOOKUP_WRAPPERS:
        words = words[1:]
        while words and (words[0].startswith("-") or "=" in words[0] or words[0].isdigit()):
            words = words[1:]
    return os.path.basename(words[0]) if words else ""


LOOKUPS = {"grep", "egrep", "fgrep", "rg", "ag", "ack", "awk", "sed", "jq", "yq", "find", "psql", "mysql", "sqlite3",
           "mongosh", "mongo", "redis-cli", "duckdb", "clickhouse-client"}
DATA_TOKEN_ADVICE = (
    "Blocked: this {what} holds a data token like [email: k3f9a01c27b4], which only nl-run can resolve. Run as written it "
    "matches the token's text, not the value, and the answer would be wrong. Run the same command through nl-run "
    "(for example nl-run -- grep -n '[email: k3f9a01c27b4]' users.csv); matching lines come back as tokens.")


DATA_WRITE_ADVICE = (
    "Blocked: this writes a data token like [email: k3f9a01c27b4] into {path}, which would put the token's text in "
    "the file instead of the value and break it. Write the change with a script fed to nl-run on stdin, which resolves "
    "tokens: nl-run -- python3 - < fix.py. A token in a Markdown or text note is fine.")
NOTE_EXT = (".md", ".markdown", ".txt", ".rst")


def deny_message(hit):
    if hit in ("ps with arguments", "pgrep with arguments"):
        return PS_ADVICE
    if hit.startswith("data-write:"):
        return DATA_WRITE_ADVICE.format(path=hit.split(":", 1)[1] or "a file")
    if hit.startswith("data-token:"):
        return DATA_TOKEN_ADVICE.format(what="search" if hit.endswith("Grep") else "command")
    if hit.startswith("git add "):
        return (f"Blocked: `{hit}` would put a credential source into git history, which keeps it "
                "after the file is deleted and travels with every clone and push. Add it to .gitignore "
                "and commit a .env.example with dummy values instead. If this is a false alarm, say so "
                "and ask the user to run it with `!`.")
    return f"Blocked: this would print a credential source ({hit}) into the transcript. {ADVICE}"


_CFG = dict(detect.DEFAULT_CONFIG)


def _matches(path, patterns):
    full = os.path.expanduser(path)
    for p in patterns:
        p = os.path.expanduser(p)
        if fnmatch.fnmatch(full, p) or full == p.rstrip("/") or full.startswith(p.rstrip("/") + "/"):
            return True
    return False


def is_source(token):
    path = token.strip("'\"").rstrip(";,)")
    if not path or path.startswith("-") or "://" in path:
        return False
    if _matches(path, _CFG.get("safe_paths", [])):
        return False
    if _matches(path, _CFG.get("extra_credential_globs", [])):
        return True
    if SECRET_DIR.search(path) or SECRET_SUBPATH.search(path):
        return True
    m = HOME_FILE.match(path)
    if m and not m.group(2) and m.group(1) not in SAFE_DOTFILES:
        return True
    # A glob such as `.env*` or `*.pem` reads the files it expands to; judge the literal part.
    name = re.sub(r"[*?\[\]]", "", path.rsplit("/", 1)[-1])
    if CODE_EXT.search(name) or SAFE_ENV.search(name):
        return False
    return bool(SECRET_NAME.search(name))


def split_tokens(text):
    lexer = shlex.shlex(text, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    try:
        return list(lexer)
    except ValueError:
        return text.split()


def strip_heredocs(command):
    """Keep a heredoc body only when a shell runs it; prose and file contents stay out."""
    out, lines, i = [], command.split("\n"), 0
    while i < len(lines):
        line = lines[i]
        m = re.search(r"<<-?\s*['\"]?(\w+)['\"]?", line)
        i += 1
        out.append(line)
        if not m:
            continue
        body = []
        while i < len(lines) and lines[i].strip() != m.group(1):
            body.append(lines[i])
            i += 1
        i += 1
        if re.search(r"(?<![\w./-])(?:bash|sh|zsh|ssh)\b", line):
            out.extend(body)
    return "\n".join(out)


RUN_SCRIPT = re.compile(
    r"(?:^|[;&|(\n]|(?<![\w./-])(?:bash|sh|zsh|source|exec)\s|(?:^|\s)\.\s)\s*([\w./~-]+\.sh)\b", re.M)


def embedded_scripts(command):
    """Text hidden in base64 and in local scripts that a command runs or encodes."""
    for blob in re.findall(r"[A-Za-z0-9+/=]{24,}", command):
        try:
            text = base64.b64decode(blob + "=" * (-len(blob) % 4)).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if " " in text or "\n" in text:
            yield text
    # Only a script the command runs: reading, comparing or naming one does not execute it.
    for path in RUN_SCRIPT.findall(command):
        full = os.path.expanduser(path)
        if os.path.isfile(full) and os.path.getsize(full) < 200_000:
            try:
                yield open(full, encoding="utf-8", errors="ignore").read()
            except OSError:
                pass


def check_pipeline(stages, depth):
    if depth < 4:
        for stage in stages:
            if stage and stage[0] in WRAPPERS:
                for token in stage[1:]:
                    if " " in token or "|" in token:
                        hit = check_command(token, depth=depth + 1)
                        if hit:
                            return hit
    if ends_unseen(stages):
        return None
    for stage in stages:
        if not stage:
            continue
        if stage[0] in ("grep", "egrep", "rg") and any(re.fullmatch(r"-\w*[cql]\w*", t) for t in stage):
            continue
        if stage[0] == "sed" and any(t.startswith("-i") for t in stage):
            continue
        # Staging a credential file is a leak that outlives the session.
        if stage[0] == "git" and len(stage) > 1 and stage[1] == "add":
            for t in stage[2:]:
                if is_source(t):
                    return "git add " + t
        # `git show REV:path` and `git cat-file -p REV:path` print a file from history.
        if stage[0] == "git" and len(stage) > 1 and stage[1] in ("show", "cat-file"):
            for t in stage[2:]:
                if ":" in t and "://" not in t and is_source(t.split(":", 1)[1]):
                    return t
        sources = [t for t in stage if is_source(t)]
        if sources and any(t in READERS for t in stage):
            return sources[0]
        if "<" in stage and stage.index("<") + 1 < len(stage) and is_source(stage[stage.index("<") + 1]):
            return stage[stage.index("<") + 1]
    return None


def ends_unseen(stages):
    """True when the bytes go to a file or a consumer. A sink alone prints what it runs."""
    last = stages[-1] if stages else []
    if any(t in (">", ">>", "&>") for t in last):
        return True
    return len(stages) > 1 and bool(last) and last[0] in SINKS


def statements(text):
    """Split into statements of pipeline stages, respecting quotes."""
    quote, chars = None, []
    for c in text:
        if quote:
            quote = None if c == quote else quote
        elif c in "'\"":
            quote = c
        elif c == "\n":
            c = " ; "
        chars.append(c)
    result, stages, stage = [], [], []
    for token in split_tokens("".join(chars)):
        if token in (";", "&&", "||", "&", ";;"):
            if stage or stages:
                result.append(stages + [stage])
            stages, stage = [], []
        elif token in ("|", "|&"):
            stages.append(stage)
            stage = []
        else:
            stage.append(token)
    if stage or stages:
        result.append(stages + [stage])
    return result


def check_command(command, cfg=None, depth=0):
    global _CFG
    if cfg is not None:
        _CFG = cfg
    text = strip_heredocs(command)
    if depth < 4:
        for inner in embedded_scripts(text):
            hit = check_command(inner, depth=depth + 1)
            if hit:
                return hit
    # `$(cat file)` hands the value to the outer command; echo would print it straight back.
    if not re.search(r"\b(?:echo|printf)\b[^|;&\n]*\$\(", text):
        text = re.sub(r"\$\([^()]*\)", "X", text)
    for stages in statements(text):
        last = stages[-1]
        # Quoted arguments stay out, so a commit message naming a command does not trip this.
        for stage in stages:
            flat = " ".join(t for t in stage if " " not in t)
            full = " ".join(stage)  # a --format value with spaces names the safe fields
            for pattern, name in SECRET_COMMANDS:
                if name == "docker inspect":
                    # Only when docker or podman runs here; a grep, sed or commit message naming it prints nothing.
                    at = next((k for k, t in enumerate(stage[:-1])
                               if os.path.basename(t) in ("docker", "podman") and stage[k + 1] == "inspect"), None)
                    found = at is not None and pattern.search(" ".join(stage[at:]))
                else:
                    found = pattern.search(flat)
                if found:
                    filtered = last and last[0] in ("grep", "egrep") and any(re.fullmatch(r"-\w*[coql]\w*E?", t) for t in last)
                    if not (ends_unseen(stages) or filtered):
                        return name
        hit = check_pipeline(stages, depth)
        if hit:
            return hit
    return None


def check(payload, cfg=None):
    global _CFG
    if cfg is not None:
        _CFG = cfg
    tool = payload.get("tool_name")
    args = payload.get("tool_input", {})
    if tool == "Bash":
        command = args.get("command", "")
        if vault.TOKEN_RE.search(command) and _known(command):
            for stages in statements(strip_heredocs(command)):
                for stage in stages:
                    if stage and _lookup_tool(stage) in LOOKUPS and _known(" ".join(stage)):
                        return "data-token:Bash"
        return check_command(command)
    if tool == "Grep" and _known(args.get("pattern") or ""):
        return "data-token:Grep"
    if tool in ("Write", "Edit"):
        path = args.get("file_path") or ""
        text = args.get("content") if tool == "Write" else args.get("new_string")
        if _known(text) and not path.lower().endswith(NOTE_EXT):
            return "data-write:" + path
    if tool == "Read" and is_source(args.get("file_path", "")):
        return args["file_path"]
    if tool == "Grep" and args.get("output_mode") == "content":
        for key in ("path", "glob"):
            if is_source(args.get(key) or ""):
                return args[key]
    return None


def main():
    try:
        payload = json.load(sys.stdin)
    except (ValueError, OSError):
        return
    hit = check(payload, detect.load_config())
    if hit:
        json.dump({"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": deny_message(hit),
        }}, sys.stdout)


def test():
    import tempfile

    cfg = dict(detect.DEFAULT_CONFIG)
    denied = [
        "cat ~/.storage-creds",
        "sed -E 's/=.*/=x/; s/:.*/:x/' ~/.storage-creds | cut -c1-40",
        "grep -v 'expected' .kamal/secrets.production",
        "head -1 /root/.env",
        "crontab -l | cut -c1-160",
        "ssh host 'cat ~/.my-token'",
        "ssh host 'systemctl show foo'",
        "echo " + base64.b64encode(b"cat /etc/app/db_password\n").decode() + " | base64 -d | bash",
        "cut -d= -f1 ~/.storage-creds",
        "ssh host bash -s <<S\ncat .env\nS",
        "echo $(cat ~/.my-token)",
        "security find-generic-password -s foo -w",
        "ps -eo pid,args",
        "docker inspect web",
        "cat .env | grep DB",
        "awk '{print $2}' ~/.ssh/id_ed25519",
        "docker exec app printenv",
        "ssh host 'cat /srv/app/.env'",
        "cat ~/.claude.json",
        "gh auth token",
        "kubectl get secret db -o yaml",
        "cat /etc/wireguard/wg0.conf",
        "cat .env*",
        "cat config/*.pem",
        "export -p",
        "set",
        "declare -x",
        "declare -p",
        "cat /proc/self/environ",
        "git show HEAD:.env",
        "git show abc123:config/.env.production",
        "git cat-file -p HEAD:.env",
        "git add .env",
        "git add -f config/.env.production",
        "cd app && git add src/main.py .env.local",
        "git add ~/.ssh/id_ed25519",
        "infisical run -- env",
        "doppler run -- printenv",
        "nl-run -- sh -c 'cat .env'",
        "cat ~/.cache/no-leaky/vault.json",
        "cat ~/.config/no-leaky/data.key",
    ]
    allowed = [
        ". ~/.my-token",
        "set -a; . ~/.my-token; set +a",
        "wc -l ~/.storage-creds",
        "shasum -a 256 ~/.storage-creds",
        "stat ~/.storage-creds",
        "grep -c x ~/.storage-creds",
        "jq -n --rawfile b ~/.my-token '{b:$b}' | curl -d @- https://x",
        'curl -H "Authorization: Bearer $(cat ~/.api-token)" https://x',
        "cat ~/.my-token | ssh host 'cat > /tmp/f'",
        "cat ~/.my-token > /tmp/f",
        "$(cat ~/.deploy/dev) 'uptime'",
        "cat ~/.zshrc",
        "cat ~/.ssh/id_ed25519.pub",
        "cat .env.example",
        "cat app/services/credentials.rb",
        "cat > notes.md <<E\ncat ~/.my-token\nE",
        "git commit -m 'never cat ~/.my-token'",
        "ls -la ~/.ssh",
        "crontab -l | grep -oE 'rake [a-z:]+'",
        "docker inspect -f '{{.State.StartedAt}}' web",
        "ps -eo pid,comm",
        "sed -i 's/a/b/' .env",
        "set -a; . ./.env; set +a; npm start",
        "op run -- npm start",
        "ls ~/.claude/projects/-Users-x-proj/memory",
        'ls "/Users/x/Library/Application Support/tool/profiles/abc/home/projects/p"',
        "wc -c ~/.claude.json",
        "docker inspect --format '{{.State.Status}} {{.State.ExitCode}}' app",
        "docker inspect -f '{{.State.Status}}' app",
        "set -e",
        "set -euo pipefail",
        "export FOO=bar",
        "git show HEAD:README.md",
        "git show HEAD --stat",
        "cat *.md",
        "git add .env.example",
        "git add src/app.py .gitignore",
        "git add -A",
        "git commit -m 'stop tracking .env'",
        'nl-run -- psql "$DATABASE_URL" -c "select id from orders"',
    ]
    bad = [c for c in denied if not check_command(c, cfg)] + [c for c in allowed if check_command(c, cfg)]
    if "pgrep -f" not in deny_message("ps with arguments"):
        bad.append("ps denial points to pgrep -f")
    for c in ("pgrep -af worker.py", "pgrep --list-full worker", "podman inspect web"):
        if not check_command(c, cfg):
            bad.append("denied: " + c)
    for c in ('grep -n "docker inspect" README.md', "sed -n '/podman inspect/p' notes.md",
              'git commit -m "guard docker inspect too"'):
        if check_command(c, cfg):
            bad.append("text that only mentions it allowed: " + c)
    for c in ("sudo docker inspect web", "ssh host 'docker inspect web'"):
        if not check_command(c, cfg):
            bad.append("denied: " + c)
    for c in ("pgrep -f worker.py", "pgrep -l worker", "podman inspect -f '{{.State.Status}}' web"):
        if check_command(c, cfg):
            bad.append("allowed: " + c)
    global VAULT
    real_vault = VAULT
    vdir = tempfile.mkdtemp()
    VAULT = os.path.join(vdir, "vault.json")
    tok = "[email: k1234abcd5678]"
    vault.remember({tok: "someone@shop-a.co.id"}, VAULT)
    stranger = "[email: k0000000000ff]"  # looks like a token, never minted here: a test fixture or a doc example
    if check({"tool_name": "Write", "tool_input": {"file_path": "tests/test_tokens.py", "content": f"T = '{stranger}'"}}, cfg):
        bad.append("a token the vault does not know may be written")
    if check({"tool_name": "Bash", "tool_input": {"command": f"grep -n '{stranger}' tests/x.py"}}, cfg):
        bad.append("a lookup for a token the vault does not know is allowed")
    hit = check({"tool_name": "Grep", "tool_input": {"pattern": tok, "path": "users.csv"}}, cfg)
    if not hit or "nl-run" not in deny_message(hit):
        bad.append("Grep with a data token denied with an nl-run hint")
    hit = check({"tool_name": "Bash", "tool_input": {"command": f"grep -n '{tok}' users.csv"}}, cfg)
    if not hit or "nl-run" not in deny_message(hit):
        bad.append("Bash with a data token outside nl-run denied with an nl-run hint")
    for c in (f"/usr/bin/grep -n '{tok}' users.csv", f"sudo grep '{tok}' a.log", f"cat a.log | xargs grep '{tok}'"):
        if not check({"tool_name": "Bash", "tool_input": {"command": c}}, cfg):
            bad.append("token lookup behind a path or wrapper denied: " + c.split()[0])
    if check({"tool_name": "Bash", "tool_input": {"command": f"nl-run -- grep -n '{tok}' users.csv"}}, cfg):
        bad.append("nl-run with a data token allowed")
    if check({"tool_name": "Grep", "tool_input": {"pattern": "user_email", "path": "app.py"}}, cfg):
        bad.append("Grep without a token allowed")
    # review 3: a token written into a real file corrupts it
    for payload in ({"tool_name": "Write", "tool_input": {"file_path": "/srv/nginx.conf", "content": f"server {tok}:8080;"}},
                    {"tool_name": "Edit", "tool_input": {"file_path": "app.yml", "old_string": "a", "new_string": f"host: {tok}"}}):
        hit = check(payload, cfg)
        if not hit or "nl-run" not in deny_message(hit):
            bad.append(f"{payload['tool_name']} of a token into a config file denied")
    if check({"tool_name": "Write", "tool_input": {"file_path": "notes/report.md", "content": f"customer {tok} fails"}}, cfg):
        bad.append("token in a markdown report allowed")
    VAULT = real_vault
    if "git history" not in deny_message(check_command("git add .env", cfg) or ""):
        bad.append("git add denial names git history")

    with tempfile.TemporaryDirectory() as tmp:
        script = os.path.join(tmp, "backup-knowledge.sh")
        other = os.path.join(tmp, "other.sh")
        for p in (script, other):
            with open(p, "w") as f:
                f.write("#!/bin/sh\ncrontab -l > /dev/null\ncat ~/.my-token\n")
        for c in (f"grep -n extras_for {script}", f"cmp {script} {other}", f"shasum {script}",
                  f"cat > {tmp}/run.sh <<'E'\n{script} my-repo\nE"):
            if check_command(c, cfg):
                bad.append("false alarm: " + c)
        for c in (f"bash {script}", f"sh {script} arg", script, f"source {script}"):
            if not check_command(c, cfg):
                bad.append("runs a script that prints: " + c)

    cfg2 = dict(cfg, extra_credential_globs=["/srv/*/conf/*.ini"], safe_paths=["~/.mytool"])
    if not check_command("cat /srv/app/conf/db.ini", cfg2):
        bad.append("extra glob not denied")
    if check_command("cat ~/.mytool", cfg2) or check({"tool_name": "Read", "tool_input": {"file_path": os.path.expanduser("~/.mytool")}}, cfg2):
        bad.append("safe path denied")
    if not check_command("cat ~/.mytool", cfg):
        bad.append("unknown dotfile allowed without config")
    if not check({"tool_name": "Read", "tool_input": {"file_path": "/Users/x/.my-token"}}, cfg):
        bad.append("Read of a token file allowed")
    if check({"tool_name": "Read", "tool_input": {"file_path": "/Users/x/.zshrc"}}, cfg):
        bad.append("Read of .zshrc denied")
    if check({"tool_name": "Grep", "tool_input": {"path": ".env", "output_mode": "count"}}, cfg):
        bad.append("Grep count on .env denied")
    if not check({"tool_name": "Grep", "tool_input": {"path": ".env", "output_mode": "content"}}, cfg):
        bad.append("Grep content on .env allowed")
    if not check({"tool_name": "Grep", "tool_input": {"path": ".", "glob": ".env*", "output_mode": "content"}}, cfg):
        bad.append("Grep content with an .env glob allowed")
    if check({"tool_name": "Grep", "tool_input": {"path": ".", "glob": "*.py", "output_mode": "content"}}, cfg):
        bad.append("Grep content on *.py denied")
    msg = deny_message(".env")
    if "`. file`" not in msg or "with `!`" not in msg or ".env" not in msg:
        bad.append("deny message lacks the safe way or the ! line")

    if bad:
        print("WRONG:", *bad, sep="\n  ")
        sys.exit(1)
    print(f"ok: {len(denied)} denied, {len(allowed)} allowed")


if __name__ == "__main__":
    if "--test" in sys.argv:
        test()
    else:
        main()
