---
name: no-leaky-secrets
description: Use before reading a config, .env, credentials file, token file, private key, container or process state (docker inspect, ps, printenv, crontab, systemctl), before staging files with git add, or before sharing a session, so a secret is used without being printed into the transcript. Also use when a command was blocked as a credential source, when a secret already appeared in output, or when asked to set up the no-leaky hooks.
---

# no-leaky-secrets

Anything a command prints lands in the transcript, and from there in backups, shared sessions and the provider's logs. A secret you only needed to *use* should never be *shown*.

## Use it, do not show it

| You need to | Leaking way | Safe way |
| --- | --- | --- |
| Start an app with its env | `cat .env`, then copy values | `set -a; . ./.env; set +a; npm start`, or `op run -- npm start` |
| Call an API with a token | `echo $TOKEN`, paste it into the command | `curl -H "Authorization: Bearer $(cat ~/.token)" https://...` |
| Check a token works | print it and eyeball it | call the API and read the HTTP status: `curl -s -o /dev/null -w '%{http_code}' ...` |
| Check `.env` has every key | `cat .env`, `grep KEY .env` | `grep -c '^KEY=' .env`, or `cut -d= -f1` on `.env.example` and compare names |
| Compare two secret files | `diff a b` | `cmp a b`, `shasum a b` |
| Debug a container | `docker inspect app` | `docker inspect --format '{{.State.Status}} {{.State.ExitCode}}' app`, `docker logs app` |
| Find a process | `ps aux` | `ps -eo pid,comm`, `pgrep -l name` |
| Read a cron job | `crontab -l` | `crontab -l \| grep -c job-name`, or ask the user to look |
| Pass a file to a remote host | `cat key`, then paste | `cat key \| ssh host 'cat > /path'`, `scp` |
| Put a secret in a JSON body | inline it | `jq -n --rawfile k ~/.token '{key:$k}' \| curl -d @- ...` |
| Share config with the team | `git add .env` | add `.env` to `.gitignore`, commit a `.env.example` with dummy values |

Rules behind the table:

- Load, pipe or redirect. `. file`, `"$(cat file)"` inside the command that needs it, `jq --rawfile`, a pipe into `curl` or `ssh`, `> file`.
- To inspect, count and hash: `wc -l`, `stat`, `shasum`, `cmp`, `grep -c`. Prove it works by its effect.
- Never write your own filter. `sed 's/=.*/=***/'`, `cut -c1-10`, `head`, `grep -v` on a credential source still print it, they only change the shape.
- A "masked" copy, a prefix or a suffix is still a leak. Do not print one.

## Setting up the hooks

`npx skills add` copies this folder but cannot edit Claude Code settings, so the hooks are one step the user approves. When the user asks to set up no-leaky, or a credential read was not blocked and they want it to be:

1. Run `python3 <this skill's folder>/scripts/install.py --dry-run` and show the user every line it would change.
2. If a listed PostToolUse hook only reports status and never rewrites output (an app's own status or notification hook), add `--no-wrap '<part of its command>'`.
3. On a yes, run it again without `--dry-run`. It backs up `settings.json` first. The hooks take effect in the next session.
4. Run `install.py --check` and tell the user the result. If it ever reports a missing hook or interpreter, run the install again.

`install.py --uninstall` takes them out again.

## When the guard blocks a command

The denial names the source and the safe way. Take the safe way. Do not retry with another filter or another reader. If you think it is a false alarm, say so in one line and ask the user to run the command themselves in Claude Code's shell mode (they type an exclamation mark, then the command).

## When a secret already appeared

1. Stop and tell the user: which secret (kind or variable name), how it got there (which command or tool), and its fingerprint if the tool gave one.
2. Never repeat the value, not even partly, not in a quote, a summary or a commit.
3. Recommend rotating it where it was issued. The user rotates; you do not touch the value.
4. Suggest `/no-leaky-scan` to see whether it leaked before.

## When the user pastes a secret

The prompt guard holds the message back and says so. Suggest a safer route: put the value in a file or env var and tell you the path or name. They can still send it with a `secret-ok:` prefix.

## Before sharing a session

Run `python3 <skill dir>/scripts/scan.py --session <transcript.jsonl>` and share only when it exits 0.
