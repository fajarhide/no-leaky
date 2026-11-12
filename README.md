# no-leaky

<p align="center"><img src="assets/poster.png" width="840" alt="An agent session transcript stamped CAUGHT over a struck-out KEY LEAKED. cat .env, printenv and git add .env are denied, a key in a stack trace is redacted and a token pasted in chat is held. Beside it the line Stop your AI agent leaking your secrets, You told it not to read .env, the transcript says it did, and the command npx skills add fajarhide/no-leaky -g"></p>

Stop your AI agent leaking your secrets.

You told it not to read `.env`. Then it ran `cat .env` to check one setting, `docker inspect` on a broken container, `ps aux` to find a process, or read a diff that held a key somebody committed. The value went into the transcript, and from there into backups, shared sessions and the provider's logs. Nothing broke, so nobody noticed. On one developer's machine, 362 Claude Code transcripts from six weeks held 35 distinct secrets across 28 projects.

These two skills stop the next leak and find the ones already there. Values are never printed, not in a denial, a report or a log: every finding is a kind and a fingerprint, the first 8 hex of the value's SHA-256. You keep working the way you do now. They are for Claude Code, and the scan also reads Codex transcripts.

| Skill | Use it when | You get back | skills.sh |
| --- | --- | --- | --- |
| `no-leaky-secrets` | Your agent works anywhere near `.env`, config, keys, containers or processes | A command that would print a secret is denied with the safe way to do the same thing, a secret that still reaches output is redacted, and a secret you paste is held back | [![no-leaky-secrets installs on skills.sh](https://img.shields.io/badge/dynamic/regex?url=https%3A%2F%2Fwww.skills.sh%2Ffajarhide%2Fno-leaky%2Fno-leaky-secrets&search=Installs%3C%5C%2F%5Ba-z%5D%2B%3E%5Cs%2A%28%3F%3A%3C%5B%5E%3E%5D%2B%3E%5Cs%2A%29%2A%28%5B0-9.%2CKM%E2%80%93-%5D%2B%29&replace=%241&label=installs)](https://www.skills.sh/fajarhide/no-leaky/no-leaky-secrets) |
| `no-leaky-scan` | You want to know what already leaked | Every secret in your past transcripts, where it came from, how many sessions, and how to rotate it | [![no-leaky-scan installs on skills.sh](https://img.shields.io/badge/dynamic/regex?url=https%3A%2F%2Fwww.skills.sh%2Ffajarhide%2Fno-leaky%2Fno-leaky-scan&search=Installs%3C%5C%2F%5Ba-z%5D%2B%3E%5Cs%2A%28%3F%3A%3C%5B%5E%3E%5D%2B%3E%5Cs%2A%29%2A%28%5B0-9.%2CKM%E2%80%93-%5D%2B%29&replace=%241&label=installs)](https://www.skills.sh/fajarhide/no-leaky/no-leaky-scan) |

## From "may my agent read .env?" to proof

Asked whether their coding agent may read `.env`, about 60 developers in November 2026 split down the middle. Half said no. The other half said yes, as long as production values are different. Almost nobody named anything that makes either answer true.

| What people rely on | Why it fails | What no-leaky does |
| --- | --- | --- |
| "I told it not to read it" | A rule in the prompt is a request. Agents `cat .env` while debugging something else. | The guard denies the read before it runs. |
| "Are you sure it never did?" | Nobody is, without reading the tool calls. | The scan reads past transcripts and lists every secret that went through, by fingerprint. |
| "Prod values are different" | Until one prod key gets copied into a local file to reproduce a bug. | Every value in an `.env` file on this machine is known by hash, so that key is caught wherever it turns up later. |
| "The app sources the env, the agent never sees it" | Until a stack trace prints the config. | The filter redacts secrets in Bash, Read and Grep output. |
| "We use a secret manager" | An agent that can run `infisical run -- env` holds the secret too. | The guard denies env dumps: `printenv`, `env`, `export -p`, `/proc/*/environ`. |
| "I tell it to forget afterwards" | Forgetting is a chat feature. The provider already has the value. | Stop it before the model. For what already went through, the scan says what to rotate. |
| "It only reads, it never commits" | `git add .env` puts it in history, which outlives the file. | The guard denies staging credential files. |

## The rules

Every part here follows the same four.

1. **Use it, do not show it.** A secret the agent only needs to use is loaded, piped or redirected, never printed. `set -a; . ./.env; set +a; npm start` runs the app with the same values `cat .env` would have shown.
2. **Judge by source, not by look.** The guard decides by where the bytes come from, so a key in a format nobody wrote a pattern for is still stopped at `cat`.
3. **No masked copies.** A prefix, a suffix or `sk-***` is still a leak. Reports, denials and logs carry a kind and a fingerprint only.
4. **Publish the losses.** What each part misses is listed under Limits, next to what it catches.

## Install

```sh
npx skills add fajarhide/no-leaky -g
```

The skills work right away, and `/no-leaky-scan` runs from then on. The hooks need one more step, because a skill installer never edits Claude Code settings. Ask your agent:

```
Set up the no-leaky hooks
```

It shows what `install.py --dry-run` would change and installs after you say yes. Or run it yourself:

```sh
python3 ~/.claude/skills/no-leaky-secrets/scripts/install.py --dry-run
python3 ~/.claude/skills/no-leaky-secrets/scripts/install.py              # backs up settings.json first
python3 ~/.claude/skills/no-leaky-secrets/scripts/install.py --uninstall
```

It honors `CLAUDE_CONFIG_DIR`. If another hook already rewrites tool output on the same tools, the installer runs it through the filter (`filter.py --after '<its command>'`), because Claude Code keeps only the rewrite that finishes last. A hook that never rewrites output does not need this, and wrapping one that reads its parent pid or is managed by another app breaks it. Leave those alone with `--no-wrap '<part of its command>'`.

Without `-g`, the skills land inside whichever project you ran the command from. Python 3.9 or later, standard library only.

## Using them

Ask your agent in plain words:

```
Did my agent leak any secrets?
Start the app with the env from .env
Check this API token still works
Debug why the web container keeps restarting
Set up the no-leaky hooks
```

| You say something like | It loads |
| --- | --- |
| "start the app with .env", "check this token works", "debug this container", "why was cat .env blocked" | `no-leaky-secrets` |
| `/no-leaky-scan`, "did my agent leak anything" | `no-leaky-scan` |

The hooks do not depend on the model choosing a skill. Once installed, they run on every Bash, Read and Grep call and on every prompt you send.

## Guard

| Hook | Event | What it does |
| --- | --- | --- |
| `guard.py` | PreToolUse on Bash, Read, Grep | Denies a command that would print a credential source (`.env`, token files, private keys, `printenv`, `docker inspect`, `ps aux`, `crontab -l`, `gh auth token`, `kubectl get secret -o`), and `git add` of a credential file. The denial gives the safe way to do the same thing. |
| `filter.py` | PostToolUse on Bash, Read, Grep | Replaces any secret that still got through with `[secret: <kind>, fp <8 hex>]` and leaves the rest of the output alone. |
| `prompt_guard.py` | UserPromptSubmit | Holds back a message you typed that carries a secret. Start it with `secret-ok:` to send it anyway. |

What the guard still allows: `set -a; . ./.env; set +a; npm start`, `curl -H "Authorization: Bearer $(cat ~/.token)"`, `jq --rawfile`, a pipe into `ssh`, a redirect to a file, `wc`, `shasum`, `cmp`, `grep -c`, `git add .env.example`. Its self-check holds 38 commands it must deny and 39 it must allow.

The filter caught keys the redaction layer in front of it missed. Seven fake vendor keys in one Bash output went through a token optimizer's post-hook first: it redacted 3 and passed 4 on raw. Chained behind it with `--after`, `filter.py` redacted the other 4, so 7 of 7 left as fingerprints. One run on one output, reported upstream.

## Scan

```sh
python3 ~/.claude/skills/no-leaky-secrets/scripts/scan.py
```

```
- claude: covered (784 files)
- codex: covered (34 files)
- gemini: not found

## Certain, act on these (1)
| what | tier | sessions | first | last | route | fp | would stop it | fix |
| openai OPENAI_API_KEY | certain | 3 | 2026-10-02 | 2026-10-20 | Bash: cat .env | 4f0c2a91 | command guard or output filter | Rotate it in the OpenAI dashboard ... |
```

Rows are grouped as certain (a vendor key format, or a value that exists in an `.env` on this machine), likely (a JWT, a password in a URL, a long value under a name like `*_TOKEN`) and public by design (`NEXT_PUBLIC_*`, publishable keys).

On the author's machine, 787 Claude Code and 34 Codex transcripts took 112 seconds and gave 34 certain rows, 153 likely and 2 public. None of the 873 known values from local `.env` files appeared in the report or on screen.

Exit code 1 means a real finding that is not ignored, so the scan can gate a backup or a share. Add a rotated key to `~/.config/no-leaky/config.json` under `ignore` with a reason and a date.

Options: `--agent claude|codex|gemini`, `--since YYYY-MM-DD`, `--session FILE`, `--report PATH`, `--source-dir DIR`.

## Limits

Measured on Claude Code 2.1.322:

- The output filter covers Bash, Read and Grep. WebFetch and MCP tools are not filtered yet.
- A blocked prompt never reaches the model, but Claude Code still writes one copy into the local transcript.
- A running session does not pick up new hooks. They take effect in the next one.
- The likely tier is noisy: 153 rows on the author's machine, each to be checked by hand before you rotate anything. An entropy cutoff was measured and separated real keys from code no better.
- A first scan of about 4 GB of transcripts takes about two minutes. The goal was one.
- The scan reads Claude Code and Codex. Gemini CLI is read as plain text. Cursor is not read.
- A value already in a variable, or a file opened from inside a Python or Ruby script, is not seen by the guard. The filter is the net behind it.

Every script has a self-check: `python3 <script> --test`.

## Licence

MIT
