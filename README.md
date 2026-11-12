# no-leaky

Coding agents print secrets while they work on something else. They `cat .env` to check a setting, `docker inspect` a broken container, run `ps aux`, or read a diff that holds a key somebody committed. The value lands in the transcript, and from there in backups, shared sessions and the provider's logs. Nothing breaks, so nobody notices.

On one developer's machine, 362 Claude Code transcripts from six weeks held 35 distinct secrets across 28 projects. 25 were real keys; the other 10 were public by design.

`no-leaky-secrets` does three things:

1. **Scan**: finds secrets already sitting in Claude Code and Codex transcripts, and says where each came from and how to rotate it. It prints fingerprints, never values.
2. **Guard**: three Claude Code hooks stop the next leak while the agent keeps working.
3. **Teach**: a skill that shows any agent how to use a secret without printing it.

## Scan

```sh
python3 skills/no-leaky-secrets/scripts/scan.py
```

```
- claude: covered (784 files)
- codex: covered (34 files)
- gemini: not found

## Certain, act on these (1)
| what | tier | sessions | first | last | route | fp | would stop it | fix |
| openai OPENAI_API_KEY | certain | 3 | 2026-10-02 | 2026-10-20 | Bash: cat .env | 4f0c2a91 | command guard or output filter | Rotate it in the OpenAI dashboard ... |
```

Rows are grouped as certain (a vendor key format, or a value that exists in an `.env` on this machine), likely (a JWT, a password in a URL, a long value under a name like `*_TOKEN`) and public by design (`NEXT_PUBLIC_*`, publishable keys). The fingerprint is the first 8 hex of the value's SHA-256.

Exit code 1 means a real finding that is not ignored, so the scan can gate a backup or a share. Add a rotated key to `~/.config/no-leaky/config.json` under `ignore` with a reason and a date.

Options: `--agent claude|codex|gemini`, `--since YYYY-MM-DD`, `--session FILE`, `--report PATH`, `--source-dir DIR`.

## Guard

| Hook | Event | What it does |
| --- | --- | --- |
| `guard.py` | PreToolUse on Bash, Read, Grep | Denies a command that would print a credential source (`.env`, token files, private keys, `printenv`, `docker inspect`, `ps aux`, `crontab -l`, `gh auth token`, `kubectl get secret -o`). It decides by where the bytes come from, never by what they look like. The denial gives the safe way to do the same thing. |
| `filter.py` | PostToolUse on Bash, Read, Grep | Replaces any secret that still got through with `[secret: <kind>, fp <8 hex>]` and leaves the rest of the output alone. |
| `prompt_guard.py` | UserPromptSubmit | Holds back a message you typed that carries a secret. Start it with `secret-ok:` to send it anyway. |

What the guard still allows: `set -a; . ./.env; set +a; npm start`, `curl -H "Authorization: Bearer $(cat ~/.token)"`, `jq --rawfile`, a pipe into `ssh`, a redirect to a file, `wc`, `shasum`, `cmp`, `grep -c`.

Install:

```sh
python3 skills/no-leaky-secrets/scripts/install.py            # backs up settings.json first
python3 skills/no-leaky-secrets/scripts/install.py --uninstall
```

It honors `CLAUDE_CONFIG_DIR`. If another hook already rewrites tool output on the same tools, the installer runs it through the filter (`filter.py --after '<its command>'`), because Claude Code keeps only the rewrite that finishes last. A hook that never rewrites output does not need this, and wrapping one that reads its parent pid or is managed by another app breaks it. Leave those alone with `--no-wrap '<part of its command>'`.

## Limits

Measured on Claude Code 2.1.322:

- The output filter covers Bash, Read and Grep. WebFetch and MCP tools are not filtered yet.
- A blocked prompt never reaches the model, but Claude Code still writes one copy into the local transcript.
- The scan reads Claude Code and Codex. Gemini CLI is read as plain text. Cursor is not read.
- A first scan of about 4 GB of transcripts takes about two minutes.
- Check each likely row by hand before you rotate anything.

Every script has a self-check: `python3 <script> --test`. Python 3.9 or later, standard library only.

## License

MIT
