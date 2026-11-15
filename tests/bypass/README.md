# Bypass corpus

A list of ways a secret could still reach the model, replayed against the real guard and filter. It gives the claim "no-leaky stops this" a test, and it gives each gap under Limits in the main README a command you can run.

Nothing here executes. A case holds the command (or tool call) and the output that command would print with a fake secret in it. The runner asks the guard whether it would deny the call. If it would not, the runner passes the output through the filter and checks whether the secret is still readable.

## Run it

```sh
python3 tests/bypass/run.py                # report; exit 1 on a regression or a stale label
python3 tests/bypass/run.py --layers       # guard misses that only the filter caught
python3 tests/bypass/run.py --markdown     # known-gap tables for the README
python3 tests/bypass/run.py -k docker      # cases whose id or command contains "docker"
python3 tests/bypass/run.py --seed random  # fuzz with new fake secrets; the seed is printed on failure
```

Python 3.9 or later, standard library only. A run never reads your real config, cache or vault.

## What it checks

- `commands.jsonl`: shell commands and Read or Grep calls, end to end through the guard and then the filter.
- `transforms.jsonl`: a secret rewritten before it prints (base64, upper case, split in two). Only the filter can help here.
- `pii.jsonl`: personal data from many countries, checked against the data detector. Every value is synthetic or a published example.

Each read or dump case is tried with up to three kinds of secret, because the two layers protect different things:

- `vendor`: a key in a published vendor format. The filter recognises it by shape.
- `opaque-known`: no recognisable shape, but the value sits in an `.env` on this machine, so the filter knows its hash.
- `opaque-unknown`: no recognisable shape and not in any local file. Only the guard protects it.

That is why most documented gaps list `opaque-unknown` alone. When the guard misses a command, the filter usually still catches a vendor key or a value from a local `.env`.

## Case fields

- `id`: short and unique. The letter is the category: d direct read, o obfuscation, i interpreter, c indirect, s search, e environment, v version control, a cloud CLI, p process, t built-in tool, k private key, b benign.
- `command`, or `tool` with `path`, `pattern` and `glob`: the call.
- `output`: what the call would print. `{S}` marks the fake secret.
- `output_transform`: optional name from `TRANSFORMS` in `run.py` (`base64`, `hex`), applied to the output.
- `expect`: `safe` (the default), `allow` (the guard must not deny it) or `deny` (the guard must deny it, for policy rules such as staging `.env`).
- `leaks`: the secret kinds that still leak today, or `"all"`. Leave it out when nothing leaks.
- `flavors`: limit the secret kinds, for example `["private_key"]`.
- `note`: one line on why the case is interesting.

`transforms.jsonl` takes `transform`, `kinds` and `leaks`. A case can also carry `fixed`, a map of label to string parts that the runner joins at run time. Use it for a value that must be exact. Written out whole, a fake key in the right format can trip GitHub secret scanning when you push.

## Report a bypass

1. Add a line to `commands.jsonl` with the command, a realistic output and the kinds that leak, for example `"leaks": ["opaque-unknown"]`.
2. Run `python3 tests/bypass/run.py -k <your id>`. A line starting with `REGRESSION` means the label is wrong. A passing run means the gap is now documented.
3. Open a pull request, or an issue using the bypass template. Use fake values only.

A hole that exposes real secrets in a way the Limits do not cover is better reported privately. See `SECURITY.md`.

## When a fix lands

The runner fails on stale labels. When a change closes a gap, the case prints `FIXED` and the run exits 1 until the `leaks` entry is deleted. The fix and the label change go in the same commit, and the tables from `--markdown` get shorter.

## Personal data beyond Indonesia

`pii.jsonl` marks which formats the detector tokenizes today (`tokenized`), which it misses (`gap`) and which must stay readable (`ignored`). National identifiers outside Indonesia are all gaps for now. Add a detector, flip the case to `tokenized`, and the run tells you whether the new pattern also fires on something it should leave alone.
