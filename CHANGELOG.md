# Changelog

All notable changes to no-leaky. Versions follow [Semantic Versioning](https://semver.org/): before 1.0.0, a minor
version adds features and may change hook behavior, a patch version only fixes.

## [0.2.7] - 2026-11-14

### Fixed
- A value in `.env` that the template beside it (`.env.example`, `.env.sample`, `.env.template`, `.env.dist`) also
  holds is no longer learned as a known secret. A template is written to be shared, so its values are defaults:
  image references, database names, hosts. A scan had listed two image references from `.env.example` as certain
  secrets. Editing the template refreshes what is learned. The known-values cache format moves to 5.

## [0.2.6] - 2026-11-14

### Fixed
- A model name in a `.env` file (`OPENAI_MODEL`, `GEMINI_MODEL`, `*_MODEL_ID`, `*_MODEL_NAME`) is no longer learned as a
  known secret, so the model name stops coming back as `[secret: known, ...]` wherever it appears. A name that also
  carries a credential word, such as `MODEL_API_KEY`, is still learned. The known-values cache format moves to 4.

## [0.2.5] - 2026-11-14

### Fixed
- An email address stored as a value in a `.env` file (an allowlist, a sender address) is no longer learned as a
  known secret, so `git config user.email` and every other place that address appears stop coming back as
  `[secret: known, ...]`. Addresses are personal data and the data filter already turns them into `[email: k...]`
  tokens. The known-values cache format moves to 3, and the hooks' ten-minute cache shortcut now rebuilds a cache
  written in an older format instead of trusting it, so the fix applies on the first tool call after an upgrade.

## [0.2.4] - 2026-11-13

### Added
- The installer adds Claude Code's own `permissions.deny` rules for real env files (`.env`, `.env.local`,
  `.env.production` and similar) and common credential files. They hold even if a hook is ever missing: on a run
  with no hooks, Claude Code refused both `Read .env` and `cat .env` while `.env.example` stayed readable. The rules
  added are recorded in `no-leaky-permissions.json`, so uninstall never removes rules the user wrote.
- `install.py --check` reports missing deny rules.

## [0.2.3] - 2026-11-13

### Fixed
- Hooks no longer vanish under an app that keeps its own Claude Code profile. Orca re-copies
  `~/.claude/settings.json` over the profile's settings when it starts a session, which wiped hooks installed into
  the profile. The installer now spots such a profile (same settings once hook order is ignored, or links into
  `~/.claude`) and installs into both.
- Hooks run `python3` from PATH when it is a real install, not the versioned path the installer happened to run
  from, so removing an old Python after an upgrade does not silently turn them off. A pyenv or asdf shim and a
  virtualenv are never used.

### Added
- `install.py --check`: reports whether every hook is installed and its interpreter and script still exist, and
  exits 1 when something is wrong.
- README: requirements (Python 3.9+, Node.js for `npx`, macOS and Linux).

## [0.2.2] - 2026-11-13

### Fixed
- A token-shaped string the vault never minted (a test fixture, a doc example) is no longer blocked in Write, Edit,
  Grep or a lookup command: it stands for no data. Found while writing this release's own tests.
- The guard no longer blocks a `grep`, `sed` or commit message that only mentions `docker inspect`; it denies the
  command only when docker or podman actually runs.
- `podman inspect` is guarded like `docker inspect`; `pgrep -a` (full command lines) is guarded like `ps aux`.
- The `ps` denial points to `pgrep -f`, so the agent finds a process without seeing its arguments instead of
  deciding it is not running.
- Lookup commands holding a token are recognized behind a path or a wrapper (`/usr/bin/grep`, `sudo grep`,
  `xargs grep`).
- Not personal data any more: `+` and fewer than 10 digits (diff hunks, offsets), netmasks, GitHub noreply
  addresses and subdomains of example.com, .org and .net.
- `scan.py` exits 1 only for secrets. Data rows are still reported, but your own email in `git log` no longer fails
  every run.
- The filter self-check no longer reads the real `~/.config/no-leaky/config.json`.

### Added
- CI: every self-check runs on Ubuntu (Python 3.9 and 3.13) and macOS for each push and pull request.

## [0.2.1] - 2026-11-13

### Fixed
- `no-leaky-data` was skipped by `npx skills add`: its SKILL.md description held `: ` unquoted, which is not valid YAML. The installer self-check now fails on any SKILL.md front matter that would not parse.
- `no-leaky-secrets` SKILL.md held an exclamation mark followed by a backtick, which skill scanners and Claude Code read as a shell command directive. Reworded; the self-check now fails on that pattern in any SKILL.md.

## [0.2.0] - 2026-11-13

### Added
- `no-leaky-data` skill. Emails, phone numbers, NIK, NPWP, card numbers, IPv4 addresses, AWS account IDs and the
  client names you list reach the agent as `[kind: k<12 hex>]` tokens, an HMAC under a key that never leaves the
  machine.
- `nl-run`: runs a command with tokens resolved inside its own process, so the agent uses a value it never saw.
  Network tools are refused unless every host is in `data_hosts`.
- The output filter covers MCP tool output.
- The guard blocks writing a data token into a file with Write or Edit (Markdown and text notes are fine).
- The prompt guard holds a prompt carrying personal data; the scan reports data in its own section.
- Config keys `data_allow`, `internal_names`, `data_hosts`.

### Changed
- A Grep or a lookup command (`grep`, `rg`, `psql`, `sqlite3` and similar) that holds a data token is denied with
  the `nl-run` form, since run as written it matches the token text.
- The scan uses half the cores at low priority.
- The README leads with the leak bench.

## [0.1.0] - 2026-11-12

### Added
- `no-leaky-secrets`: a PreToolUse guard that denies commands printing a credential source, a PostToolUse filter
  that redacts secrets in Bash, Read and Grep output, and a UserPromptSubmit guard for pasted secrets
  (`secret-ok:` sends it anyway).
- `no-leaky-scan`: finds secrets already in Claude Code and Codex transcripts and says how to rotate them. It
  prints fingerprints, never values.
- `install.py` with backup, `--dry-run` and `--uninstall`. It chains another output-rewriting hook with
  `filter.py --after`.
- The guard denies `git add` of a credential file.
- `install.py --no-wrap` leaves a PostToolUse hook that never rewrites output unwrapped.

[0.2.7]: https://github.com/fajarhide/no-leaky/compare/v0.2.6...v0.2.7
[0.2.6]: https://github.com/fajarhide/no-leaky/compare/v0.2.5...v0.2.6
[0.2.5]: https://github.com/fajarhide/no-leaky/compare/v0.2.4...v0.2.5
[0.2.4]: https://github.com/fajarhide/no-leaky/compare/v0.2.3...v0.2.4
[0.2.3]: https://github.com/fajarhide/no-leaky/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/fajarhide/no-leaky/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/fajarhide/no-leaky/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/fajarhide/no-leaky/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/fajarhide/no-leaky/releases/tag/v0.1.0
