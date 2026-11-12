# Changelog

All notable changes to no-leaky. Versions follow [Semantic Versioning](https://semver.org/): before 1.0.0, a minor
version adds features and may change hook behavior, a patch version only fixes.

## [0.2.0] - unreleased

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

[0.2.0]: https://github.com/fajarhide/no-leaky/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/fajarhide/no-leaky/releases/tag/v0.1.0
