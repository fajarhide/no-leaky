# Security

no-leaky stops accidental leaks by a coding agent that works for you. It reads command lines and tool output, so an agent trying to get a secret out on purpose can get past it. Reports fall into two kinds.

## A way past the guard

A command that gets a credential into the transcript without being denied. These exist, and the known ones are listed in [tests/bypass_corpus.txt](tests/bypass_corpus.txt).

Report one in public: open a pull request that adds the command to that file as `gap`, or open an issue. Use a fake value, never a real one. A fix moves the line from `gap` to `deny`, and the test keeps it there.

## A leak in no-leaky itself

no-leaky printing a value it should hide: a denial, a scan report, a log or a test that shows a secret or part of one. Also the vault or the data key readable by another user, or a token that can be turned back into its value without the key.

Report these in private, through **Report a vulnerability** on the repository's Security tab. Describe the shape of the value and the steps; do not send a real secret.

## Versions

Fixes go into the latest release only. Update as the [README](README.md#update) says.
