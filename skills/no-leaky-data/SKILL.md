---
name: no-leaky-data
description: Use when output shows tokens like [email: k3f9a01c], when working with customer, user or personal data (emails, phone numbers, national IDs, card numbers, internal hosts or client names), or when a prompt was held for holding personal data.
---

# no-leaky-data

Everything you see is sent to your provider. Personal data in tool output (emails, phone numbers, NIK, NPWP, card numbers, IP addresses, AWS account IDs, and the client names the user listed) reaches you as tokens:

```
customer 4411 <[email: k3f9a01c]> paid with [card: k77b2e10], phone [phone: k0c5d9a2]
```

The same person always gets the same token on this machine, so you can follow one customer through a log, a database row and a ticket without ever seeing who they are.

## Use a value without seeing it

Put the token in a command and run it through `nl-run`. It swaps the real value in inside its own process; the output comes back to you tokenized again.

```sh
nl-run -- sqlite3 shop.db "select id, status from orders where email = '[email: k3f9a01c]'"
nl-run -- grep -n '[email: k3f9a01c]' logs/app.log
```

A search or query that holds a token but does not go through `nl-run` is blocked: run as written it would match the token's text and return nothing.

## Rules

- Never try to recover a value: no decoding, no guessing it from context, no asking the user for it, no reading `~/.cache/no-leaky/vault.json` (the guard denies it).
- Report findings about a person by token: "the checkout for [email: k3f9a01c] fails because...".
- To change a line that holds a token, do not use Edit (it compares against the real file, so a token never matches). Write a small script and run it with `nl-run -- python3 fix.py`; tokens in the script are resolved when it runs.
- A token you write into a file stays a token. Write values into files only through `nl-run`.
- `nl-run` refuses network tools (`curl`, `ssh`, `scp` and an inline script that reaches the network) unless every host is in `data_hosts`. If a task truly needs one, tell the user which host and why; they decide whether to list it.
- `nl-run: unknown token` means the token expired (7 days) or came from another machine. Read the source again to get a fresh one.

## When a prompt is held

The user pasted data. Suggest they put the rows in a file and give you the path: you will read them as tokens and can still work with them. They can send it anyway by starting the message with `secret-ok:`.

## Settings the user controls

`~/.config/no-leaky/config.json`:

```json
{
  "data_allow": ["their-own@email.example"],
  "internal_names": ["client or employer names to hide"],
  "data_hosts": ["db.internal.example"]
}
```

`data_allow` keeps their own email and name readable. `internal_names` turns those names into `[name: k…]` tokens in text (paths, URLs and git remotes are left alone so `cd` and `git` keep working). `data_hosts` lists hosts `nl-run` may send resolved values to.
