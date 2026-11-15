# Contributing

Two kinds of contribution are easy to review, because a runnable corpus checks both: a bypass, and a country pack.

## A bypass

A bypass is a command or output format that gets a secret or personal data past the hooks. Add a line to `tests/bypass/commands.jsonl` with the command, a realistic output and the secret kinds that leak. `tests/bypass/README.md` has the fields and the steps. Use fake values only.

## A country pack

A pack finds one kind of national identifier and keeps it only if it passes the identifier's own checksum, so a random run of digits does not become a token. The German tax ID (`de-steuerid`) is the smallest complete example. Copy it.

1. Find the rule in a public source before writing code: the issuing authority, a standard, or a reference implementation. For the German tax ID that is the description from the Federal Central Tax Office and the `de/idnr.py` module of python-stdnum. Link the source in the issue or the pull request.

2. Write the finder in `skills/no-leaky-secrets/scripts/packs.py`. For Germany that is `_de_steuerid`, with `_steuerid_ok` for the rules and `_steuerid_check` for the check digit. A numeric finder is called with one run of digits and separators and yields `(start, end)` spans. A finder for letters followed by digits is called at one anchor. The header of `packs.py` says which to pick.

3. Decide what the plain form needs. Eleven plain digits look like many other numbers, so `_DE_ID_BARE` is read only when a word such as `Steuer-ID` stands in front (`_near` and `_DE_ID_WORD`). The usual written form, `12 345 678 901`, has a rare enough shape to stand alone. Put the words people write in the local language into the word pattern.

4. Register it with one line in `PACKS`: pack id, country code, token kind, sweep, finder. The kind becomes the token, `[steuerid: k…]`, so it is one lowercase word.

5. Add a generator to `fake()` and the kind to `CHECKSUM_KINDS`. `test()` then checks that 120 generated values are found exactly once and that changing one digit gets each of them rejected.

6. Add vectors to `test()`: a published example, the plain form with and without its word, a wrong check digit, and each structure rule on its own with a correct check digit. The block starting at `steuer-id structure` shows how. Testing the rules apart from the checksum is what catches a rule that was dropped.

7. Add cases to `tests/bypass/pii.jsonl`: one `tokenized` value per written form and `ignored` values for every way a number can fail. Run `python3 tests/bypass/run.py` and it tells you whether anything else changed.

8. Add the country to the list in the README and a line to `CHANGELOG.md`.

9. Run the checks:

```sh
python3 skills/no-leaky-secrets/scripts/packs.py --test
python3 tests/bypass/run.py
```

## Check against a reference while you write it

If a library implements the same rule, use it as an oracle during development and keep it out of the repository, which uses the standard library only. For Germany:

```python
import random
from stdnum.de import idnr
import packs

rng = random.Random(1)
miss = []
for _ in range(400_000):
    d = "".join(rng.choice("0123456789") for _ in range(11))
    if packs._steuerid_ok(d) != idnr.is_valid(d):
        miss.append(d)
print(len(miss), "disagreements")
```

Random digits rarely satisfy a structure rule, so shape part of the sample to pass it. The German pack was compared on 400,000 strings, about a quarter of them valid, with no disagreement.

## Look for false positives in ordinary text

Run the finders over text that has nothing to do with the identifier: source code, documentation, `/etc`. A pack that fires on colour triplets or numbers in scientific notation is not ready. Two of the first packs did exactly that, and the fixes became test cases.
