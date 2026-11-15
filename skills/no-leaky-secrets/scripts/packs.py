#!/usr/bin/env python3
"""Country packs: national identifiers that carry a check digit or a strict shape.

Each pack finds one kind of identifier and keeps it only if it passes its own checksum, so a random run
of digits does not become a token. A format that is too common to trust on its own (nine bare digits, three
groups of three) is read only when a word like "ssn" stands just before it.

Settings, in ~/.config/no-leaky/config.json:
  "data_packs": null                  every pack (the default)
  "data_packs": ["us", "gb", "iban"]  only these country codes or pack ids
  "data_packs": []                    none

Speed: the text is swept twice, not once per pack. One sweep finds runs of digits and separators, and the
numeric packs read only inside those runs. The other finds capital letters followed by digits, and the
letter-and-digit packs try to match from there.

Missing a country? Open an issue with the Country pack request template, or add it yourself. Write a finder,
give it a line in PACKS, add a fake value in fake() and a few vectors in test(). A numeric finder is called as
find(text, start, end) over one run; a letter-and-digit finder as find(text, pos) at one anchor. Each yields
(start, end) spans. A checksum has to reject a one-digit change, and test() checks that.

Self-check: python3 packs.py --test        List the packs: python3 packs.py --list
"""

import random
import re
import sys

# --- shared helpers ---------------------------------------------------------------------------------------


def _luhn(d):
    total = 0
    for i, c in enumerate(reversed(d)):
        n = int(c)
        if i % 2:
            n = n * 2 - 9 if n > 4 else n * 2
        total += n
    return total % 10 == 0


# Verhoeff tables (Aadhaar).
_VD = ["0123456789", "1234067895", "2340178956", "3401289567", "4012395678",
       "5987604321", "6598710432", "7659821043", "8765932104", "9876543210"]
_VP = ["0123456789", "1576283094", "5803796142", "8916043527", "9453126870",
       "4286573901", "2793806415", "7046913258"]
_VINV = "0432156789"


def _verhoeff_ok(d):
    c = 0
    for i, ch in enumerate(reversed(d)):
        c = int(_VD[c][int(_VP[i % 8][int(ch)])])
    return c == 0


def _verhoeff_digit(body):
    c = 0
    for i, ch in enumerate(reversed(body)):
        c = int(_VD[c][int(_VP[(i + 1) % 8][int(ch)])])
    return _VINV[c]


def _near(text, start, rx, width=40):
    """True when `rx` matches in the same line, within `width` characters before `start`."""
    lo = max(text.rfind("\n", 0, start) + 1, start - width)
    return rx.search(text[lo:start]) is not None


def _pathlike(text, s, e):
    """A match that is a path component or a file name stays readable, so cd and git keep working.
    A backslash that starts \\n, \\r, \\t or \\" is JSON escaping at the end of a line or string, not a path."""
    return (s > 0 and text[s - 1] in "/\\") or bool(re.match(r'/|\\(?![nrt"])|\.\w', text[e:e + 2]))


# --- United States: social security number ----------------------------------------------------------------

_SSN = re.compile(r"(?<![\w-])\d{3}-\d{2}-\d{4}(?![\w-])")
_SSN_BARE = re.compile(r"(?<![\w.-])\d{9}(?![\w.-])")
_SSN_WORD = re.compile(r"(?i)\bssn\b|social[ _-]?security|\bss ?(?:no|num|#)")


def _ssn_ok(d):
    area, group, serial = int(d[:3]), int(d[3:5]), int(d[5:])
    return 0 < area < 900 and area != 666 and group > 0 and serial > 0


def _us_ssn(text, s, e):
    for m in _SSN.finditer(text, s, e):
        if _ssn_ok(re.sub(r"\D", "", m.group())):
            yield m.start(), m.end()
    for m in _SSN_BARE.finditer(text, s, e):
        if _ssn_ok(m.group()) and _near(text, m.start(), _SSN_WORD):
            yield m.start(), m.end()


# --- United Kingdom: national insurance number ------------------------------------------------------------

_NINO = re.compile(r"(?<![A-Za-z0-9])[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z][ ]?\d{2}[ ]?\d{2}[ ]?\d{2}[ ]?[A-D](?![A-Za-z0-9])")
_NINO_BAD = {"BG", "GB", "KN", "NK", "NT", "TN", "ZZ"}


def _gb_nino(text, pos):
    m = _NINO.match(text, pos)
    if m and m.group()[:2] not in _NINO_BAD:
        yield m.start(), m.end()


# --- India: Aadhaar ---------------------------------------------------------------------------------------

# Not inside a longer list of digit groups: a column of ids, ports or years passes Verhoeff one time in ten.
_AADHAAR = re.compile(r"(?<![\d-])(?<!\d )[2-9]\d{3}[ -]\d{4}[ -]\d{4}(?![\d-])(?! \d)")
_AADHAAR_BARE = re.compile(r"(?<![\d.-])[2-9]\d{11}(?![\d.-])")
_AADHAAR_WORD = re.compile(r"(?i)aadhaar|aadhar|uidai|\buid\b")


def _in_aadhaar(text, s, e):
    for m in _AADHAAR.finditer(text, s, e):
        if _verhoeff_ok(re.sub(r"\D", "", m.group())):
            yield m.start(), m.end()
    for m in _AADHAAR_BARE.finditer(text, s, e):
        if _verhoeff_ok(m.group()) and _near(text, m.start(), _AADHAAR_WORD):
            yield m.start(), m.end()


# --- Brazil: CPF ------------------------------------------------------------------------------------------

_CPF = re.compile(r"(?<![\d.-])\d{3}\.\d{3}\.\d{3}-\d{2}(?![\d-])")
_CPF_BARE = re.compile(r"(?<![\d.-])\d{11}(?![\d.-])")
_CPF_WORD = re.compile(r"(?i)\bcpf\b")


def _cpf_digits(nine):
    d = [int(c) for c in nine]
    a = (sum(d[i] * (10 - i) for i in range(9)) * 10 % 11) % 10
    d.append(a)
    b = (sum(d[i] * (11 - i) for i in range(10)) * 10 % 11) % 10
    return f"{a}{b}"


def _cpf_ok(d):
    return len(set(d)) > 1 and _cpf_digits(d[:9]) == d[9:]


def _br_cpf(text, s, e):
    for m in _CPF.finditer(text, s, e):
        if _cpf_ok(re.sub(r"\D", "", m.group())):
            yield m.start(), m.end()
    for m in _CPF_BARE.finditer(text, s, e):
        if _cpf_ok(m.group()) and _near(text, m.start(), _CPF_WORD):
            yield m.start(), m.end()


# --- IBAN (international) ---------------------------------------------------------------------------------

# Length of the whole IBAN per country. Checked on 2026-11-15 against SWIFT registry release 101, as published
# in python-stdnum's iban.dat: all 89 countries, every length equal.
IBAN_LEN = dict(
    BI=27, DJ=27, FK=18, HN=28, LY=25, MN=20, NI=28, OM=23, RU=33, SD=18, SO=23, YE=30,
    AD=24, AE=23, AL=28, AT=20, AZ=28, BA=20, BE=16, BG=22, BH=22, BR=29, BY=28, CH=21, CR=22, CY=28, CZ=24, DE=22,
    DK=18, DO=28, EE=20, EG=29, ES=24, FI=18, FO=18, FR=27, GB=22, GE=22, GI=23, GL=18, GR=27, GT=28, HR=21, HU=28,
    IE=22, IL=23, IQ=23, IS=26, IT=27, JO=30, KW=30, KZ=20, LB=28, LC=32, LI=21, LT=20, LU=20, LV=21, MC=27, MD=24,
    ME=22, MK=19, MR=27, MT=31, MU=30, NL=18, NO=15, PK=24, PL=28, PS=29, PT=25, QA=29, RO=24, RS=22, SA=24, SC=31,
    SE=24, SI=19, SK=24, SM=27, ST=25, SV=28, TL=23, TN=24, TR=26, UA=29, VA=22, VG=24, XK=20)
_IBAN = re.compile(r"(?<![A-Za-z0-9])[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?(?![A-Za-z0-9])")


def _iban_ok(compact):
    return int("".join(str(int(c, 36)) for c in compact[4:] + compact[:4])) % 97 == 1


def _iban(text, pos):
    for m in filter(None, [_IBAN.match(text, pos)]):
        raw = m.group()
        size = IBAN_LEN.get(raw[:2])
        if not size:
            continue
        # The pattern can run past the IBAN into a following capitalised word; cut at the country's length.
        seen, end = 0, None
        for i, ch in enumerate(raw):
            if ch != " ":
                seen += 1
                if seen == size:
                    end = i + 1
                    break
        if end is None or (end < len(raw) and raw[end] != " "):
            continue
        if _iban_ok(raw[:end].replace(" ", "")):
            yield m.start(), m.start() + end


# --- Spain: DNI and NIE -----------------------------------------------------------------------------------

_DNI = re.compile(r"(?<![A-Za-z0-9.])\d{8}-?[A-HJ-NP-TV-Z](?![A-Za-z0-9]|[+-]\d)")
_NIE = re.compile(r"(?<![A-Za-z0-9.])[XYZ]\d{7}-?[A-HJ-NP-TV-Z](?![A-Za-z0-9]|[+-]\d)")
_DNI_LETTERS = "TRWAGMYFPDXBNJZSQVHLCKE"


def _dni_ok(raw):
    body, letter = re.sub(r"[- ]", "", raw)[:-1], raw[-1]
    if body[0] in "XYZ":  # NIE: the leading letter stands for 0, 1 or 2
        body = str("XYZ".index(body[0])) + body[1:]
    return _DNI_LETTERS[int(body) % 23] == letter


def _es_dni(text, s, e):
    for m in _DNI.finditer(text, s, e):
        if _dni_ok(m.group()):
            yield m.start(), m.end()


def _es_nie(text, pos):
    m = _NIE.match(text, pos)
    if m and _dni_ok(m.group()):
        yield m.start(), m.end()


# --- Netherlands: BSN -------------------------------------------------------------------------------------

_BSN = re.compile(r"(?<![\d.-])\d{3}[ .]?\d{3}[ .]?\d{3}(?![\d.-])")
_BSN_WORD = re.compile(r"(?i)\bbsn\b|burgerservice|sofi")


def _bsn_ok(d):
    n = [int(c) for c in d]
    return (sum(n[i] * (9 - i) for i in range(8)) - n[8]) % 11 == 0 and d != "000000000"


def _nl_bsn(text, s, e):
    for m in _BSN.finditer(text, s, e):
        if _bsn_ok(re.sub(r"\D", "", m.group())) and _near(text, m.start(), _BSN_WORD):
            yield m.start(), m.end()


# --- Germany: tax identification number (Steuer-IdNr) ----------------------------------------------------

# Written 12 345 678 901 on tax letters, and as 11 plain digits elsewhere. The plain form needs a word in front.
_DE_ID = re.compile(r"(?<![\d-])[1-9]\d(?: \d{3}){3}(?![\d-])")
_DE_ID_BARE = re.compile(r"(?<![\d.-])[1-9]\d{10}(?![\d.-])")
_DE_ID_WORD = re.compile(r"(?i)steuer[- ]?id|identifikationsnummer|\bidnr\b")


def _steuerid_check(first10):
    """ISO 7064 MOD 11,10 over the first ten digits, as the BZSt specifies it."""
    product = 10
    for c in first10:
        total = (int(c) + product) % 10 or 10
        product = 2 * total % 11
    return (11 - product) % 10


def _steuerid_ok(d):
    # Among the first ten digits exactly one digit appears two or three times and every other digit at most once.
    repeats = [d[:10].count(c) for c in set(d[:10]) if d[:10].count(c) > 1]
    return (d[0] != "0" and len(repeats) == 1 and repeats[0] in (2, 3)
            and _steuerid_check(d[:10]) == int(d[10]))


def _de_steuerid(text, s, e):
    for m in _DE_ID.finditer(text, s, e):
        if _steuerid_ok(re.sub(r"\D", "", m.group())):
            yield m.start(), m.end()
    for m in _DE_ID_BARE.finditer(text, s, e):
        if _steuerid_ok(m.group()) and _near(text, m.start(), _DE_ID_WORD):
            yield m.start(), m.end()


# --- Canada: social insurance number ----------------------------------------------------------------------

_SIN = re.compile(r"(?<![\d.-])[1-79]\d{2}[ -]?\d{3}[ -]?\d{3}(?![\d.-])")
_SIN_WORD = re.compile(r"(?i)\bsin\b|social[ _-]?insurance")


def _ca_sin(text, s, e):
    # Three groups of three digits is also an RGB triplet or a part number, so the word is always required.
    for m in _SIN.finditer(text, s, e):
        if _luhn(re.sub(r"\D", "", m.group())) and _near(text, m.start(), _SIN_WORD):
            yield m.start(), m.end()


# --- Singapore: NRIC and FIN ------------------------------------------------------------------------------

_NRIC = re.compile(r"(?<![A-Za-z0-9])([STFG])(\d{7})([A-Z])(?![A-Za-z0-9])")


def _nric_letter(prefix, digits):
    total = sum(w * int(c) for w, c in zip((2, 7, 6, 5, 4, 3, 2), digits))
    if prefix in "TG":
        total += 4
    return ("JZIHGFEDCBA" if prefix in "ST" else "XWUTRQPNMLK")[total % 11]


def _sg_nric(text, pos):
    m = _NRIC.match(text, pos)
    if m and _nric_letter(m.group(1), m.group(2)) == m.group(3):
        yield m.start(), m.end()


# --- France: INSEE number (NIR) ---------------------------------------------------------------------------

_INSEE = re.compile(r"(?<![\w.-])[12](?: ?\d{2}){2} ?\d{2} ?\d{3} ?\d{3} ?\d{2}(?![\w-])")  # not inside a hash or id


def _fr_insee(text, s, e):
    for m in _INSEE.finditer(text, s, e):
        d = re.sub(r"\D", "", m.group())
        month = int(d[3:5])
        if len(d) == 15 and (1 <= month <= 12 or month >= 20) and 97 - int(d[:13]) % 97 == int(d[13:]):
            yield m.start(), m.end()


# --- Italy: codice fiscale --------------------------------------------------------------------------------

_CF = re.compile(r"(?<![A-Za-z0-9])[A-Z]{6}\d{2}[A-EHLMPR-T]\d{2}[A-Z]\d{3}[A-Z](?![A-Za-z0-9])")
_CF_ODD = (1, 0, 5, 7, 9, 13, 15, 17, 19, 21, 2, 4, 18, 20, 11, 3, 6, 8, 12, 14, 16, 10, 22, 25, 24, 23)


def _cf_char(first15):
    total = 0
    for i, c in enumerate(first15):
        v = ord(c) - 65 if c.isalpha() else int(c)
        total += _CF_ODD[v] if i % 2 == 0 else v
    return chr(65 + total % 26)


def _it_cf(text, pos):
    m = _CF.match(text, pos)
    if m and _cf_char(m.group()[:15]) == m.group()[15]:
        yield m.start(), m.end()


# --- Mexico: CURP -----------------------------------------------------------------------------------------

_CURP = re.compile(r"(?<![A-Za-z0-9])[A-Z]{4}\d{6}[HMX][A-Z]{2}[B-DF-HJ-NP-TV-Z]{3}[0-9A-Z]\d(?![A-Za-z0-9])")
_CURP_DICT = "0123456789ABCDEFGHIJKLMN\u00d1OPQRSTUVWXYZ"


def _curp_digit(first17):
    return str((10 - sum(_CURP_DICT.index(c) * (18 - i) for i, c in enumerate(first17)) % 10) % 10)


def _mx_curp(text, pos):
    m = _CURP.match(text, pos)
    if m:
        raw = m.group()
        if 1 <= int(raw[6:8]) <= 12 and 1 <= int(raw[8:10]) <= 31 and _curp_digit(raw[:17]) == raw[17]:
            yield m.start(), m.end()


# --- registry ---------------------------------------------------------------------------------------------

# (pack id, country code, token kind, sweep, finder). Sweep "num": find(text, start, end) over a run of digits and
# separators. Sweep "alpha": find(text, pos) at capital letters followed by digits. data.find_data keeps the
# longest match when two packs overlap.
PACKS = [
    ("us-ssn", "us", "ssn", "num", _us_ssn),
    ("gb-nino", "gb", "nino", "alpha", _gb_nino),
    ("in-aadhaar", "in", "aadhaar", "num", _in_aadhaar),
    ("br-cpf", "br", "cpf", "num", _br_cpf),
    ("iban", "intl", "iban", "alpha", _iban),
    ("es-dni", "es", "dni", "num", _es_dni),
    ("es-nie", "es", "dni", "alpha", _es_nie),
    ("nl-bsn", "nl", "bsn", "num", _nl_bsn),
    ("de-steuerid", "de", "steuerid", "num", _de_steuerid),
    ("ca-sin", "ca", "sin", "num", _ca_sin),
    ("sg-nric", "sg", "nric", "alpha", _sg_nric),
    ("fr-insee", "fr", "insee", "num", _fr_insee),
    ("it-cf", "it", "cf", "alpha", _it_cf),
    ("mx-curp", "mx", "curp", "alpha", _mx_curp),
]
KINDS = tuple(dict.fromkeys(p[2] for p in PACKS))

_RUN = re.compile(r"\d[\d .\-]{6,}\d")  # a run of digits and separators, 8 characters or more
_ANCHOR = re.compile(r"[A-Z]{1,6} ?\d\d")  # capital letters, then digits


def active(cfg):
    """The packs a config turns on: all of them unless data_packs names some."""
    chosen = (cfg or {}).get("data_packs")
    if chosen is None:
        return PACKS
    wanted = {str(c).lower() for c in chosen}
    return [p for p in PACKS if p[0] in wanted or p[1] in wanted]


def normalize(kind, value):
    """One token per identifier however it is spaced or hyphenated."""
    return re.sub(r"[^0-9A-Z]", "", value.upper())


def candidates(text, cfg=None):
    """(kind, start, end) for every identifier a pack finds in the text."""
    packs = active(cfg)
    if not packs:
        return
    num = [p for p in packs if p[3] == "num"]
    alpha = [p for p in packs if p[3] == "alpha"]
    if num:
        for run in _RUN.finditer(text):
            s, e = run.start(), min(len(text), run.end() + 3)  # a few characters past the run so a trailing letter fits
            for _, _, kind, _, find in num:
                for a, b in find(text, s, e):
                    if not _pathlike(text, a, b):
                        yield kind, a, b
    if alpha:
        for anchor in _ANCHOR.finditer(text):
            for _, _, kind, _, find in alpha:
                for a, b in find(text, anchor.start()):
                    if not _pathlike(text, a, b):
                        yield kind, a, b


# --- fake values, for tests and benches only --------------------------------------------------------------


def _digits(n, rng):
    return "".join(rng.choice("0123456789") for _ in range(n))


def fake(kind, rng=random):
    """A valid value of a kind, formatted the way people write it. Synthetic: it passes the checksum, nothing more."""
    if kind == "ssn":
        area = rng.choice([a for a in range(1, 900) if a != 666])
        return f"{area:03d}-{rng.randint(1, 99):02d}-{rng.randint(1, 9999):04d}"
    if kind == "nino":
        a, b = rng.choice("ABCEGHJKLMOPRSTWXYZ"), rng.choice("ABCEGHJKLMNPRSTWXYZ")
        while a + b in _NINO_BAD:
            b = rng.choice("ABCEGHJKLMNPRSTWXYZ")
        return f"{a}{b} {_digits(2, rng)} {_digits(2, rng)} {_digits(2, rng)} {rng.choice('ABCD')}"
    if kind == "aadhaar":
        body = rng.choice("23456789") + _digits(10, rng)
        d = body + _verhoeff_digit(body)
        return f"{d[:4]} {d[4:8]} {d[8:]}"
    if kind == "cpf":
        while True:
            nine = _digits(9, rng)
            if len(set(nine)) > 1:
                break
        d = nine + _cpf_digits(nine)
        return f"{d[:3]}.{d[3:6]}.{d[6:9]}-{d[9:]}"
    if kind == "iban":
        cc = rng.choice(sorted(IBAN_LEN))
        bban = "".join(rng.choice("0123456789ABCDEFGHJKLMNPQRSTUVWXYZ") for _ in range(IBAN_LEN[cc] - 4))
        n = int("".join(str(int(c, 36)) for c in bban + cc + "00"))
        raw = f"{cc}{98 - n % 97:02d}{bban}"
        return " ".join(raw[i:i + 4] for i in range(0, len(raw), 4))
    if kind == "dni":
        n = rng.randint(1, 99999999)
        return f"{n:08d}{_DNI_LETTERS[n % 23]}"
    if kind == "bsn":
        while True:
            eight = _digits(8, rng)
            last = sum(int(eight[i]) * (9 - i) for i in range(8)) % 11
            if last < 10 and eight != "00000000":
                return eight + str(last)
    if kind == "steuerid":
        while True:
            if rng.random() < 0.7:  # one digit twice, eight others once
                digits = rng.sample("0123456789", 9)
                digits.append(rng.choice(digits))
            else:  # one digit three times, seven others once
                digits = rng.sample("0123456789", 8)
                digits += [rng.choice(digits)] * 2
            rng.shuffle(digits)
            if digits[0] != "0":
                break
        first = "".join(digits)
        d = first + str(_steuerid_check(first))
        return f"{d[:2]} {d[2:5]} {d[5:8]} {d[8:]}"
    if kind == "sin":
        body = rng.choice("12345679") + _digits(7, rng)
        for c in "0123456789":
            if _luhn(body + c):
                return f"{body[:3]} {body[3:6]} {body[6:]}{c}"
    if kind == "nric":
        p, digits = rng.choice("STFG"), _digits(7, rng)
        return f"{p}{digits}{_nric_letter(p, digits)}"
    if kind == "insee":
        month = rng.randint(1, 12)
        body = f"{rng.choice('12')}{_digits(2, rng)}{month:02d}{_digits(2, rng)}{_digits(3, rng)}{_digits(3, rng)}"
        d = body + f"{97 - int(body) % 97:02d}"
        return f"{d[0]} {d[1:3]} {d[3:5]} {d[5:7]} {d[7:10]} {d[10:13]} {d[13:]}"
    if kind == "cf":
        L = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        first = ("".join(rng.choice(L) for _ in range(6)) + _digits(2, rng) + rng.choice("ABCDEHLMPRST")
                 + _digits(2, rng) + rng.choice(L) + _digits(3, rng))
        return first + _cf_char(first)
    if kind == "curp":
        first = ("".join(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(4)) + _digits(2, rng)
                 + f"{rng.randint(1, 12):02d}{rng.randint(1, 28):02d}" + rng.choice("HM") + "".join(
                     rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(2))
                 + "".join(rng.choice("BCDFGHJKLMNPQRSTVWXYZ") for _ in range(3)) + rng.choice("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
        return first + _curp_digit(first)
    raise ValueError(kind)


# Kinds whose rule is a checksum. A one-digit change must break them. SSN and NINO have structure rules only.
CHECKSUM_KINDS = ("aadhaar", "cpf", "iban", "dni", "bsn", "sin", "nric", "insee", "cf", "curp", "steuerid")


def test():
    bad = []

    def check(label, cond):
        if not cond:
            bad.append(label)

    rng = random.Random(20261115)

    def found(text, cfg=None):
        return [(k, text[s:e]) for k, s, e in candidates(text, cfg)]

    # Published examples and structure rules.
    vectors = {
        "ssn": ["123-45-6789"], "nino": ["AB123456C", "AB 12 34 56 C"], "aadhaar": ["2526 0181 5908"], "cpf": ["529.982.247-25"],
        "iban": ["GB82 WEST 1234 5698 7654 32", "DE89 3704 0044 0532 0130 00", "FR1420041010050500013M02606"],
        "dni": ["12345678Z", "X1234567L"], "sin": [], "nric": ["S1234567D"],
        "cf": ["RSSMRA85T10A562S"], "curp": ["HEGG560427MVZRRL04"], "steuerid": ["36 574 261 809"],
    }
    for kind, values in vectors.items():
        for v in values:
            got = found(f"record: {v} end")
            check(f"{kind}: {v} found", got == [(kind, v)])
    check("sin needs its word", found("rgb 130 692 544 teal") == [] and found("SIN: 130 692 544") == [("sin", "130 692 544")]
          and found("social insurance 130-692-544") == [("sin", "130-692-544")])
    check("steuer-id bare needs its word", found("ref 36574261809 ok") == []
          and found("Steuer-ID: 36574261809") == [("steuerid", "36574261809")]
          and found("IdNr 36574261809") == [("steuerid", "36574261809")])

    # The structure rule is tested apart from the checksum: each of these carries a correct check digit.
    def steuerid(first10):
        return first10 + str(_steuerid_check(first10))

    for label, first10, ok in [
        ("one digit twice", "1234567899", True), ("one digit three times", "1121345678", True),
        ("no digit repeated", "1234567890", False), ("two digits repeated", "1122345678", False),
        ("one digit four times", "1111234567", False), ("leading zero", "0123456788", False),
    ]:
        d = steuerid(first10)
        check(f"steuer-id structure: {label}", _steuerid_ok(d) == ok)
        spaced = f"{d[:2]} {d[2:5]} {d[5:8]} {d[8:]}"
        check(f"steuer-id detection: {label}", (found(f"tax {spaced} end") == [("steuerid", spaced)]) == ok)

    check("bsn needs its word", found("id 111222333 end") == [] and found("bsn: 111222333") == [("bsn", "111222333")])
    check("ssn bare needs its word", found("order 123456789 shipped") == [] and found("ssn 123456789") == [("ssn", "123456789")])
    check("cpf bare needs its word", found("ref 52998224725 ok") == [] and found("CPF 52998224725") == [("cpf", "52998224725")])
    check("aadhaar bare needs its word", found("ref 252601815908 ok") == []
          and found("aadhaar: 252601815908") == [("aadhaar", "252601815908")])

    # Things that must stay readable: structure rules, wrong checksums, documentation examples.
    for label, text in [
        ("ssn area 000", "000-12-3456"), ("ssn area 666", "666-12-3456"), ("ssn area 9xx", "912-34-5678"),
        ("ssn group 00", "123-00-6789"), ("ssn serial 0000", "123-45-0000"),
        ("nino documentation example", "QQ123456C"), ("nino banned prefix", "BG123456A"), ("nino bad suffix", "AB123456E"),
        ("cpf all the same digit", "111.111.111-11"), ("cpf bad check", "529.982.247-26"),
        ("iban bad check", "GB82 WEST 1234 5698 7654 33"), ("iban wrong length", "GB82 WEST 1234 5698 7654 3"),
        ("steuer-id bad check", "36 574 261 890"), ("steuer-id second repeated digit", "36 554 266 806"),
        ("aadhaar bad check", "2526 0181 5909"), ("dni wrong letter", "12345678A"), ("sin documentation example", "046 454 286"),
        ("nric wrong letter", "S1234567A"), ("curp bad digit", "HEGG560427MVZRRL05"), ("cf bad char", "RSSMRA85T10A562T"),
        ("scientific notation", "Decimal('1.38435736E+12')"), ("path component", "/data/123-45-6789/profile"),
        ("windows path", "C:\\Users\\123-45-6789\\notes"), ("file name", "export-123-45-6789.csv"),
        ("version string", "v1.2.3-45-6789"), ("phone", "415-555-0132"), ("date", "2026-11-15"),
        ("uuid", "123e4567-e89b-12d3-a456-426614174000"), ("git sha", "3d3c42e5aac5ba805825da76410c181273ba90b1"),
    ]:
        check(f"ignored: {label}", found(f"see {text} here") == [])

    # Every fake value passes its own detector, in the form people write it, and a one-digit change does not.
    for kind in KINDS:
        hits = 0
        for _ in range(120):
            v = fake(kind, rng)
            text = f"customer record: {v}, next field"
            if kind in ("bsn", "sin"):
                text = f"{kind}: {v}, next field"
            if found(text) == [(kind, v)]:
                hits += 1
            if kind in CHECKSUM_KINDS:
                pos = next(i for i, c in enumerate(v) if c.isdigit() and i > 1)
                mutated = v[:pos] + str((int(v[pos]) + 1) % 10) + v[pos + 1:]
                check(f"{kind}: one-digit change rejected ({v} -> {mutated})",
                      (kind, mutated) not in found(text.replace(v, mutated)))
        check(f"{kind}: fake values found ({hits}/120)", hits == 120)

    # Spacing does not change the token's identity.
    check("normalize spacing", normalize("iban", "GB82 WEST 1234 5698 7654 32") == normalize("iban", "gb82west12345698765432"))
    check("normalize nino", normalize("nino", "AB 12 34 56 C") == "AB123456C")

    # Transcripts hold JSON-escaped text: a value at the end of a line or string is followed by \\n or \\".
    check("value before an escaped newline", found('"id|AB 12 34 56 C\\n"') == [("nino", "AB 12 34 56 C")]
          and found('{"ssn": "123-45-6789\\n"}') == [("ssn", "123-45-6789")]
          and found('{"ssn": "123-45-6789"}') == [("ssn", "123-45-6789")])

    # An IBAN followed by a capitalised word is cut at its own length.
    check("iban cut before next word", found("pay DE89370400440532013000 TEST now") == [("iban", "DE89370400440532013000")])

    # Config.
    check("default is all", len(active({})) == len(PACKS) and len(active({"data_packs": None})) == len(PACKS))
    check("es has two packs, one kind", [p[0] for p in active({"data_packs": ["es"]})] == ["es-dni", "es-nie"])
    check("none", active({"data_packs": []}) == [] and found("123-45-6789", {"data_packs": []}) == [])
    check("by country", [p[0] for p in active({"data_packs": ["US", "iban"]})] == ["us-ssn", "iban"])
    check("by pack id", [p[0] for p in active({"data_packs": ["gb-nino"]})] == ["gb-nino"])
    check("off pack not read", found("123-45-6789 AB123456C", {"data_packs": ["gb"]}) == [("nino", "AB123456C")])

    # Plain text with no digits is skipped before any pattern runs.
    aad, ins = fake("aadhaar", rng), fake("insee", rng).replace(" ", "")
    check("aadhaar inside a list of digit groups", found(f"ids 4821 {aad} 7710 end") == []
          and found(f"ids {aad} 7710 end") == [] and found(f"ids 4821 {aad} end") == [])
    check("insee inside a hash", found(f"ref a9f{ins}c2 end") == [])
    check("no digits no work", found("nothing numeric in this sentence at all") == [])
    check("trailing letter after a run", found("id 12345678Z") == [("dni", "12345678Z")] and found("id 12345678-Z") == [("dni", "12345678-Z")]
          and found("size 12345678 B") == [])  # a byte count, not a DNI: the letter must touch the digits

    if bad:
        print("WRONG:\n  " + "\n  ".join(bad[:30]) + (f"\n  ... and {len(bad) - 30} more" if len(bad) > 30 else ""))
        sys.exit(1)
    print(f"ok: packs self-check passed ({len(PACKS)} packs, {len(KINDS)} kinds)")


if __name__ == "__main__":
    if "--list" in sys.argv:
        for pid, country, kind, sweep, _ in PACKS:
            print(f"{pid:<11} country {country:<5} kind {kind:<8} sweep {sweep}")
    elif "--test" in sys.argv:
        test()
    else:
        print(__doc__)
