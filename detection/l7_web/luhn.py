"""Credit-card number detection (Workstream B).

Pipeline:
    1. Regex pre-filter: 13-19 digit runs, optionally split by spaces/dashes.
    2. `credit_card_detector(digits)`: check issuer length, prefix and Luhn checksum when the issuer uses luhn.
"""

from __future__ import annotations

import re
from typing import NamedTuple

from . import Finding

_CANDIDATE = re.compile(r"(?<!\d)(?:\d[ ._-]?){11,18}\d(?!\d)")


class Issuer(NamedTuple):
    name: str
    prefixes: list
    lengths: tuple
    active: bool
    uses_luhn: bool
    include_detection: bool


ISSUERS = [  # https://en.wikipedia.org/wiki/Payment_card_number
    #      Name                          Prefix                                                        size      active uses_luhn include
    Issuer("American Express", [("34", "34"), ("37", "37")], (15,), True, True, True),
    Issuer(
        "Bankcard", [("5610", "5610"), ("560221", "560225")], (16,), False, True, True
    ),
    Issuer("China T-Union", [("31", "31")], (19,), True, True, True),
    Issuer("China UnionPay", [("62", "62")], (16, 17, 18, 19), True, True, True),
    Issuer("Diners Club enRoute", [], (15,), True, False, False),
    Issuer(
        "Diners Club International",
        [("30", "30"), ("36", "36"), ("38", "38"), ("39", "39")],
        tuple(range(14, 20)),
        True,
        True,
        True,
    ),
    Issuer("Diners Club US & Canada", [("55", "55")], (16,), True, True, True),
    Issuer(
        "Discover",
        [("6011", "6011"), ("644", "649"), ("65", "65")],
        (16, 17, 18, 19),
        True,
        True,
        True,
    ),
    Issuer(
        "Discover (UnionPay co-brand)",
        [("622126", "622925")],
        (16, 17, 18, 19),
        True,
        True,
        True,
    ),
    Issuer("UkrCart", [("60400100", "60420099")], (16, 17, 18, 19), True, True, True),
    Issuer(
        "RuPay",
        [("60", "60"), ("65", "65"), ("81", "81"), ("82", "82"), ("508", "508")],
        (16,),
        True,
        True,
        True,
    ),
    Issuer("RuPay-JCB", [("353", "353"), ("356", "356")], (16,), True, True, True),
    Issuer("InterPayment", [("636", "636")], (16, 17, 18, 19), True, True, True),
    Issuer("InstaPayment", [("637", "639")], (16,), True, True, True),
    Issuer("JCB", [("3528", "3589")], (16, 17, 18, 19), True, True, True),
    Issuer("LankaPay", [("357111", "357111")], (16,), True, True, True),
    Issuer(
        "Laser",
        [("6304", "6304"), ("6706", "6706"), ("6771", "6771"), ("6709", "6709")],
        (16, 17, 18, 19),
        False,
        True,
        True,
    ),
    Issuer(
        "Maestro UK",
        [("6759", "6759"), ("676770", "676770"), ("676774", "676774")],
        tuple(range(12, 20)),
        True,
        True,
        True,
    ),
    Issuer(
        "Maestro",
        [
            ("5018", "5018"),
            ("5020", "5020"),
            ("5038", "5038"),
            ("5893", "5893"),
            ("6304", "6304"),
            ("6759", "6759"),
            ("6761", "6761"),
            ("6762", "6762"),
            ("6763", "6763"),
        ],
        tuple(range(12, 20)),
        True,
        True,
        True,
    ),
    Issuer("Dankort", [("5019", "5019"), ("4571", "4571")], (16,), True, True, True),
    Issuer("Mir", [("2200", "2204")], (16, 17, 18, 19), True, True, True),
    Issuer("BORICA", [("2205", "2205")], (16,), True, True, True),
    Issuer("NPS Pridnestrovie", [("6054740", "6054744")], (16,), False, True, True),
    Issuer("Mastercard", [("2221", "2720"), ("51", "55")], (16,), True, True, True),
    Issuer(
        "Solo", [("6334", "6334"), ("6767", "6767")], (16, 18, 19), False, True, True
    ),
    Issuer(
        "Switch",
        [
            ("4903", "4903"),
            ("4905", "4905"),
            ("4911", "4911"),
            ("4936", "4936"),
            ("564182", "564182"),
            ("633110", "633110"),
            ("6333", "6333"),
            ("6759", "6759"),
        ],
        (16, 18, 19),
        False,
        True,
        True,
    ),
    Issuer("Troy", [("65", "65"), ("9792", "9792")], (16,), True, True, True),
    Issuer("Visa", [("4", "4")], (13, 16, 19), True, True, True),
    Issuer(
        "Visa Electron",
        [
            ("4026", "4026"),
            ("417500", "417500"),
            ("4844", "4844"),
            ("4913", "4913"),
            ("4917", "4917"),
        ],
        (16,),
        False,
        True,
        True,
    ),
    Issuer("UATP", [("1", "1")], (15,), True, True, True),
    Issuer(
        "Verve",
        [("506099", "506198"), ("650002", "650027"), ("507865", "507964")],
        (16, 18, 19),
        True,
        True,
        True,
    ),
    Issuer("Uzcard", [("8600", "8600"), ("5614", "5614")], (16,), True, True, True),
    Issuer("HUMO", [("9860", "9860")], (16,), True, True, True),
    Issuer(
        "GPN",
        [("1946", "1946"), ("50", "50"), ("56", "56"), ("58", "58"), ("60", "63")],
        (16, 18, 19),
        True,
        True,
        True,
    ),
    Issuer("Napas", [("9704", "9704")], (16, 19), True, False, True),
    Issuer("WEX", [("960046", "960046")], (19,), True, False, True),
]


def luhn_valid(digits: str) -> bool:
    if not digits.isdigit():
        return False

    string_list = list(digits)
    int_list = [int(x) for x in string_list]
    reversed_list = list(reversed(int_list))

    total = 0
    for i in range(len(reversed_list)):
        if i % 2 == 1:
            reversed_list[i] = reversed_list[i] * 2
        if reversed_list[i] > 9:
            reversed_list[i] = reversed_list[i] - 9
        total += reversed_list[i]

    return total % 10 == 0


def verify_prefix(digits: str, prefixes: list) -> bool:
    for i in range(len(prefixes)):
        low = prefixes[i][0]
        high = prefixes[i][1]
        size = len(low)  # n digits of prefix
        start = int(digits[0:size])
        if start >= int(low) and start <= int(high):
            return True
    return False


def credit_card_detector(digits: str) -> Issuer | None:
    luhn_res = luhn_valid(digits)
    for issuer in ISSUERS:
        if not issuer.include_detection:  # For test and statistic purposes
            continue
        if len(digits) not in issuer.lengths:
            continue
        if issuer.uses_luhn and not luhn_res:
            continue
        if verify_prefix(digits, issuer.prefixes):
            return issuer
    return None


def scan(text: str) -> list[Finding]:
    hits: list[Finding] = []
    for m in _CANDIDATE.finditer(text):
        raw = m.group(0)
        digits = re.sub(r"[ ._-]", "", raw)
        issuer = credit_card_detector(digits)
        if issuer is not None:
            hits.append(
                Finding(
                    rule_id="luhn_cc",
                    detector="luhn",
                    severity="high",
                    matched=raw,
                    start=m.start(),
                    end=m.end(),
                    meta={"digits": len(digits), "issuing_network": issuer.name},
                )
            )
    return hits
