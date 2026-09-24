"""Credit-card number detection with Luhn validation (Workstream B).

Owner: <assign in team split>

Two-stage pipeline:
    1. Regex pre-filter: 13-19 digit runs, optionally split by spaces/dashes.
    2. `luhn_valid(digits)` check on the normalized digit string.

Only stage-2 hits become Findings, which keeps the FP rate down when
scanning bodies that happen to contain long numeric runs (order ids,
tracking numbers, hex-encoded blobs).
"""

from __future__ import annotations

import re

from . import Finding

_CANDIDATE = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")


def luhn_valid(digits: str) -> bool:

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


def scan(text: str) -> list[Finding]:
    hits: list[Finding] = []
    for m in _CANDIDATE.finditer(text):
        raw = m.group(0)
        digits = re.sub(r"[ -]", "", raw)
        if 13 <= len(digits) <= 19 and luhn_valid(digits):
            hits.append(
                Finding(
                    rule_id="luhn_cc",
                    detector="luhn",
                    severity="high",
                    matched=raw,
                    start=m.start(),
                    end=m.end(),
                    meta={"digits": len(digits)},
                )
            )
    return hits
