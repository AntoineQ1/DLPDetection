"""Shannon-entropy based detection of high-entropy tokens (Workstream B).

`shannon_entropy` is the shared math primitive, also reused by the covert
channel detectors. Thresholds and how text is split into tokens stay in each
detector.
"""

from __future__ import annotations

import math
import os
import re

from detection.common.types import Severity

from . import Finding

ENTROPY_THRESHOLD = float(os.environ.get("L7_ENTROPY_THRESHOLD", "4.7"))
ENTROPY_MIN_CHARS = int(os.environ.get("L7_ENTROPY_MIN_CHARS", "16"))
_TOKEN_RE = re.compile(r"[A-Za-z0-9+/=._\-]{16,}")


def shannon_entropy(text: str) -> float:
    """Per-character Shannon entropy in bits."""
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


# Teoretical Max of Shanon Entropy Function => log_2(n)
# Most of the tokens use 0-9a-zA-z and some other characters suchs as . \ - _
# Being conservative, n ~= 10 + 26 + 26 = 62
# log_2(62) ~= 5.95
#  2.14 < entropy of normal english text < 4.76
# So a good threshold is 4.70
# It will detect some false positives but that is beter than letting a possible normal entropy secret pass
def scan(text: str) -> list[Finding]:
    hits: list[Finding] = []
    for m in _TOKEN_RE.finditer(text):
        token = m.group(0)
        if (
            len(token) >= ENTROPY_MIN_CHARS
            and shannon_entropy(token) >= ENTROPY_THRESHOLD
        ):
            hits.append(
                Finding(
                    rule_id="high_entropy",
                    detector="shannon_entropy",
                    severity=Severity.MEDIUM,
                    matched=token,
                    start=m.start(),
                    end=m.end(),
                    meta={"entropy": round(shannon_entropy(token), 3)},
                )
            )
    return hits
