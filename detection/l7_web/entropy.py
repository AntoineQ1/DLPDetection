"""Shannon-entropy based detection of high-entropy tokens (Workstream B).

`shannon_entropy` is the shared math primitive, also reused by the covert
channel detectors. Thresholds and how text is split into tokens stay in each
detector.
"""

from __future__ import annotations

import math

from . import Finding


def shannon_entropy(text: str) -> float:
    """Per-character Shannon entropy in bits."""
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def scan(text: str) -> list[Finding]:
    return []
