"""Shannon-entropy based detection of high-entropy tokens (Workstream B).

Scaffold only. `scan()` currently returns no findings so that `scan_all()`
in `detection.l7_web.__init__` can import this module without error while
the entropy heuristic (tokenization, threshold, alphabet handling) is still
being decided. To be filled in by the Workstream B co-owner.
"""

from __future__ import annotations

from . import Finding


def scan(text: str) -> list[Finding]:
    return []
