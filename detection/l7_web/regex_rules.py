"""Regex-based secret detection (Workstream B).

Scaffold only. `RULES` is intentionally empty so that `scan_all()` in
`detection.l7_web.__init__` can import this module without error while the
concrete patterns (PEM private keys, AWS/Google/Slack/GitHub tokens, JWTs,
...) are still being decided. To be filled in by the Workstream B co-owner.
"""

from __future__ import annotations

import re

from . import Finding, Severity

# (rule_id, severity, compiled pattern) — populate to enable this detector.
RULES: list[tuple[str, Severity, re.Pattern[str]]] = []


def scan(text: str) -> list[Finding]:
    hits: list[Finding] = []
    for rule_id, severity, pattern in RULES:
        for m in pattern.finditer(text):
            hits.append(
                Finding(
                    rule_id=rule_id,
                    detector="regex",
                    severity=severity,
                    matched=m.group(0),
                    start=m.start(),
                    end=m.end(),
                )
            )
    return hits
