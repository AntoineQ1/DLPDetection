"""Regex-based secret detection (Workstream B)."""

from __future__ import annotations

import re
from typing import NamedTuple

from . import Finding, Severity


class RegexRule(NamedTuple):
    rule_id: str
    pattern: re.Pattern
    severity: Severity


# Compiled patterns for standard high-confidence credentials
RULES: list[RegexRule] = [
    RegexRule(
        rule_id="AWS_VERY_REAL_API_KEY",
        pattern=re.compile("api-key"),
        severity="high",
    ),
]


def scan(text: str) -> list[Finding]:
    hits: list[Finding] = []
    for rule in RULES:
        for m in rule.pattern.finditer(text):
            hits.append(
                Finding(
                    rule_id=rule.rule_id,
                    detector="regex",
                    severity=rule.severity,
                    matched=m.group(0),
                    start=m.start(),
                    end=m.end(),
                    meta={},
                )
            )
    return hits
