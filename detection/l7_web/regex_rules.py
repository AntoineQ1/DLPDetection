"""Regex-based secret detection (Workstream B).
"""

from __future__ import annotations

import re

from . import Finding

# I will add here rules during this week based on this fonts:
# https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml 
# https://docs.github.com/en/code-security/secret-scanning/introduction/supported-secret-scanning-patterns
# https://github.com/trufflesecurity/trufflehog
# https://mazinahmed.net/blog/secrets-patterns-db/
# https://github.com/mazen160/secrets-patterns-db

RULES = [
    {"id": "AWS_VERY_REAL_API_KEY", "regex": re.compile("api-key"), "severity": "high"}, # Dummy regex just for testing purposes
]

def scan(text: str) -> list[Finding]:
    hits: list[Finding] = []
    for rule in RULES:
        for m in rule["regex"].finditer(text):
            hits.append(
                Finding(
                    rule_id=rule["id"],
                    detector="regex",
                    severity=rule["severity"],
                    matched=m.group(0),
                    start=m.start(),
                    end=m.end(),
                    meta={},
                )
            )
    return hits