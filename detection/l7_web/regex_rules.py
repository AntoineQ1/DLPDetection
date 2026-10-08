"""Regex-based secret detection (Workstream B)."""

from __future__ import annotations

import re
from typing import NamedTuple

from . import Finding, Severity

from detection.common.types import Severity

class RegexRule(NamedTuple):
    rule_id: str
    pattern: re.Pattern
    severity: Severity


# Compiled patterns for standard high-confidence credentials
RULES: list[RegexRule] = [
    # AWS
    RegexRule(
        rule_id="AWS Token",
        pattern=re.compile(r"(?:ABIA|ACCA|AGPA|AIDA|AIPA|AKIA|ANPA|ANVA|APKA|AROA|ASCA|ASIA)[0-9A-Z]{16}"),
        severity=Severity.HIGH,
    ),
    # GitHub
    RegexRule(
        rule_id="GitHub Token",
        pattern=re.compile(r"(?:ghp_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9_]{36,}"),
        severity=Severity.HIGH,
    ),
    RegexRule(
        rule_id="GitHub PAT",
        pattern=re.compile("github_pat_[A-Za-z0-9_]{82}"),
        severity=Severity.HIGH,
    ),
    # OpenAI API
    RegexRule(
        rule_id="OpenAI API Key (user-level)",
        pattern=re.compile("sk-[A-Za-z0-9]{48}"),
        severity=Severity.HIGH,
    ),
    RegexRule(
        rule_id="OpenAI API Key (scoped-keys)",
        pattern=re.compile("sk-proj-[A-Za-z0-9_-]{100,}"),
        severity=Severity.HIGH,
    ),
    # Anthropic
    RegexRule(
        rule_id="Anthropic API Key",
        pattern=re.compile("sk-ant-[A-Za-z0-9_-]{80,}"),
        severity=Severity.HIGH,
    ),
    # Google
    RegexRule(
        rule_id="Google Cloud API Key",
        pattern=re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
        severity=Severity.HIGH,
    ),
    RegexRule(
        rule_id="Google Gemini API Key",
        pattern=re.compile(r"AQ\.[A-Za-z0-9_-]{50}"),
        severity=Severity.HIGH,
    ),
    # JWT
    RegexRule(
        rule_id="JWT",
        pattern=re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
        severity=Severity.HIGH,
    ),
    # Stripe
    RegexRule(
        rule_id="Stripe key",
        pattern=re.compile(r"(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{10,128}"),
        severity=Severity.HIGH,
    ),
    # Cloudflare
    RegexRule(
        rule_id="Cloudflare Account Token",
        pattern=re.compile(r"(?:cfat_|cfk_|cfut_)[A-Za-z0-9]{40}[A-Za-z0-9]{8}"),
        severity=Severity.HIGH,
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
