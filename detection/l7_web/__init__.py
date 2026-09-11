"""L7 web-layer DLP inspection (Workstream B).

Public contract used by the mitmproxy addon and the test suite:

    from detection.l7_web import scan_all, Finding

    findings = scan_all(text, source="body")
    if findings:
        # block the flow, log findings
        ...

Each detector module (`regex_rules`, `luhn`, `entropy`) exposes a
`scan(text: str) -> list[Finding]` function. `scan_all` aggregates them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

Severity = Literal["low", "medium", "high"]


@dataclass(frozen=True)
class Finding:
    """A single DLP hit produced by an L7 detector.

    Attributes:
        rule_id:   Stable identifier, e.g. "pem_private_key", "luhn_cc",
                   "high_entropy_token". Used by tests and the eval matrix.
        detector:  Which module produced the hit ("regex" | "luhn" | "entropy").
        severity:  Rough triage class, used by the addon to decide block vs log.
        matched:   The offending substring (may be truncated when logged).
        start:     Byte offset of the match in the scanned text.
        end:       Byte offset one past the last matched byte.
        source:    Where the text came from ("body", "header:<name>", "url", ...).
        meta:      Detector-specific extras (regex group name, entropy value, ...).
    """

    rule_id: str
    detector: str
    severity: Severity
    matched: str
    start: int
    end: int
    source: str = "body"
    meta: dict = field(default_factory=dict)


def scan_all(text: str, source: str = "body") -> list[Finding]:
    """Run every L7 detector against `text` and return the union of findings.

    Kept dependency-free so tests can call it without spinning up mitmproxy.
    """
    from . import regex_rules, luhn, entropy

    hits: list[Finding] = []
    for module in (regex_rules, luhn, entropy):
        hits.extend(_tagged(module.scan(text), source))
    return hits


def _tagged(findings: list[Finding], source: str) -> list[Finding]:
    """Stamp the source onto findings that didn't set one explicitly."""
    out: list[Finding] = []
    for f in findings:
        if f.source == "body" and source != "body":
            out.append(
                Finding(
                    rule_id=f.rule_id,
                    detector=f.detector,
                    severity=f.severity,
                    matched=f.matched,
                    start=f.start,
                    end=f.end,
                    source=source,
                    meta=f.meta,
                )
            )
        else:
            out.append(f)
    return out


__all__ = ["Finding", "Severity", "scan_all"]
