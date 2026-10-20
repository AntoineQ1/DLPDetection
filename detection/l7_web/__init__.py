from dataclasses import dataclass, field

from detection.common.types import Severity


@dataclass
class Finding:
    rule_id: str
    detector: str
    severity: Severity
    matched: str
    start: int
    end: int
    source: str = "body"
    meta: dict = field(default_factory=dict)

# Helper to prevent invisible unicode chars
def _remove_invisible_text(text: str) -> str:
    return "".join(char for char in text if char.isprintable())

def scan_all(text: str, source: str = "body") -> list[Finding]:
    from . import entropy, luhn, regex_rules
    text = _remove_invisible_text(text)
    hits: list[Finding] = []
    for module in (regex_rules, luhn, entropy):
        for f in module.scan(text):
            if source != "body" and f.source == "body":
                f.source = source
            hits.append(f)
    return hits
