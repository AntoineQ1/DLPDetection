"""ICMP covert channel detection engine - Parsing & structural heuristics."""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from detection.common.types import Severity

from scapy.layers.inet import ICMP, IP

from detection.l7_web import scan_all

if TYPE_CHECKING:
    from scapy.packet import Packet

# Constants RFC 792 for message types
ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0

# Standard ping payloads for Windows and Linux
WINDOWS_PING_PAYLOAD = b"abcdefghijklmnopqrstuvwabcdefghi"
LINUX_PING_PATTERN = bytes(range(16, 56))
STANDARD_PAYLOAD_SIZES = {32, 56}
MAX_STANDARD_PAYLOAD_SIZE = 64

# Rate limiting defaults (human ping = 1 pkt/s)
DEFAULT_WINDOW_SECONDS = 1.0
DEFAULT_MAX_REQUESTS_PER_WINDOW = 4


@dataclass(frozen=True)
class ICMPEchoMessage:
    """Represents a parsed ICMP Echo Request message with its fields."""

    source_ip: str
    destination_ip: str
    icmp_type: int
    icmp_code: int
    icmp_id: int | None
    icmp_seq: int | None
    payload: bytes
    payload_size: int


@dataclass(frozen=True)
class ICMPFinding:
    """Represents a finding from an ICMP anomaly detected in a packet."""

    rule_id: str
    severity: Severity
    description: str
    details: dict[str, Any] = field(default_factory=dict)


class ICMPRateTracker:
    """Tracks ICMP Echo Request frequencies per source IP over a sliding time window."""

    def __init__(
        self,
        window_seconds: float = DEFAULT_WINDOW_SECONDS,
        max_requests: int = DEFAULT_MAX_REQUESTS_PER_WINDOW,
    ) -> None:
        self.window_seconds = window_seconds
        self.max_requests = max_requests
        self._history: dict[str, deque[float]] = defaultdict(deque)

    def record_and_check(
        self,
        source_ip: str,
        timestamp: float | None = None,
    ) -> list[ICMPFinding]:
        """Record an arrival and check if the source IP exceeded the rate threshold."""
        now = time.time() if timestamp is None else timestamp
        window_start = now - self.window_seconds

        queue = self._history[source_ip]

        # Evict timestamps outside the sliding window
        while queue and queue[0] <= window_start:
            queue.popleft()

        queue.append(now)

        if len(queue) > self.max_requests:
            return [
                ICMPFinding(
                    rule_id="icmp_high_frequency",
                    severity="high",
                    description=(
                        f"Abnormal ICMP Echo frequency: {len(queue)} requests in "
                        f"{self.window_seconds:.1f}s window from {source_ip} "
                        f"(threshold: {self.max_requests})"
                    ),
                    details={
                        "count": len(queue),
                        "window_seconds": self.window_seconds,
                        "threshold": self.max_requests,
                        "source_ip": source_ip,
                    },
                )
            ]

        return []

    def reset(self) -> None:
        """Clear all tracking state (used primarily for test isolation)."""
        self._history.clear()


def parse_icmp_echo(pkt: Packet) -> ICMPEchoMessage | None:
    """Parse an ICMP Echo Request packet and extract its fields.
    """
    if not (pkt.haslayer(IP) and pkt.haslayer(ICMP)):
        return None

    icmp_layer = pkt[ICMP]

    # Only process Echo Request messages (type 8) (not Echo Reply)
    if icmp_layer.type != ICMP_ECHO_REQUEST:
        return None

    payload_bytes = bytes(icmp_layer.payload)

    return ICMPEchoMessage(
        source_ip=pkt[IP].src,
        destination_ip=pkt[IP].dst,
        icmp_type=icmp_layer.type,
        icmp_code=icmp_layer.code,
        icmp_id=getattr(icmp_layer, "id", None),
        icmp_seq=getattr(icmp_layer, "seq", None),
        payload=payload_bytes,
        payload_size=len(payload_bytes),
    )


def is_known_benign_payload(payload: bytes) -> bool:
    """Check if the payload matches known benign ping patterns (Windows or Linux)."""
    if payload == WINDOWS_PING_PAYLOAD:
        return True
    elif len(payload) == 56 and payload[16:] == LINUX_PING_PATTERN:
        return True
    else:
        return False


def check_structure(msg: ICMPEchoMessage) -> list[ICMPFinding]:
    """Check the structure of the ICMP Echo Request message for anomalies."""
    findings: list[ICMPFinding] = []

    # Ignore known benign payloads to reduce false positives
    if is_known_benign_payload(msg.payload):
        return findings

    # Case 1: Payload size exceeds standard threshold
    if msg.payload_size > MAX_STANDARD_PAYLOAD_SIZE:
        findings.append(
            ICMPFinding(
                rule_id="icmp_oversized_payload",
                severity=Severity.HIGH,
                description=f"Payload size ({msg.payload_size} bytes) exceeds standard threshold ({MAX_STANDARD_PAYLOAD_SIZE} bytes)",
                details={"payload_size": msg.payload_size, "threshold": MAX_STANDARD_PAYLOAD_SIZE},
            )
        )
        return findings

    # Case 2: Payload size is non-standard (not 32 or 56 bytes)
    if msg.payload_size not in STANDARD_PAYLOAD_SIZES:
        findings.append(
            ICMPFinding(
                rule_id="icmp_non_standard_size",
                severity=Severity.MEDIUM,
                description=f"Payload size ({msg.payload_size} bytes) deviates from standard OS ping sizes (32, 56)",
                details={"payload_size": msg.payload_size, "expected_sizes": sorted(STANDARD_PAYLOAD_SIZES)},
            )
        )
        return findings

    # Case 3: Altered content (attempt to evade by chunking)
    findings.append(
        ICMPFinding(
            rule_id="icmp_abnormal_pattern",
            severity=Severity.MEDIUM,
            description=f"Payload size is {msg.payload_size} bytes but content does not match standard OS ping signature",
            details={"payload_size": msg.payload_size},
        )
    )

    return findings

def check_content(msg: ICMPEchoMessage) -> list[ICMPFinding]:
    """Scan the ICMP payload for sensitive data using the shared L7 inspection engine."""
    if not msg.payload:
        return []

    decoded_text = msg.payload.decode("utf-8", errors="ignore")
    if not decoded_text.strip():
        return []

    findings: list[ICMPFinding] = []
    l7_findings = scan_all(decoded_text, source="icmp_payload")

    for hit in l7_findings:

        findings.append(
            ICMPFinding(
                rule_id=f"icmp_sensitive_data_{hit.rule_id}",
                severity=hit.severity,
                description=f"Sensitive content detected in ICMP payload via L7 rule '{hit.rule_id}'",
                details={
                    "matched": hit.matched,
                    "detector": hit.detector,
                    "source": hit.source,
                    "l7_rule_id": hit.rule_id,
                    **hit.meta,
                },
            )
        )

    return findings


def analyze_icmp_message(
    msg: ICMPEchoMessage,
    rate_tracker: ICMPRateTracker | None = None,
    timestamp: float | None = None,
) -> list[ICMPFinding]:
    """Execute all heuristics (structural, content, and rate limiting) on an ICMP message."""
    findings: list[ICMPFinding] = []

    # 1. Structural inspection
    findings.extend(check_structure(msg))

    # 2. Content inspection (DLP engine)
    findings.extend(check_content(msg))

    # 3. Behavioral inspection (Rate limiting)
    if rate_tracker is not None:
        findings.extend(rate_tracker.record_and_check(msg.source_ip, timestamp=timestamp))

    return findings