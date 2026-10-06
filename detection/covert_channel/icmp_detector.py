import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any

from scapy.layers.inet import ICMP, IP
from scapy.packet import Packet

from detection.common.types import Severity
from detection.l7_web import scan_all

# RFC 792 message types
ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0

# Standard ping payloads for Windows and Linux
WINDOWS_PING_PAYLOAD = b"abcdefghijklmnopqrstuvwabcdefghi"
LINUX_PING_PATTERN = bytes(range(16, 56))
STANDARD_PAYLOAD_SIZES = {32, 56}
MAX_STANDARD_PAYLOAD_SIZE = 64

# Default rate limits (standard ping is around 1 pkt/s)
DEFAULT_WINDOW_SECONDS = 1.0
DEFAULT_MAX_REQUESTS_PER_WINDOW = 4


@dataclass(frozen=True)
class ICMPEchoMessage:
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
    rule_id: str
    severity: Severity
    description: str
    details: dict[str, Any] = field(default_factory=dict)


class ICMPRateTracker:
    """Sliding-window tracker to detect ICMP bursts per source IP."""

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
        now = time.time() if timestamp is None else timestamp
        window_start = now - self.window_seconds

        queue = self._history[source_ip]

        # Drop timestamps older than the sliding window
        while queue and queue[0] <= window_start:
            queue.popleft()

        queue.append(now)

        if len(queue) > self.max_requests:
            return [
                ICMPFinding(
                    rule_id="icmp_high_frequency",
                    severity=Severity.HIGH,
                    description=(
                        f"Abnormal ICMP Echo frequency: {len(queue)} requests in "
                        f"{self.window_seconds:.1f}s from {source_ip} "
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
        self._history.clear()


def parse_icmp_echo(pkt: Packet) -> ICMPEchoMessage | None:
    """Extract relevant fields from an ICMP Echo Request packet."""
    if not (pkt.haslayer(IP) and pkt.haslayer(ICMP)):
        return None

    icmp = pkt[ICMP]
    if icmp.type != ICMP_ECHO_REQUEST:
        return None

    payload = bytes(icmp.payload)

    return ICMPEchoMessage(
        source_ip=pkt[IP].src,
        destination_ip=pkt[IP].dst,
        icmp_type=icmp.type,
        icmp_code=icmp.code,
        icmp_id=getattr(icmp, "id", None),
        icmp_seq=getattr(icmp, "seq", None),
        payload=payload,
        payload_size=len(payload),
    )


def is_known_benign_payload(payload: bytes) -> bool:
    """Check if payload matches standard Windows or Linux ping data."""
    return payload == WINDOWS_PING_PAYLOAD or (
        len(payload) == 56 and payload[16:] == LINUX_PING_PATTERN
    )


def check_structure(msg: ICMPEchoMessage) -> list[ICMPFinding]:
    """Inspect payload size and pattern for structural anomalies."""
    if is_known_benign_payload(msg.payload):
        return []

    # 1. Payload exceeds standard size
    if msg.payload_size > MAX_STANDARD_PAYLOAD_SIZE:
        return [
            ICMPFinding(
                rule_id="icmp_oversized_payload",
                severity=Severity.HIGH,
                description=f"Payload size ({msg.payload_size} bytes) exceeds standard threshold ({MAX_STANDARD_PAYLOAD_SIZE} bytes)",
                details={
                    "payload_size": msg.payload_size,
                    "threshold": MAX_STANDARD_PAYLOAD_SIZE,
                },
            )
        ]

    # 2. Non-standard payload size
    if msg.payload_size not in STANDARD_PAYLOAD_SIZES:
        return [
            ICMPFinding(
                rule_id="icmp_non_standard_size",
                severity=Severity.MEDIUM,
                description=f"Payload size ({msg.payload_size} bytes) deviates from standard OS ping sizes (32, 56)",
                details={
                    "payload_size": msg.payload_size,
                    "expected_sizes": sorted(STANDARD_PAYLOAD_SIZES),
                },
            )
        ]

    # 3. Standard size (32 or 56B), but altered content
    return [
        ICMPFinding(
            rule_id="icmp_abnormal_pattern",
            severity=Severity.MEDIUM,
            description=f"Payload size is {msg.payload_size} bytes but content does not match standard OS ping signature",
            details={"payload_size": msg.payload_size},
        )
    ]


def check_content(msg: ICMPEchoMessage) -> list[ICMPFinding]:
    """Scan payload text for sensitive data using the L7 engine."""
    if not msg.payload:
        return []

    decoded_text = msg.payload.decode("utf-8", errors="ignore")
    if not decoded_text.strip():
        return []

    findings: list[ICMPFinding] = []
    for hit in scan_all(decoded_text, source="icmp_payload"):
        findings.append(
            ICMPFinding(
                rule_id=f"icmp_sensitive_data_{hit.rule_id}",
                severity=hit.severity,
                description=f"Sensitive content detected in ICMP payload via rule '{hit.rule_id}'",
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
    """Run all detection checks (structure, content, rate) on an ICMP message."""
    findings: list[ICMPFinding] = []

    findings.extend(check_structure(msg))
    findings.extend(check_content(msg))

    if rate_tracker is not None:
        findings.extend(
            rate_tracker.record_and_check(msg.source_ip, timestamp=timestamp)
        )

    return findings
