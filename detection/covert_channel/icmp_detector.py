"""ICMP covert channel detection engine - Parsing & structural heuristics."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from scapy.layers.inet import ICMP, IP

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
    severity: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    description: str
    details: dict[str, Any] = field(default_factory=dict)


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
                severity="HIGH",
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
                severity="MEDIUM",
                description=f"Payload size ({msg.payload_size} bytes) deviates from standard OS ping sizes (32, 56)",
                details={"payload_size": msg.payload_size, "expected_sizes": sorted(STANDARD_PAYLOAD_SIZES)},
            )
        )
        return findings

    # Case 3: Altered content (attempt to evade by chunking)
    findings.append(
        ICMPFinding(
            rule_id="icmp_abnormal_pattern",
            severity="MEDIUM",
            description=f"Payload size is {msg.payload_size} bytes but content does not match standard OS ping signature",
            details={"payload_size": msg.payload_size},
        )
    )

    return findings