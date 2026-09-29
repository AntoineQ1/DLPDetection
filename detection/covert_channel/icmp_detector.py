"""ICMP covert channel detection engine - Parsing & analysis."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from scapy.layers.inet import ICMP, IP

if TYPE_CHECKING:
    from scapy.packet import Packet

# Constants RFC 792 for message types
ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0


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
