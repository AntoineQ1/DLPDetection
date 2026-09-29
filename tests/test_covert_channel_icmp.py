"""Unit tests for the ICMP covert channel detection engine."""

from scapy.layers.inet import ICMP, IP, TCP
from scapy.packet import Raw

from detection.covert_channel.icmp_detector import (
    ICMP_ECHO_REPLY,
    ICMP_ECHO_REQUEST,
    parse_icmp_echo,
)


def test_parse_icmp_echo_valid():
    """Check that a valid ICMP Echo Request packet is parsed correctly."""
    raw_data = b"abcdefghijklmnopqrstuvwabcdefghi"  # Windows ping default payload
    pkt = IP(src="172.20.0.3", dst="172.21.0.10") / ICMP(type=ICMP_ECHO_REQUEST, id=0x1234, seq=1) / Raw(load=raw_data)

    parsed = parse_icmp_echo(pkt)

    assert parsed is not None
    assert parsed.source_ip == "172.20.0.3"
    assert parsed.destination_ip == "172.21.0.10"
    assert parsed.icmp_type == 8
    assert parsed.icmp_id == 0x1234
    assert parsed.icmp_seq == 1
    assert parsed.payload == raw_data
    assert parsed.payload_size == 32


def test_parse_icmp_ignores_echo_reply():
    """Ensures only Echo Request messages are parsed, not Echo Replies."""
    pkt = IP(src="172.21.0.10", dst="172.20.0.3") / ICMP(type=ICMP_ECHO_REPLY, id=0x1234, seq=1)

    parsed = parse_icmp_echo(pkt)
    assert parsed is None


def test_parse_icmp_ignores_non_icmp_traffic():
    """Ensure that non-ICMP packets are ignored by the ICMP parser."""
    pkt = IP(src="172.20.0.3", dst="172.21.0.10") / TCP(dport=80)

    parsed = parse_icmp_echo(pkt)
    assert parsed is None


def test_parse_icmp_handles_empty_payload():
    """Test the parsing of an empty ICMP Echo Request (no payload)."""
    pkt = IP(src="172.20.0.3", dst="172.21.0.10") / ICMP(type=ICMP_ECHO_REQUEST)

    parsed = parse_icmp_echo(pkt)
    assert parsed is not None
    assert parsed.payload == b""
    assert parsed.payload_size == 0