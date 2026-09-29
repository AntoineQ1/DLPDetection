"""Unit tests for the ICMP covert channel detection engine."""

from scapy.layers.inet import ICMP, IP, TCP
from scapy.packet import Raw

from detection.covert_channel.icmp_detector import (
    ICMP_ECHO_REPLY,
    ICMP_ECHO_REQUEST,
    LINUX_PING_PATTERN,
    WINDOWS_PING_PAYLOAD,
    check_structure,
    is_known_benign_payload,
    parse_icmp_echo,
)


def _build_linux_payload() -> bytes:
    """Generate a 56-byte Linux ping payload with a dummy 16-byte timeval prefix."""
    dummy_timeval = b"\x00" * 16
    return dummy_timeval + LINUX_PING_PATTERN


def test_parse_icmp_echo_valid():
    """Check that a valid ICMP Echo Request packet is parsed correctly."""
    raw_data = WINDOWS_PING_PAYLOAD
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


def test_benign_payload_validation():
    """Verify that legitimate Windows and Linux payloads pass validation."""
    assert is_known_benign_payload(WINDOWS_PING_PAYLOAD) is True
    assert is_known_benign_payload(_build_linux_payload()) is True
    assert is_known_benign_payload(b"X" * 32) is False
    assert is_known_benign_payload(b"X" * 56) is False


def test_structure_benign_traffic_yields_no_findings():
    """Verify that standard Linux and Windows pings raise zero findings."""
    pkt_linux = IP(src="172.20.0.3", dst="172.21.0.10") / ICMP(type=ICMP_ECHO_REQUEST) / Raw(load=_build_linux_payload())
    msg_linux = parse_icmp_echo(pkt_linux)
    assert msg_linux is not None
    assert check_structure(msg_linux) == []

    pkt_win = IP(src="172.20.0.3", dst="172.21.0.10") / ICMP(type=ICMP_ECHO_REQUEST) / Raw(load=WINDOWS_PING_PAYLOAD)
    msg_win = parse_icmp_echo(pkt_win)
    assert msg_win is not None
    assert check_structure(msg_win) == []


def test_structure_oversized_payload():
    """Verify detection of bulk payload exfiltration (> 64 bytes)."""
    bulk_data = b"CONFIDENTIAL_DATA_LEAK_" * 4
    pkt = IP(src="172.20.0.3", dst="172.21.0.10") / ICMP(type=ICMP_ECHO_REQUEST) / Raw(load=bulk_data)
    msg = parse_icmp_echo(pkt)

    assert msg is not None
    findings = check_structure(msg)
    assert len(findings) == 1
    assert findings[0].rule_id == "icmp_oversized_payload"
    assert findings[0].severity == "HIGH"


def test_structure_non_standard_size():
    """Verify detection of non-standard payload lengths (e.g., 20 bytes)."""
    short_data = b"exfiltrated_password"
    pkt = IP(src="172.20.0.3", dst="172.21.0.10") / ICMP(type=ICMP_ECHO_REQUEST) / Raw(load=short_data)
    msg = parse_icmp_echo(pkt)

    assert msg is not None
    findings = check_structure(msg)
    assert len(findings) == 1
    assert findings[0].rule_id == "icmp_non_standard_size"
    assert findings[0].severity == "MEDIUM"


def test_structure_evasion_chunking_with_forged_pattern():
    """Verify detection when payload size matches 56 bytes but content is forged."""
    evasion_data = b"A" * 56
    pkt = IP(src="172.20.0.3", dst="172.21.0.10") / ICMP(type=ICMP_ECHO_REQUEST) / Raw(load=evasion_data)
    msg = parse_icmp_echo(pkt)

    assert msg is not None
    findings = check_structure(msg)
    assert len(findings) == 1
    assert findings[0].rule_id == "icmp_abnormal_pattern"
    assert findings[0].severity == "MEDIUM"