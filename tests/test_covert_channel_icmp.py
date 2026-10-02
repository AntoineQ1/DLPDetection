"""Unit tests for the ICMP covert channel detection engine."""

from typing import Any
from unittest.mock import MagicMock

from scapy.layers.inet import ICMP, IP, TCP
from scapy.packet import Raw

from detection.common.types import Severity
from detection.covert_channel.icmp_detector import (
    ICMP_ECHO_REPLY,
    ICMP_ECHO_REQUEST,
    LINUX_PING_PATTERN,
    WINDOWS_PING_PAYLOAD,
    ICMPRateTracker,
    analyze_icmp_message,
    check_content,
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
    pkt = (
        IP(src="172.20.0.3", dst="172.21.0.10")
        / ICMP(type=ICMP_ECHO_REQUEST, id=0x1234, seq=1)
        / Raw(load=raw_data)
    )

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
    pkt = IP(src="172.21.0.10", dst="172.20.0.3") / ICMP(
        type=ICMP_ECHO_REPLY, id=0x1234, seq=1
    )

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
    pkt_linux = (
        IP(src="172.20.0.3", dst="172.21.0.10")
        / ICMP(type=ICMP_ECHO_REQUEST)
        / Raw(load=_build_linux_payload())
    )
    msg_linux = parse_icmp_echo(pkt_linux)
    assert msg_linux is not None
    assert check_structure(msg_linux) == []

    pkt_win = (
        IP(src="172.20.0.3", dst="172.21.0.10")
        / ICMP(type=ICMP_ECHO_REQUEST)
        / Raw(load=WINDOWS_PING_PAYLOAD)
    )
    msg_win = parse_icmp_echo(pkt_win)
    assert msg_win is not None
    assert check_structure(msg_win) == []


def test_structure_oversized_payload():
    """Verify detection of bulk payload exfiltration (> 64 bytes)."""
    bulk_data = b"CONFIDENTIAL_DATA_LEAK_" * 4
    pkt = (
        IP(src="172.20.0.3", dst="172.21.0.10")
        / ICMP(type=ICMP_ECHO_REQUEST)
        / Raw(load=bulk_data)
    )
    msg = parse_icmp_echo(pkt)

    assert msg is not None
    findings = check_structure(msg)
    assert len(findings) == 1
    assert findings[0].rule_id == "icmp_oversized_payload"
    assert findings[0].severity == Severity.HIGH


def test_structure_non_standard_size():
    """Verify detection of non-standard payload lengths (e.g., 20 bytes)."""
    short_data = b"exfiltrated_password"
    pkt = (
        IP(src="172.20.0.3", dst="172.21.0.10")
        / ICMP(type=ICMP_ECHO_REQUEST)
        / Raw(load=short_data)
    )
    msg = parse_icmp_echo(pkt)

    assert msg is not None
    findings = check_structure(msg)
    assert len(findings) == 1
    assert findings[0].rule_id == "icmp_non_standard_size"
    assert findings[0].severity == Severity.MEDIUM


def test_structure_evasion_chunking_with_forged_pattern():
    """Verify detection when payload size matches 56 bytes but content is forged."""
    evasion_data = b"A" * 56
    pkt = (
        IP(src="172.20.0.3", dst="172.21.0.10")
        / ICMP(type=ICMP_ECHO_REQUEST)
        / Raw(load=evasion_data)
    )
    msg = parse_icmp_echo(pkt)

    assert msg is not None
    findings = check_structure(msg)
    assert len(findings) == 1
    assert findings[0].rule_id == "icmp_abnormal_pattern"
    assert findings[0].severity == Severity.MEDIUM

def test_check_content_empty_or_whitespace_payload():
    """Verify that an empty or whitespace-only payload produces no findings."""
    pkt = IP(src="172.20.0.3", dst="172.21.0.10") / ICMP(type=ICMP_ECHO_REQUEST) / Raw(load=b"   \t\n  ")
    msg = parse_icmp_echo(pkt)
    assert msg is not None
    assert check_content(msg) == []


def test_check_content_detects_sensitive_data(monkeypatch: Any):
    """Verify that sensitive substrings in ICMP payload trigger L7 scan_all detection."""
    mock_hit = MagicMock()
    mock_hit.rule_id = "fake_api_token"
    mock_hit.detector = "regex"
    mock_hit.severity = Severity.CRITICAL
    mock_hit.matched = "ghp_1234567890abcdef"
    mock_hit.source = "icmp_payload"
    mock_hit.meta = {"entropy": 4.2}

    # Intercept scan_all to test icmp_detector in strict isolation
    monkeypatch.setattr(
        "detection.covert_channel.icmp_detector.scan_all",
        lambda text, source: [mock_hit] if "ghp_" in text else [],
    )

    # Payload with binary noise prepended before the token
    noisy_payload = b"\x00\xff\xfe" + b"ghp_1234567890abcdef" + b"\x00"
    pkt = IP(src="172.20.0.3", dst="172.21.0.10") / ICMP(type=ICMP_ECHO_REQUEST) / Raw(load=noisy_payload)
    msg = parse_icmp_echo(pkt)
    assert msg is not None

    findings = check_content(msg)
    assert len(findings) == 1
    assert findings[0].rule_id == "icmp_sensitive_data_fake_api_token"
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].details["matched"] == "ghp_1234567890abcdef"
    assert findings[0].details["detector"] == "regex"


def test_analyze_icmp_message_aggregates_structure_and_content(monkeypatch: Any):
    """Verify that analyze_icmp_message combines both structural and content findings."""
    mock_hit = MagicMock()
    mock_hit.rule_id = "credit_card"
    mock_hit.detector = "luhn"
    mock_hit.severity = Severity.HIGH
    mock_hit.matched = "4532015112830366"
    mock_hit.source = "icmp_payload"
    mock_hit.meta = {}

    monkeypatch.setattr(
        "detection.covert_channel.icmp_detector.scan_all",
        lambda text, source: [mock_hit],
    )

    # Oversized payload (80 bytes) containing a sensitive number
    leak_data = b"4532015112830366" + b"A" * 64
    pkt = IP(src="172.20.0.3", dst="172.21.0.10") / ICMP(type=ICMP_ECHO_REQUEST) / Raw(load=leak_data)
    msg = parse_icmp_echo(pkt)
    assert msg is not None

    all_findings = analyze_icmp_message(msg)
    rule_ids = [f.rule_id for f in all_findings]

    # Must contain both the structural finding and the content finding
    assert "icmp_oversized_payload" in rule_ids
    assert "icmp_sensitive_data_credit_card" in rule_ids

def test_rate_tracker_normal_frequency():
    """Verify that pings within the allowed rate (e.g. 1 per second) trigger no findings."""
    tracker = ICMPRateTracker(window_seconds=1.0, max_requests=4)
    source_ip = "172.20.0.3"

    # Simulate 3 pings spaced by 0.3s
    assert tracker.record_and_check(source_ip, timestamp=100.0) == []
    assert tracker.record_and_check(source_ip, timestamp=100.3) == []
    assert tracker.record_and_check(source_ip, timestamp=100.6) == []


def test_rate_tracker_exceeds_threshold():
    """Verify that a burst exceeding the threshold generates an alert."""
    tracker = ICMPRateTracker(window_seconds=1.0, max_requests=4)
    source_ip = "172.20.0.3"

    # 4 packets in 0.4 seconds (within threshold)
    for t in [100.0, 100.1, 100.2, 100.3]:
        assert tracker.record_and_check(source_ip, timestamp=t) == []

    # 5th packet at 100.4s triggers the alert
    findings = tracker.record_and_check(source_ip, timestamp=100.4)
    assert len(findings) == 1
    assert findings[0].rule_id == "icmp_high_frequency"
    assert findings[0].severity == "high"
    assert findings[0].details["count"] == 5


def test_rate_tracker_sliding_window_eviction():
    """Verify that older packets slide out of the window and do not cause false positives."""
    tracker = ICMPRateTracker(window_seconds=1.0, max_requests=4)
    source_ip = "172.20.0.3"

    # 4 packets at t=100.x
    for t in [100.0, 100.1, 100.2, 100.3]:
        tracker.record_and_check(source_ip, timestamp=t)

    # 5th packet arrives at t=101.5 (more than 1s later -> older entries evicted)
    findings = tracker.record_and_check(source_ip, timestamp=101.5)
    assert findings == []


def test_rate_tracker_ip_isolation():
    """Verify that rates are tracked independently per source IP."""
    tracker = ICMPRateTracker(window_seconds=1.0, max_requests=2)

    # IP 1 sends 2 packets
    tracker.record_and_check("172.20.0.3", timestamp=100.0)
    tracker.record_and_check("172.20.0.3", timestamp=100.1)

    # IP 2 sends 1 packet at same time: must not trigger
    findings = tracker.record_and_check("172.20.0.4", timestamp=100.1)
    assert findings == []


def test_analyze_icmp_message_triggers_rate_limit():
    """Verify analyze_icmp_message invokes the rate tracker when provided."""
    tracker = ICMPRateTracker(window_seconds=1.0, max_requests=1)
    pkt = IP(src="172.20.0.3", dst="172.21.0.10") / ICMP(type=8)
    msg = parse_icmp_echo(pkt)
    assert msg is not None

    # First packet: only structural findings (empty payload deviates from 32/56)
    f1 = analyze_icmp_message(msg, rate_tracker=tracker, timestamp=10.0)
    assert not any(f.rule_id == "icmp_high_frequency" for f in f1)

    # Second packet immediately after: triggers rate limit
    f2 = analyze_icmp_message(msg, rate_tracker=tracker, timestamp=10.1)
    assert any(f.rule_id == "icmp_high_frequency" for f in f2)