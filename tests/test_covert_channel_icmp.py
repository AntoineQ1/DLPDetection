"""Comprehensive Automated Test Suite for ICMP Covert Channel Detection Engine.

This module provides exhaustive unit test scenarios validating packet ingestion,
structural payload heuristics, deep content inspection, and temporal sliding-window
rate tracking against ICMP-based exfiltration vectors.

THIS FILE IS AI GENERATED.
"""

from __future__ import annotations

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

# Standard mock IP address configuration constants
MOCK_SOURCE_HOST_IP: str = "172.20.0.3"
MOCK_DESTINATION_HOST_IP: str = "172.21.0.10"
MOCK_ALTERNATE_HOST_IP: str = "172.20.0.4"


# =====================================================================
# Synthetic Payload Fixture Helpers
# =====================================================================


def _build_linux_payload() -> bytes:
    """Synthesizes a standardized 56-byte Linux ping payload buffer.

    Prepends a 16-byte zeroed timestamp emulation header (`timeval` struct)
    to the canonical Linux ASCII pattern sequence.

    Returns:
        bytes: Raw byte buffer emulating authentic Linux ping payloads.
    """
    synthetic_timestamp_header_bytes: bytes = b"\x00" * 16
    return synthetic_timestamp_header_bytes + LINUX_PING_PATTERN


# =====================================================================
# Ingestion & Protocol Parsing Validation Suites
# =====================================================================


def test_parse_icmp_echo_valid() -> None:
    """Validates that a compliant ICMP Echo Request frame is extracted correctly."""
    # Prepare standard Windows baseline payload buffer
    emulated_payload_buffer: bytes = WINDOWS_PING_PAYLOAD

    # Synthesize multi-layer protocol frame (IP / ICMP Echo / Raw)
    synthesized_packet_frame = (
        IP(src=MOCK_SOURCE_HOST_IP, dst=MOCK_DESTINATION_HOST_IP)
        / ICMP(type=ICMP_ECHO_REQUEST, id=0x1234, seq=1)
        / Raw(load=emulated_payload_buffer)
    )

    # Ingest and parse packet telemetry model
    extracted_icmp_telemetry = parse_icmp_echo(synthesized_packet_frame)

    # Assert accurate field extraction and invariant properties
    assert extracted_icmp_telemetry is not None
    assert extracted_icmp_telemetry.source_ip == MOCK_SOURCE_HOST_IP
    assert extracted_icmp_telemetry.destination_ip == MOCK_DESTINATION_HOST_IP
    assert extracted_icmp_telemetry.icmp_type == 8
    assert extracted_icmp_telemetry.icmp_id == 0x1234
    assert extracted_icmp_telemetry.icmp_seq == 1
    assert extracted_icmp_telemetry.payload == emulated_payload_buffer
    assert extracted_icmp_telemetry.payload_size == 32


def test_parse_icmp_ignores_echo_reply() -> None:
    """Ensures parser filters out ICMP Echo Reply frames to prevent telemetry pollution."""
    synthesized_reply_packet = IP(
        src=MOCK_DESTINATION_HOST_IP, dst=MOCK_SOURCE_HOST_IP
    ) / ICMP(type=ICMP_ECHO_REPLY, id=0x1234, seq=1)

    extracted_telemetry = parse_icmp_echo(synthesized_reply_packet)
    assert extracted_telemetry is None


def test_parse_icmp_ignores_non_icmp_traffic() -> None:
    """Verifies that non-ICMP network traffic is systematically ignored by the parser."""
    synthesized_tcp_packet = IP(
        src=MOCK_SOURCE_HOST_IP, dst=MOCK_DESTINATION_HOST_IP
    ) / TCP(dport=80)

    extracted_telemetry = parse_icmp_echo(synthesized_tcp_packet)
    assert extracted_telemetry is None


def test_parse_icmp_handles_empty_payload() -> None:
    """Verifies telemetry extraction resilience when processing payload-less Echo Requests."""
    synthesized_empty_packet = IP(
        src=MOCK_SOURCE_HOST_IP, dst=MOCK_DESTINATION_HOST_IP
    ) / ICMP(type=ICMP_ECHO_REQUEST)

    extracted_telemetry = parse_icmp_echo(synthesized_empty_packet)

    assert extracted_telemetry is not None
    assert extracted_telemetry.payload == b""
    assert extracted_telemetry.payload_size == 0


# =====================================================================
# Benign Baseline & Whitelist Validation Suites
# =====================================================================


def test_benign_payload_validation() -> None:
    """Validates baseline pattern whitelist recognition against synthetic noise buffers."""
    assert is_known_benign_payload(WINDOWS_PING_PAYLOAD) is True
    assert is_known_benign_payload(_build_linux_payload()) is True
    assert is_known_benign_payload(b"X" * 32) is False
    assert is_known_benign_payload(b"X" * 56) is False


def test_structure_benign_traffic_yields_no_findings() -> None:
    """Ensures legitimate Linux and Windows ping flows produce zero anomaly findings."""
    # Synthesize authentic Linux telemetry model
    linux_frame = (
        IP(src=MOCK_SOURCE_HOST_IP, dst=MOCK_DESTINATION_HOST_IP)
        / ICMP(type=ICMP_ECHO_REQUEST)
        / Raw(load=_build_linux_payload())
    )
    linux_telemetry_model = parse_icmp_echo(linux_frame)
    assert linux_telemetry_model is not None
    assert check_structure(linux_telemetry_model) == []

    # Synthesize authentic Windows telemetry model
    windows_frame = (
        IP(src=MOCK_SOURCE_HOST_IP, dst=MOCK_DESTINATION_HOST_IP)
        / ICMP(type=ICMP_ECHO_REQUEST)
        / Raw(load=WINDOWS_PING_PAYLOAD)
    )
    windows_telemetry_model = parse_icmp_echo(windows_frame)
    assert windows_telemetry_model is not None
    assert check_structure(windows_telemetry_model) == []


# =====================================================================
# Structural Heuristic & Anomaly Detection Suites
# =====================================================================


def test_structure_oversized_payload() -> None:
    """Verifies detection of volumetric anomaly exceeding standard payload threshold (>64B)."""
    exfiltration_payload_buffer: bytes = b"CONFIDENTIAL_DATA_LEAK_" * 4
    synthesized_oversized_packet = (
        IP(src=MOCK_SOURCE_HOST_IP, dst=MOCK_DESTINATION_HOST_IP)
        / ICMP(type=ICMP_ECHO_REQUEST)
        / Raw(load=exfiltration_payload_buffer)
    )
    parsed_telemetry_model = parse_icmp_echo(synthesized_oversized_packet)

    assert parsed_telemetry_model is not None
    detected_structural_findings = check_structure(parsed_telemetry_model)

    assert len(detected_structural_findings) == 1
    assert detected_structural_findings[0].rule_id == "icmp_oversized_payload"
    assert detected_structural_findings[0].severity == Severity.HIGH


def test_structure_non_standard_size() -> None:
    """Verifies heuristic alerting on abnormal non-standard payload dimensions."""
    arbitrary_size_payload: bytes = b"exfiltrated_password"
    synthesized_abnormal_packet = (
        IP(src=MOCK_SOURCE_HOST_IP, dst=MOCK_DESTINATION_HOST_IP)
        / ICMP(type=ICMP_ECHO_REQUEST)
        / Raw(load=arbitrary_size_payload)
    )
    parsed_telemetry_model = parse_icmp_echo(synthesized_abnormal_packet)

    assert parsed_telemetry_model is not None
    detected_structural_findings = check_structure(parsed_telemetry_model)

    assert len(detected_structural_findings) == 1
    assert detected_structural_findings[0].rule_id == "icmp_non_standard_size"
    assert detected_structural_findings[0].severity == Severity.MEDIUM


def test_structure_evasion_chunking_with_forged_pattern() -> None:
    """Verifies identification of forged payloads disguised using canonical byte sizes."""
    crafted_evasion_payload: bytes = b"A" * 56
    synthesized_evasion_packet = (
        IP(src=MOCK_SOURCE_HOST_IP, dst=MOCK_DESTINATION_HOST_IP)
        / ICMP(type=ICMP_ECHO_REQUEST)
        / Raw(load=crafted_evasion_payload)
    )
    parsed_telemetry_model = parse_icmp_echo(synthesized_evasion_packet)

    assert parsed_telemetry_model is not None
    detected_structural_findings = check_structure(parsed_telemetry_model)

    assert len(detected_structural_findings) == 1
    assert detected_structural_findings[0].rule_id == "icmp_abnormal_pattern"
    assert detected_structural_findings[0].severity == Severity.MEDIUM


# =====================================================================
# Deep Packet Inspection & Content Heuristics Suites
# =====================================================================


def test_check_content_empty_or_whitespace_payload() -> None:
    """Verifies that purely whitespace or unpopulated buffers trigger zero signatures."""
    synthesized_whitespace_packet = (
        IP(src=MOCK_SOURCE_HOST_IP, dst=MOCK_DESTINATION_HOST_IP)
        / ICMP(type=ICMP_ECHO_REQUEST)
        / Raw(load=b"   \t\n  ")
    )
    parsed_telemetry_model = parse_icmp_echo(synthesized_whitespace_packet)
    assert parsed_telemetry_model is not None
    assert check_content(parsed_telemetry_model) == []


def test_check_content_detects_sensitive_data(monkeypatch: Any) -> None:
    """Verifies that embedded credential patterns trigger L7 deep content detection."""
    # Instantiate mocked signature match object
    mocked_signature_match = MagicMock()
    mocked_signature_match.rule_id = "fake_api_token"
    mocked_signature_match.detector = "regex"
    mocked_signature_match.severity = Severity.CRITICAL
    mocked_signature_match.matched = "ghp_1234567890abcdef"
    mocked_signature_match.source = "icmp_payload"
    mocked_signature_match.meta = {"entropy": 4.2}

    # Intercept scanning orchestrator to isolate payload inspection mechanics
    monkeypatch.setattr(
        "detection.covert_channel.icmp_detector.scan_all",
        lambda text, source: [mocked_signature_match] if "ghp_" in text else [],
    )

    # Synthesize payload with prepended binary encapsulation noise
    synthesized_token_payload = b"\x00\xff\xfe" + b"ghp_1234567890abcdef" + b"\x00"
    synthesized_packet = (
        IP(src=MOCK_SOURCE_HOST_IP, dst=MOCK_DESTINATION_HOST_IP)
        / ICMP(type=ICMP_ECHO_REQUEST)
        / Raw(load=synthesized_token_payload)
    )
    parsed_telemetry_model = parse_icmp_echo(synthesized_packet)
    assert parsed_telemetry_model is not None

    detected_content_findings = check_content(parsed_telemetry_model)
    assert len(detected_content_findings) == 1
    assert detected_content_findings[0].rule_id == "icmp_sensitive_data_fake_api_token"
    assert detected_content_findings[0].severity == Severity.CRITICAL
    assert detected_content_findings[0].details["matched"] == "ghp_1234567890abcdef"
    assert detected_content_findings[0].details["detector"] == "regex"


def test_analyze_icmp_message_aggregates_structure_and_content(
    monkeypatch: Any,
) -> None:
    """Verifies aggregation pipeline fuses both structural anomalies and content alerts."""
    mocked_signature_match = MagicMock()
    mocked_signature_match.rule_id = "credit_card"
    mocked_signature_match.detector = "luhn"
    mocked_signature_match.severity = Severity.HIGH
    mocked_signature_match.matched = "4532015112830366"
    mocked_signature_match.source = "icmp_payload"
    mocked_signature_match.meta = {}

    monkeypatch.setattr(
        "detection.covert_channel.icmp_detector.scan_all",
        lambda text, source: [mocked_signature_match],
    )

    # Build oversized payload (80 bytes) encapsulating sensitive payment card digits
    composite_leak_payload = b"4532015112830366" + b"A" * 64
    synthesized_composite_packet = (
        IP(src=MOCK_SOURCE_HOST_IP, dst=MOCK_DESTINATION_HOST_IP)
        / ICMP(type=ICMP_ECHO_REQUEST)
        / Raw(load=composite_leak_payload)
    )
    parsed_telemetry_model = parse_icmp_echo(synthesized_composite_packet)
    assert parsed_telemetry_model is not None

    aggregated_detection_findings = analyze_icmp_message(parsed_telemetry_model)
    triggered_rule_identifiers: list[str] = [
        finding.rule_id for finding in aggregated_detection_findings
    ]

    # Validate presence of both heterogeneous detection layers
    assert "icmp_oversized_payload" in triggered_rule_identifiers
    assert "icmp_sensitive_data_credit_card" in triggered_rule_identifiers


# =====================================================================
# Temporal Rate Limiting & Sliding Window Suites
# =====================================================================


def test_rate_tracker_normal_frequency() -> None:
    """Verifies that transmissions within established temporal thresholds trigger no alerts."""
    telemetry_rate_tracker = ICMPRateTracker(window_seconds=1.0, max_requests=4)
    target_source_host: str = MOCK_SOURCE_HOST_IP

    # Simulate sequential ping events distributed within permissible rate window
    assert (
        telemetry_rate_tracker.record_and_check(target_source_host, timestamp=100.0)
        == []
    )
    assert (
        telemetry_rate_tracker.record_and_check(target_source_host, timestamp=100.3)
        == []
    )
    assert (
        telemetry_rate_tracker.record_and_check(target_source_host, timestamp=100.6)
        == []
    )


def test_rate_tracker_exceeds_threshold() -> None:
    """Verifies high-frequency packet emission bursts accurately breach detection limits."""
    telemetry_rate_tracker = ICMPRateTracker(window_seconds=1.0, max_requests=4)
    target_source_host: str = MOCK_SOURCE_HOST_IP

    # Transmit 4 packets in 0.4 seconds (within configured limit)
    for sample_timestamp in [100.0, 100.1, 100.2, 100.3]:
        assert (
            telemetry_rate_tracker.record_and_check(
                target_source_host, timestamp=sample_timestamp
            )
            == []
        )

    # 5th transmission at t=100.4s exceeds rate envelope
    rate_limit_findings = telemetry_rate_tracker.record_and_check(
        target_source_host, timestamp=100.4
    )
    assert len(rate_limit_findings) == 1
    assert rate_limit_findings[0].rule_id == "icmp_high_frequency"
    assert rate_limit_findings[0].severity == "high"
    assert rate_limit_findings[0].details["count"] == 5


def test_rate_tracker_sliding_window_eviction() -> None:
    """Verifies time-decay sliding window successfully purges stale historical samples."""
    telemetry_rate_tracker = ICMPRateTracker(window_seconds=1.0, max_requests=4)
    target_source_host: str = MOCK_SOURCE_HOST_IP

    # Ingest 4 initial packets at baseline timestamp
    for sample_timestamp in [100.0, 100.1, 100.2, 100.3]:
        telemetry_rate_tracker.record_and_check(
            target_source_host, timestamp=sample_timestamp
        )

    # 5th packet arrives post-window interval (>1.0s); older entries are evicted
    eviction_findings = telemetry_rate_tracker.record_and_check(
        target_source_host, timestamp=101.5
    )
    assert eviction_findings == []


def test_rate_tracker_ip_isolation() -> None:
    """Verifies rate tracking isolation across distinct source IP originators."""
    telemetry_rate_tracker = ICMPRateTracker(window_seconds=1.0, max_requests=2)

    # Primary host transmits 2 packets
    telemetry_rate_tracker.record_and_check(MOCK_SOURCE_HOST_IP, timestamp=100.0)
    telemetry_rate_tracker.record_and_check(MOCK_SOURCE_HOST_IP, timestamp=100.1)

    # Secondary host transmits concurrently without inheriting primary host threshold
    isolated_host_findings = telemetry_rate_tracker.record_and_check(
        MOCK_ALTERNATE_HOST_IP, timestamp=100.1
    )
    assert isolated_host_findings == []


def test_analyze_icmp_message_triggers_rate_limit() -> None:
    """Verifies analyze_icmp_message integrates live tracking into evaluation pipeline."""
    telemetry_rate_tracker = ICMPRateTracker(window_seconds=1.0, max_requests=1)
    synthesized_echo_frame = IP(
        src=MOCK_SOURCE_HOST_IP, dst=MOCK_DESTINATION_HOST_IP
    ) / ICMP(type=8)
    parsed_telemetry_model = parse_icmp_echo(synthesized_echo_frame)
    assert parsed_telemetry_model is not None

    # First transmission: evaluates structural anomalies only
    initial_findings = analyze_icmp_message(
        parsed_telemetry_model,
        rate_tracker=telemetry_rate_tracker,
        timestamp=10.0,
    )
    assert not any(
        finding.rule_id == "icmp_high_frequency" for finding in initial_findings
    )

    # Subsequent transmission triggers rate limit finding
    subsequent_findings = analyze_icmp_message(
        parsed_telemetry_model,
        rate_tracker=telemetry_rate_tracker,
        timestamp=10.1,
    )
    assert any(
        finding.rule_id == "icmp_high_frequency" for finding in subsequent_findings
    )
