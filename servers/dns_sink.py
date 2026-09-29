"""DNS sink for the covert-channel lab (Workstream C fixture).

Runs on the *attacker* container. Listens on UDP/53, parses incoming queries
produced by attacks/dns_exfiltrate.py, strips the base domain, reassembles the
chunked payload, and answers with a benign A record so the client does not hang.

It exists only to confirm end-to-end that exfiltration *would* have succeeded if
the gateway had not blocked it — i.e. the ground truth for the detection metrics.
Standard library only.
"""

from __future__ import annotations

import argparse
import base64
import socket
import struct
import sys

BIND_ADDR = "0.0.0.0"
BIND_PORT = 53


def parse_qname(data: bytes, offset: int) -> tuple[str, int]:
    """Read a DNS QNAME (no compression handling needed for queries)."""
    labels = []
    while True:
        length = data[offset]
        offset += 1
        if length == 0:
            break
        labels.append(data[offset : offset + length].decode("latin-1"))
        offset += length
    return ".".join(labels), offset


def try_decode(label: str, mode_hint: str) -> str:
    """Best-effort reverse of the generator's encodings, for display."""
    try:
        if mode_hint == "hex":
            return bytes.fromhex(label).decode("utf-8", "replace")
        if mode_hint == "base32":
            pad = "=" * (-len(label) % 8)
            return base64.b32decode(label.upper() + pad).decode("utf-8", "replace")
        if mode_hint == "base64":
            pad = "=" * (-len(label) % 4)
            return base64.urlsafe_b64decode(label + pad).decode("utf-8", "replace")
    except Exception:
        return ""
    return label  # naive


def build_answer(query: bytes, ip: str = "127.0.0.1") -> bytes:
    """Echo the question back with one A record pointing at `ip`."""
    txid = query[:2]
    flags = struct.pack(">H", 0x8180)  # response, RD, RA
    counts = struct.pack(">HHHH", 1, 1, 0, 0)
    question = query[12:]  # original question section
    answer = (
        b"\xc0\x0c"  # pointer to the name at offset 12
        + struct.pack(">HHIH", 1, 1, 60, 4)  # TYPE A, CLASS IN, TTL, RDLENGTH
        + socket.inet_aton(ip)
    )
    return txid + flags + counts + question + answer


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--domain", default="exfil.attacker.example")
    parser.add_argument(
        "--decode",
        default="base32",
        choices=["naive", "hex", "base32", "base64"],
        help="how to interpret received labels for the reassembly preview",
    )
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((BIND_ADDR, BIND_PORT))
    print(f"[dns-sink] listening on {BIND_ADDR}:{BIND_PORT}", flush=True)

    chunks: dict[int, str] = {}  # idx -> raw encoded label
    base = args.domain
    while True:
        data, addr = sock.recvfrom(512)
        try:
            qname, _ = parse_qname(data, 12)
        except (IndexError, UnicodeError):
            continue

        # Strip the base domain to recover "c<idx>.<encoded-chunk>".
        stem = qname[: -(len(base) + 1)] if qname.endswith(base) else qname
        parts = stem.split(".")
        idx_label, payload = (parts[0], parts[1]) if len(parts) >= 2 else ("c?", parts[0])

        print(f"[dns-sink] {addr[0]} q={qname}", flush=True)

        if idx_label.startswith("c") and idx_label[1:].isdigit():
            # Store the still-encoded label; decode only the full concatenation,
            # since a single chunk is not on an encoding byte boundary.
            chunks[int(idx_label[1:])] = payload
            encoded = "".join(chunks[i] for i in sorted(chunks))
            reassembled = try_decode(encoded, args.decode)
            print(f"[dns-sink] reassembled so far: {reassembled!r}", flush=True)

        try:
            sock.sendto(build_answer(data), addr)
        except OSError:
            pass


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[dns-sink] stopped", flush=True)
