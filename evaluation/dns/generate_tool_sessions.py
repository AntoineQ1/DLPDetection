"""Generate 100 independent DNS-tunnel sessions with zrckr/dns-tunnel.

Requires a separate clone of https://github.com/zrckr/dns-tunnel and that
project's Python dependencies. Calls its Client.dns_ask packet builder; no
network traffic is sent. The external source is not copied into this repo.
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import random
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

from scapy.layers.dns import DNS
from scapy.layers.inet import IP, UDP
from scapy.utils import wrpcap

HERE = Path(__file__).resolve().parent


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tool-dir", type=Path, required=True)
    parser.add_argument("--count", type=int, default=100)
    args = parser.parse_args()
    if args.count < 1 or args.count > 254:
        parser.error("count must be between 1 and 254")
    tool_dir = args.tool_dir.resolve()
    if not (tool_dir / "client.py").is_file():
        parser.error("--tool-dir must contain the external tool's client.py")
    sys.path.insert(0, str(tool_dir))
    from client import Client  # type: ignore[import-not-found]

    commit = subprocess.check_output(["git", "-C", str(tool_dir), "rev-parse", "HEAD"], text=True).strip()
    rng = random.Random(20261017)
    random.seed(20261017)  # dnslib chooses DNS transaction IDs from global random
    packets = []
    manifest = []
    text_sizes = (8, 12, 16, 24, 48)
    file_sizes = (32, 64, 128, 256, 512)
    with tempfile.TemporaryDirectory(prefix="dlp-dns-tool-") as temp_dir:
        for index in range(args.count):
            mode = "text" if index % 2 == 0 else "file"
            source_ip = f"198.18.0.{index + 1}"
            domain = f"run{index:03d}.attack.example"
            qtype = "A" if index % 4 < 2 else "TXT"
            options = SimpleNamespace(
                timeout=1, domain=domain, qtype=qtype, text=False, rand=False,
                file=None, aes_key=None, scramble=None, force_tcp=False,
            )
            if mode == "text":
                size = text_sizes[(index // 2) % len(text_sizes)]
                alphabet = "abcdef0123456789"
                content = "".join(rng.choice(alphabet) for _ in range(size)).encode("ascii")
            else:
                size = file_sizes[(index // 2) % len(file_sizes)]
                file_path = Path(temp_dir) / f"sample_{index:03d}.bin"
                file_path.write_bytes(rng.randbytes(size))
                options.file = str(file_path)
                content = Client(("127.0.0.1", 53), options).read_file()
            client = Client(("127.0.0.1", 53), options)
            wire_queries = client.dns_ask(content, base64.urlsafe_b64encode)
            if not wire_queries:
                raise RuntimeError(f"tool emitted no DNS queries for run {index}")
            for sequence, wire in enumerate(wire_queries):
                packet = (
                    IP(src=source_ip, dst="198.51.100.53")
                    / UDP(sport=40000 + index, dport=53)
                    / DNS(wire)
                )
                packet.time = 1_700_000_000 + index * 120 + sequence * 0.2
                packets.append(packet)
            manifest.append({
                "run_id": f"tool-run-{index + 1:04d}", "source_ip": source_ip,
                "domain": domain, "mode": mode, "qtype": qtype,
                "input_bytes": len(content),
                "input_sha256": hashlib.sha256(content).hexdigest(),
                "query_count": len(wire_queries), "tool_commit": commit,
            })
    capture_path = HERE / "tool_sessions.pcap"
    wrpcap(str(capture_path), packets)
    with (HERE / "tool_sessions_manifest.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(manifest[0]))
        writer.writeheader()
        writer.writerows(manifest)
    print(f"{len(manifest)} independent runs, {len(packets)} DNS queries")
    print(f"PCAP SHA-256: {hashlib.sha256(capture_path.read_bytes()).hexdigest()}")
    print(f"Tool commit: {commit}")


if __name__ == "__main__":
    main()
