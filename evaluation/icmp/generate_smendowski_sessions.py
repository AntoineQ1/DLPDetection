"""Create offline base64-over-ICMP exfiltration sessions with Smendowski's tool.

Uses the vendored `external_icmp.py` (a copy of Smendowski et al.'s `icmp.py`)
packet builder. Unlike icmptunnel's raw-binary payloads, this tool base64-encodes
each file chunk before framing, which is what exercises the detector's content /
entropy path. No packets are sent: `create_icmp_buffer` returns scapy packets
that are written straight to a PCAP.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import random
import sys
import tempfile
from pathlib import Path

from scapy.layers.inet import ICMP
from scapy.utils import wrpcap

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import external_icmp  # noqa: E402  vendored Smendowski packet builder

TOOL_REPO = "https://github.com/Smendowski/hidden-communication-using-covert-channels"
DESTINATION_IP = "198.51.100.10"
# File sizes are drawn at random from this range (seeded). Every size stays below
# the tool's 8 KB minimum read, so a file becomes one base64 payload: small saved
# payloads that still exceed the 64-byte structure threshold and the 16-char
# entropy-token minimum.
SIZE_RANGE = (200, 3000)
MANIFEST_FIELDS = (
    "run_id", "source_ip", "destination_ip", "input_sha256", "input_size",
    "packet_count", "tool_repo", "tool_commit", "packet_builder",
)


def generate(count: int, output: Path, manifest_path: Path) -> None:
    if count < 1:
        raise ValueError("count must be positive")
    # The tool is vendored as a single file; its SHA-256 pins the exact version.
    tool_sha = hashlib.sha256((ROOT / "external_icmp.py").read_bytes()).hexdigest()
    content_rng = random.Random(20261017)
    packets = []
    manifest = []
    with tempfile.TemporaryDirectory(prefix="dlp-smendowski-") as temp_dir:
        for index in range(count):
            content = content_rng.randbytes(content_rng.randint(*SIZE_RANGE))
            source_ip = f"198.19.{1 + index // 254}.{index % 254 + 1}"
            filename = f"secret-{index + 1:04d}.bin"
            file_path = Path(temp_dir) / filename
            file_path.write_bytes(content)
            # The tool reads chunk boundaries from the global RNG; seed it so the
            # fragmentation is reproducible even for files above the read size.
            random.seed(index + 1)
            raw_chunks = external_icmp.read_and_fragment_file(str(file_path))
            encoded = external_icmp.get_base64_encoded_file_chunks(raw_chunks)
            identifier = external_icmp.get_base64_encoded_file_identifier(filename, source_ip)
            payloads = external_icmp.create_icmp_payload(encoded, identifier)
            run_packets = list(external_icmp.create_icmp_buffer(payloads, source_ip, DESTINATION_IP))
            for sequence, packet in enumerate(run_packets):
                if packet[ICMP].type != 8:
                    raise ValueError(f"smendowski packet is not an Echo Request in run {index}")
                packet.time = float(index * 120 + sequence)
                packets.append(packet)
            manifest.append({
                "run_id": f"smendowski-run-{index + 1:04d}",
                "source_ip": source_ip, "destination_ip": DESTINATION_IP,
                "input_sha256": hashlib.sha256(content).hexdigest(),
                "input_size": len(content), "packet_count": len(run_packets),
                "tool_repo": TOOL_REPO, "tool_commit": f"vendored-sha256:{tool_sha}",
                "packet_builder": "external_icmp.py:create_icmp_payload",
            })
    output.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output), packets)
    with manifest_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=MANIFEST_FIELDS)
        writer.writeheader()
        writer.writerows(manifest)
    print(f"Generated {len(manifest)} smendowski sessions, {len(packets)} packets")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=50)
    parser.add_argument("--output", type=Path, default=ROOT / "smendowski_sessions.pcap")
    parser.add_argument("--manifest", type=Path, default=ROOT / "smendowski_manifest.csv")
    args = parser.parse_args()
    generate(args.count, args.output, args.manifest)


if __name__ == "__main__":
    main()
