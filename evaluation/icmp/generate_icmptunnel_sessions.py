"""Create offline transfer sessions using icmptunnel's original C packet builder.

Requires a separate checkout of https://github.com/DhavalKapil/icmptunnel.
The adapter intercepts sendto, so no packets are sent and no privileges are needed.

Sampling is stratified random with a fixed seed: each run is assigned a profile
from a shuffled, balanced pool (so every detection path is represented), and the
per-run size, packet count, send cadence, and secret token are drawn randomly
from defined ranges/sets. Every packet is still built by the real icmptunnel
packet builder -- randomness only chooses the input bytes and timing.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import random
import subprocess
import tempfile
from pathlib import Path

from scapy.layers.inet import ICMP, IP, UDP
from scapy.packet import Raw
from scapy.utils import wrpcap

ROOT = Path(__file__).resolve().parent
TOOL_REPO = "https://github.com/DhavalKapil/icmptunnel"
CHUNK_SIZE = 900  # Inner IPv4 + UDP + data remain below icmptunnel's 1472-byte MTU.

# Each run is built by the real icmptunnel packet builder; the profile only sets
# which input/cadence distribution the run is drawn from, so the sample covers
# every detection path without any hand-built packets:
#   oversized -> large random file                -> icmp_oversized_payload (structure)
#   tiny      -> small file, random size          -> icmp_non_standard_size (structure)
#   burst     -> random >4-chunk file, sub-second -> icmp_high_frequency (rate)
#   secret    -> cleartext card + random token    -> icmp_sensitive_data_* (content)
SEED = 20261017
PROFILE_WEIGHTS = {"oversized": 0.4, "tiny": 0.2, "burst": 0.2, "secret": 0.2}
OVERSIZED_SIZE_RANGE = (200, 4000)       # random file bytes -> random chunk count
# Echo payload = 28 (inner IPv4+UDP) + data; these keep it <= 64 and not 32/56.
TINY_DATA_SIZES = (8, 12, 16, 20, 24)    # -> payload 36, 40, 44, 48, 52
BURST_CHUNK_RANGE = (5, 9)               # aleatory packet count, always > rate threshold (4)
BURST_INTERVAL_RANGE = (0.05, 0.20)      # 4 * interval < 1 s, so > 4 land in one window
# Dummy, non-live credentials: standard public test values, never real secrets.
SECRET_CARD = "4111111111111111"         # Luhn-valid Visa test number
SECRET_TOKENS = (                        # one is chosen at random per secret run
    ("AWS", "AKIAIOSFODNN7EXAMPLE"),
    ("GITHUB", "ghp_0123456789abcdefABCDEF0123456789wxyz"),
    ("STRIPE", "sk_test_0123456789abcdefABCDEFgh"),
    ("GOOGLE", "AIzaSyA1234567890abcdefghijklmnopqrstuv"),
)
MANIFEST_FIELDS = (
    "run_id", "source_ip", "destination_ip", "profile", "input_sha256",
    "input_size", "packet_count", "tool_repo", "tool_commit", "packet_builder",
)


def profile_plan(count: int, rng: random.Random) -> list[str]:
    """A shuffled, balanced pool of profiles (stratified random allocation)."""
    plan: list[str] = []
    for profile, weight in PROFILE_WEIGHTS.items():
        plan.extend([profile] * round(count * weight))
    # Correct any rounding drift against the requested count.
    while len(plan) < count:
        plan.append("oversized")
    del plan[count:]
    rng.shuffle(plan)
    return plan


def build_input(profile: str, index: int, rng: random.Random) -> tuple[bytes, float]:
    """Draw (file bytes, inter-packet interval) for a run from its profile."""
    if profile == "tiny":
        return rng.randbytes(rng.choice(TINY_DATA_SIZES)), 1.0
    if profile == "burst":
        chunks = rng.randint(*BURST_CHUNK_RANGE)
        size = (chunks - 1) * CHUNK_SIZE + rng.randint(1, CHUNK_SIZE)
        return rng.randbytes(size), round(rng.uniform(*BURST_INTERVAL_RANGE), 3)
    if profile == "secret":
        tag, token = rng.choice(SECRET_TOKENS)
        return f"PAN:{SECRET_CARD};{tag}:{token};run:{index:04d}".encode("ascii"), 1.0
    return rng.randbytes(rng.randint(*OVERSIZED_SIZE_RANGE)), 1.0


def compile_emitter(tool_dir: Path, destination: Path) -> None:
    if not (tool_dir / "icmp.c").is_file() or not (tool_dir / "icmp.h").is_file():
        raise ValueError(f"icmptunnel source not found in {tool_dir}")
    subprocess.run(
        ["gcc", "-std=c11", "-O2", "-D_DEFAULT_SOURCE", "-I", str(tool_dir),
         str(tool_dir / "icmp.c"), str(ROOT / "emit_icmptunnel_packet.c"),
         "-Wl,--wrap=sendto", "-o", str(destination)],
        check=True,
    )


def generate(tool_dir: Path, count: int, output: Path, manifest_path: Path) -> None:
    if count < 1:
        raise ValueError("count must be positive")
    commit = subprocess.check_output(
        ["git", "-C", str(tool_dir), "rev-parse", "HEAD"], text=True
    ).strip()
    rng = random.Random(SEED)
    plan = profile_plan(count, rng)
    packets = []
    manifest = []
    with tempfile.TemporaryDirectory(prefix="dlp-icmptunnel-") as temp_dir:
        emitter = Path(temp_dir) / "emit_packet"
        compile_emitter(tool_dir, emitter)
        for index in range(count):
            profile = plan[index]
            source_ip = f"198.18.{1 + index // 254}.{index % 254 + 1}"
            destination_ip = "198.51.100.10"
            content, interval = build_input(profile, index, rng)
            emitted = 0
            for offset in range(0, len(content), CHUNK_SIZE):
                chunk = content[offset:offset + CHUNK_SIZE]
                # The original tool reads this IP datagram from tun0, then places
                # its bytes in the ICMP Echo payload.
                inner = bytes(
                    IP(src=source_ip, dst="203.0.113.7")
                    / UDP(sport=45000 + index, dport=9000)
                    / Raw(load=chunk)
                )
                built = subprocess.run(
                    [str(emitter), source_ip, destination_ip, str(index * 100 + emitted)],
                    input=inner, capture_output=True, check=True,
                ).stdout
                outer = IP(built)
                if outer[ICMP].type != 8 or bytes(outer[ICMP].payload) != inner:
                    raise ValueError(f"icmptunnel packet mismatch in run {index}")
                # The live raw-socket path lets the kernel fill the outer IPv4
                # checksum; do the same when saving packets offline.
                del outer.chksum
                outer = IP(bytes(outer))
                # The burst profile keeps chunks inside a one-second window.
                outer.time = float(index * 120) + emitted * interval
                packets.append(outer)
                emitted += 1
            manifest.append({
                "run_id": f"icmptunnel-run-{index + 1:04d}",
                "source_ip": source_ip, "destination_ip": destination_ip,
                "profile": profile,
                "input_sha256": hashlib.sha256(content).hexdigest(),
                "input_size": len(content), "packet_count": emitted,
                "tool_repo": TOOL_REPO, "tool_commit": commit,
                "packet_builder": "icmp.c:send_icmp_packet",
            })
    output.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output), packets)
    with manifest_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=MANIFEST_FIELDS)
        writer.writeheader()
        writer.writerows(manifest)
    print(f"Generated {len(manifest)} icmptunnel sessions, {len(packets)} packets")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tool-dir", type=Path, required=True)
    parser.add_argument("--count", type=int, default=50)
    parser.add_argument("--output", type=Path, default=ROOT / "icmptunnel_sessions.pcap")
    parser.add_argument("--manifest", type=Path, default=ROOT / "icmptunnel_manifest.csv")
    args = parser.parse_args()
    generate(args.tool_dir, args.count, args.output, args.manifest)


if __name__ == "__main__":
    main()
