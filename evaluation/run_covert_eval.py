"""Reproduce the offline DNS and ICMP session evaluation.

DNS packets come from 100 independent runs of zrckr/dns-tunnel's packet
builder. ICMP packets come from 100 offline runs of icmptunnel's original C
packet builder. No packets are transmitted by this script.
"""

from __future__ import annotations

import argparse
import csv
import json
import random
import time
from collections import Counter
from pathlib import Path

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, UDP
from scapy.packet import Raw
from scapy.utils import PcapReader

from detection.covert_channel.dns_detector import DnsTunnelDetector, parse_dns_query
from detection.covert_channel.icmp_detector import (
    ICMPRateTracker,
    LINUX_PING_PATTERN,
    WINDOWS_PING_PAYLOAD,
    analyze_icmp_message,
    parse_icmp_echo,
)

ROOT = Path(__file__).resolve().parent
FIELDS = [
    "id", "session_id", "label", "source", "scenario", "timestamp", "source_ip",
    "destination_ip", "qtype", "qtype_code", "payload", "payload_hex", "detected",
    "outcome", "rule_ids", "detector_message",
]
SESSION_FIELDS = [
    "session_id", "label", "source", "scenario", "source_ip", "destination_ip",
    "first_timestamp", "last_timestamp", "packet_count", "alerted_packet_count",
    "detected", "outcome", "first_alert_packet_id", "rule_ids",
    "packet_ids", "payload_preview", "detector_message",
]


def result(label: str, detected: bool) -> str:
    return ("TP" if detected else "FN") if label == "malicious" else ("FP" if detected else "TN")


def write_rows(path: Path, rows: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def write_session_rows(path: Path, rows: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=SESSION_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def build_sessions(protocol: str, packets: list[dict], idle_gap_seconds: float = 60.0) -> list[dict]:
    """Group ordered packets into source/destination flows separated by idle gaps."""
    active: dict[tuple[str, str, str, str], dict] = {}
    sessions: list[dict] = []
    for packet in packets:
        # DNS has one apex per source in this fixture; including it prevents
        # unrelated domains at the same destination resolver from merging.
        qname = packet["payload"].rstrip(".") if protocol == "dns" else ""
        apex = ".".join(qname.split(".")[-2:]) if qname else ""
        key = (packet["label"], packet["source_ip"], packet["destination_ip"], apex)
        timestamp = float(packet["timestamp"])
        state = active.get(key)
        if state is None or timestamp - float(state["last_timestamp"]) > idle_gap_seconds:
            state = {
                "session_id": f"{protocol}-session-{len(sessions) + 1:04d}",
                "label": packet["label"], "source": packet["source"],
                "scenario": packet["scenario"],
                "source_ip": packet["source_ip"], "destination_ip": packet["destination_ip"],
                "first_timestamp": packet["timestamp"], "last_timestamp": packet["timestamp"],
                "packet_count": 0, "alerted_packet_count": 0, "detected": 0,
                "outcome": "", "first_alert_packet_id": "", "rule_ids": "",
                "packet_ids": "", "payload_preview": packet["payload"][:120],
                "detector_message": "[]",
                "_packet_ids": [], "_rules": set(),
            }
            active[key] = state
            sessions.append(state)
        packet["session_id"] = state["session_id"]
        state["packet_count"] += 1
        state["last_timestamp"] = packet["timestamp"]
        state["_packet_ids"].append(packet["id"])
        state["_rules"].update(rule for rule in packet["rule_ids"].split(";") if rule)
        if packet["detected"]:
            state["alerted_packet_count"] += 1
            state["detected"] = 1
            if not state["first_alert_packet_id"]:
                state["first_alert_packet_id"] = packet["id"]
                state["detector_message"] = packet["detector_message"]
    for state in sessions:
        state["outcome"] = result(state["label"], bool(state["detected"]))
        state["rule_ids"] = ";".join(sorted(state.pop("_rules")))
        state["packet_ids"] = json.dumps(state.pop("_packet_ids"))
    return sessions


def dns_benign_packets(count: int):
    """One independently labeled benign DNS session per requested datapoint."""
    services = ("www", "api", "mail", "docs", "cdn", "auth", "shop", "status", "assets", "updates")
    for session_index in range(count):
        source_ip = f"192.0.{2 + session_index // 254}.{session_index % 254 + 1}"
        zone = f"zone{session_index:04d}.example"
        kind = session_index % 10
        if kind < 2:
            scenario, packet_count = "cache_busting", 1
        elif kind == 2:
            scenario, packet_count = "ordinary_lookup_burst", 10
        elif kind < 5:
            scenario, packet_count = "service_discovery", 2
        else:
            scenario, packet_count = "ordinary_lookup", 2
        for offset in range(packet_count):
            if scenario == "cache_busting":
                host = f"assets-{session_index:04d}-{(session_index * 7919):08x}"
            elif scenario == "service_discovery":
                host = f"_sip._tcp.{services[offset]}"
            else:
                host = f"{services[offset]}-{session_index % 4}"
            qname = f"{host}.{zone}."
            qtype = 16 if (session_index + offset) % 7 == 0 else 1
            packet = (
                IP(src=source_ip, dst="198.51.100.53")
                / UDP(sport=40000 + offset, dport=53)
                / DNS(rd=1, qd=DNSQR(qname=qname, qtype=qtype))
            )
            yield packet, scenario, float(session_index * 100 + offset)


def dns_tool_packets(path: Path, manifest_path: Path, count: int):
    """Replay distinct tool runs using their original generated packet bytes."""
    with manifest_path.open(newline="", encoding="utf-8") as handle:
        manifest = list(csv.DictReader(handle))
    if len(manifest) < count:
        raise ValueError(f"tool manifest contains {len(manifest)} runs; requested {count}")
    selected = {row["source_ip"]: row for row in manifest[:count]}
    emitted = Counter()
    with PcapReader(str(path)) as capture:
        for packet in capture:
            query = parse_dns_query(packet)
            if query is None or query.source_ip not in selected:
                continue
            emitted[query.source_ip] += 1
            yield packet, f"tool_{selected[query.source_ip]['mode']}_exfil", float(packet.time)
    for source_ip, row in selected.items():
        if emitted[source_ip] != int(row["query_count"]):
            raise ValueError(f"packet count mismatch for tool run {row['run_id']}")


def dns_iodine_packets(path: Path):
    """Replay the bundled iodine capture as one additional real-tool malicious session.

    This is a single recorded transfer from a second, independent DNS-tunnel tool
    (iodine), counted as one of the malicious sessions alongside the seeded
    zrckr/dns-tunnel runs.
    """
    with PcapReader(str(path)) as capture:
        for packet in capture:
            query = parse_dns_query(packet)
            if query is None:
                continue
            yield packet, "iodine_reference", float(packet.time)


def eval_dns(benign_count: int, malicious_count: int, pcap: Path, manifest_path: Path,
             iodine_pcap: Path) -> list[dict]:
    rows = []
    # The malicious set is (malicious_count - 1) seeded zrckr/dns-tunnel runs plus
    # one recorded iodine transfer, so a second real tool is represented without
    # changing the overall malicious session count. Each stream gets fresh
    # detector state.
    for label, source, detector, packets in (
        ("benign", "synthetic_dns", DnsTunnelDetector(), dns_benign_packets(benign_count)),
        ("malicious", "zrckr_dns_tunnel", DnsTunnelDetector(),
         dns_tool_packets(pcap, manifest_path, malicious_count - 1)),
        ("malicious", "iodine", DnsTunnelDetector(), dns_iodine_packets(iodine_pcap)),
    ):
        for packet, scenario, timestamp in packets:
            query = parse_dns_query(packet)
            assert query is not None
            alerts = detector.inspect(query.source_ip, query.destination_ip, query.qname, query.qtype, now=timestamp)
            detected = bool(alerts)
            rows.append({
                "id": f"dns-{len(rows) + 1:04d}", "label": label, "source": source,
                "scenario": scenario, "timestamp": f"{timestamp:.6f}",
                "source_ip": query.source_ip, "destination_ip": query.destination_ip,
                "qtype": query.qtype, "qtype_code": int(packet[DNS].qd[0].qtype),
                "payload": query.qname, "payload_hex": "",
                "detected": int(detected), "outcome": result(label, detected),
                "rule_ids": ";".join(alert["rule_id"] for alert in alerts),
                "detector_message": json.dumps(alerts, default=str, ensure_ascii=False),
            })
    return rows


# Benign ICMP is sampled at random (seeded): a diagnostic kind per session and,
# for custom pings, a size drawn from this set. 32/56 are standard ping sizes so
# altered content there reads as an abnormal pattern; 48/64 are non-standard
# sizes; 100/120 are oversized -- the benign variety the detector over-flags.
BENIGN_CUSTOM_SIZES = (32, 48, 56, 64, 100, 120)
BENIGN_KINDS = ("linux_default_ping", "windows_default_ping", "custom_ping")
BENIGN_KIND_WEIGHTS = (0.4, 0.3, 0.3)


def icmp_benign_packets(count: int):
    rng = random.Random(20261017)
    for session_index in range(count):
        kind = rng.choices(BENIGN_KINDS, weights=BENIGN_KIND_WEIGHTS)[0]
        if kind == "linux_default_ping":
            # A real Linux ping's timeval is "now" -- is_valid_linux_timestamp
            # (added by issue #11's fix) rejects anything else as stale, so a
            # fabricated tv_sec here would misclassify a genuinely benign ping
            # as icmp_abnormal_pattern.
            now = time.time()
            tv_sec = int(now)
            tv_usec = int((now - tv_sec) * 1_000_000)
            payload = (
                tv_sec.to_bytes(8, "little", signed=True)
                + tv_usec.to_bytes(8, "little", signed=True)
                + LINUX_PING_PATTERN
            )
            scenario = "linux_default_ping"
        elif kind == "windows_default_ping":
            payload = WINDOWS_PING_PAYLOAD
            scenario = "windows_default_ping"
        else:
            size = rng.choice(BENIGN_CUSTOM_SIZES)
            payload = rng.randbytes(size)
            scenario = f"custom_{size}_byte_ping"
        source_ip = f"192.0.{2 + session_index // 254}.{session_index % 254 + 1}"
        for sequence in range(rng.randint(1, 5)):  # aleatory packet count per session
            packet = IP(src=source_ip, dst="198.51.100.10") / ICMP(type=8, id=1234, seq=sequence + 1) / Raw(load=payload)
            yield packet, scenario, float(session_index * 100 + sequence)


def icmp_tool_packets(path: Path, manifest_path: Path, count: int, scenario: str, profile_prefix: str | None = None):
    """Replay one distinct ICMP transfer per selected manifest row.

    When the manifest carries a per-run ``profile`` and ``profile_prefix`` is
    given, the scenario is ``f"{profile_prefix}_{profile}"`` so each detection
    path shows up separately; otherwise every packet uses ``scenario``.
    """
    with manifest_path.open(newline="", encoding="utf-8") as handle:
        manifest = list(csv.DictReader(handle))
    if len(manifest) < count:
        raise ValueError(f"ICMP tool manifest contains {len(manifest)} runs; requested {count}")
    selected = {row["source_ip"]: row for row in manifest[:count]}
    emitted = Counter()
    with PcapReader(str(path)) as capture:
        for packet in capture:
            message = parse_icmp_echo(packet)
            if message is None or message.source_ip not in selected:
                continue
            row = selected[message.source_ip]
            emitted[message.source_ip] += 1
            if profile_prefix and row.get("profile"):
                yield packet, f"{profile_prefix}_{row['profile']}", float(packet.time)
            else:
                yield packet, scenario, float(packet.time)
    for source_ip, row in selected.items():
        if emitted[source_ip] != int(row["packet_count"]):
            raise ValueError(f"packet count mismatch for tool run {row['run_id']}")


def eval_icmp(
    benign_count: int,
    malicious_count: int,
    icmptunnel_pcap: Path,
    icmptunnel_manifest: Path,
    smendowski_pcap: Path,
    smendowski_manifest: Path,
) -> list[dict]:
    rows = []

    def emit(label: str, source: str, scenario: str, timestamp: float, msg, tracker) -> None:
        findings = analyze_icmp_message(msg, rate_tracker=tracker, timestamp=timestamp)
        detected = bool(findings)
        messages = [{"rule_id": finding.rule_id, "severity": str(finding.severity),
                     "description": finding.description, "details": finding.details} for finding in findings]
        rows.append({
            "id": f"icmp-{len(rows) + 1:04d}", "label": label, "source": source,
            "scenario": scenario, "timestamp": f"{timestamp:.6f}",
            "source_ip": msg.source_ip, "destination_ip": msg.destination_ip,
            "qtype": "", "qtype_code": "",
            "payload": msg.payload.decode("utf-8", errors="replace"),
            "payload_hex": msg.payload.hex(), "detected": int(detected),
            "outcome": result(label, detected),
            "rule_ids": ";".join(finding.rule_id for finding in findings),
            "detector_message": json.dumps(messages, default=str, ensure_ascii=False),
        })

    # Benign class gets its own detector state.
    benign_tracker = ICMPRateTracker()
    for packet, scenario, timestamp in icmp_benign_packets(benign_count):
        msg = parse_icmp_echo(packet)
        assert msg is not None
        emit("benign", "synthetic_ping", scenario, timestamp, msg, benign_tracker)

    # Malicious class: two real tools exercising the two detection paths.
    # icmptunnel ships raw binary (structure path); Smendowski base64-encodes
    # (content / entropy path). Split evenly, distinct source-IP ranges, so one
    # rate tracker covers the class without cross-tool interference.
    icmptunnel_count = malicious_count - malicious_count // 2
    smendowski_count = malicious_count // 2
    malicious_tracker = ICMPRateTracker()
    for source, packets in (
        ("DhavalKapil_icmptunnel",
         icmp_tool_packets(icmptunnel_pcap, icmptunnel_manifest, icmptunnel_count, "icmptunnel_file_transfer", "icmptunnel")),
        ("Smendowski_covert_channels",
         icmp_tool_packets(smendowski_pcap, smendowski_manifest, smendowski_count, "smendowski_base64_exfil")),
    ):
        for packet, scenario, timestamp in packets:
            msg = parse_icmp_echo(packet)
            assert msg is not None
            emit("malicious", source, scenario, timestamp, msg, malicious_tracker)
    return rows


def report(name: str, rows: list[dict], sessions: list[dict]) -> str:
    outcomes = Counter(row["outcome"] for row in rows)
    session_outcomes = Counter(row["outcome"] for row in sessions)
    session_scenarios = Counter((row["scenario"], row["outcome"]) for row in sessions)
    rules = Counter(rule for row in rows for rule in row["rule_ids"].split(";") if rule)
    scenarios = Counter((row["scenario"], row["outcome"]) for row in rows)
    benign = outcomes["TN"] + outcomes["FP"]
    malicious = outcomes["TP"] + outcomes["FN"]
    benign_sessions = session_outcomes["TN"] + session_outcomes["FP"]
    malicious_sessions = session_outcomes["TP"] + session_outcomes["FN"]
    lines = [f"# {name} detector evaluation -- result tables", "",
             "Generated by `evaluation/run_covert_eval.py`. Numbers only; see the evaluation "
             "write-up for method, tool provenance, and interpretation.", "",
             "## Session-level results", "",
             "| Metric | Count / value |", "| --- | ---: |",
             f"| Benign sessions | {benign_sessions} |", f"| Malicious sessions | {malicious_sessions} |",
             f"| Detected malicious sessions | {session_outcomes['TP']} |",
             f"| Missed malicious sessions | {session_outcomes['FN']} |",
             f"| Flagged benign sessions | {session_outcomes['FP']} |",
             f"| Unflagged benign sessions | {session_outcomes['TN']} |",
             f"| Benign session alert rate | {session_outcomes['FP'] / benign_sessions:.1%} |",
             f"| Malicious session detection rate | {session_outcomes['TP'] / malicious_sessions:.1%} |", "",
             "### By session scenario", "", "| Scenario | TP | FN | FP | TN |",
             "| --- | ---: | ---: | ---: | ---: |"]
    for scenario in sorted({row["scenario"] for row in sessions}):
        lines.append(f"| {scenario} | " + " | ".join(str(session_scenarios[(scenario, outcome)]) for outcome in ("TP", "FN", "FP", "TN")) + " |")
    lines += ["",
             "## Packet-level diagnostics", "",
             "A packet without an alert is not a missed session when another packet in the same session alerted. "
             "The packet `outcome` column describes individual alert emission only.", "",
             "| Metric | Count / value |", "| --- | ---: |",
             f"| Benign samples | {benign} |", f"| Malicious samples | {malicious} |",
             f"| True positives | {outcomes['TP']} |", f"| False negatives | {outcomes['FN']} |",
             f"| False positives | {outcomes['FP']} |", f"| True negatives | {outcomes['TN']} |",
             f"| Benign packet alert rate | {outcomes['FP'] / benign:.1%} |",
             f"| Malicious packet alert rate | {outcomes['TP'] / malicious:.1%} |", "",
             "### By scenario", "", "| Scenario | TP | FN | FP | TN |", "| --- | ---: | ---: | ---: | ---: |"]
    for scenario in sorted({row["scenario"] for row in rows}):
        lines.append(f"| {scenario} | " + " | ".join(str(scenarios[(scenario, outcome)]) for outcome in ("TP", "FN", "FP", "TN")) + " |")
    lines += ["", "### Rules fired", "", "| Rule | Findings |", "| --- | ---: |"]
    lines += [f"| {rule} | {count} |" for rule, count in rules.most_common()]
    lines += ["", "## Review packet examples", ""]
    for outcome in ("FP", "FN"):
        examples = [row for row in rows if row["outcome"] == outcome][:5]
        title = "Flagged benign packets" if outcome == "FP" else "Malicious packets without an alert"
        lines.append(f"### {title}")
        lines.append("")
        if examples:
            for row in examples:
                lines.append(f"- `{row['id']}` ({row['scenario']}): `{row['rule_ids'] or 'no alert'}`")
        else:
            lines.append("- None in this sample.")
        lines.append("")
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dns-pcap", type=Path, default=ROOT / "dns" / "tool_sessions.pcap")
    parser.add_argument("--dns-manifest", type=Path, default=ROOT / "dns" / "tool_sessions_manifest.csv")
    parser.add_argument("--dns-iodine-pcap", type=Path, default=ROOT / "dns" / "iodine_sample.pcap")
    parser.add_argument("--icmp-pcap", type=Path, default=ROOT / "icmp" / "icmptunnel_sessions.pcap")
    parser.add_argument("--icmp-manifest", type=Path, default=ROOT / "icmp" / "icmptunnel_manifest.csv")
    parser.add_argument("--icmp-smendowski-pcap", type=Path, default=ROOT / "icmp" / "smendowski_sessions.pcap")
    parser.add_argument("--icmp-smendowski-manifest", type=Path, default=ROOT / "icmp" / "smendowski_manifest.csv")
    parser.add_argument("--benign-count", type=int, default=100)
    parser.add_argument("--malicious-count", type=int, default=100)
    args = parser.parse_args()
    if args.benign_count < 1 or args.malicious_count < 1:
        parser.error("session counts must be positive")
    dns_rows = eval_dns(args.benign_count, args.malicious_count, args.dns_pcap, args.dns_manifest,
                        args.dns_iodine_pcap)
    icmp_rows = eval_icmp(
        args.benign_count, args.malicious_count,
        args.icmp_pcap, args.icmp_manifest,
        args.icmp_smendowski_pcap, args.icmp_smendowski_manifest,
    )
    dns_sessions = build_sessions("dns", dns_rows)
    icmp_sessions = build_sessions("icmp", icmp_rows)
    write_rows(ROOT / "dns" / "results.csv", dns_rows)
    write_rows(ROOT / "icmp" / "results.csv", icmp_rows)
    write_session_rows(ROOT / "dns" / "sessions.csv", dns_sessions)
    write_session_rows(ROOT / "icmp" / "sessions.csv", icmp_sessions)
    (ROOT / "dns" / "REPORT.md").write_text(report("DNS", dns_rows, dns_sessions), encoding="utf-8")
    (ROOT / "icmp" / "REPORT.md").write_text(report("ICMP", icmp_rows, icmp_sessions), encoding="utf-8")
    print("DNS sessions", Counter(row["outcome"] for row in dns_sessions), "packets", Counter(row["outcome"] for row in dns_rows))
    print("ICMP sessions", Counter(row["outcome"] for row in icmp_sessions), "packets", Counter(row["outcome"] for row in icmp_rows))


if __name__ == "__main__":
    main()
