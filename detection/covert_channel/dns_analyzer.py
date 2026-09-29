"""DNS covert-channel analyzer (Workstream C).

Consumes DNS *queries* (qr == 0) observed on the internal interface by
``sniffer.py`` and raises DLP alerts for tunnelling behaviour produced by
``attacks/dns_exfiltrate.py``.

Design: packet parsing (scapy) is kept in :func:`analyze_dns_packet`, while all
detection logic operates on plain strings/ints in :class:`DnsTunnelDetector`, so
the heuristics are unit-testable without live capture.

Three complementary rules cover the attack's stealth ladder (D1..D5):

  DNS_LONG_QNAME        long overall qname / long single label  -> catches D1 naive
  DNS_HIGH_ENTROPY      encoded (random-looking) labels          -> catches D2 hex/base32/base64
  DNS_TUNNEL_VOLUME     many unique subdomains under one apex     -> catches D3 burst / D5 slow

Thresholds are environment-overridable so the lab can be tuned without edits.
"""

from __future__ import annotations

import math
import os
import time
from collections import deque
from dataclasses import dataclass, field

from detection.common.logger import log_alert
from detection.common.types import Severity

# --- tunables -----------------------------------------------------------------
# Number of trailing labels treated as the registered ("apex") domain. For the
# lab base domain exfil.attacker.example this groups all exfil subdomains under
# attacker.example. Approximation of eTLD+1; good enough for the closed lab.
APEX_LABELS = int(os.environ.get("DNS_APEX_LABELS", "2"))

# A single label this long is a strong tunnelling signal (RFC max is 63; normal
# hostnames rarely exceed ~20).
LABEL_LEN_THRESHOLD = int(os.environ.get("DNS_LABEL_LEN_THRESHOLD", "20"))
# Total qname length that is suspicious regardless of entropy (catches naive).
QNAME_LEN_THRESHOLD = int(os.environ.get("DNS_QNAME_LEN_THRESHOLD", "50"))
# Shannon entropy (bits/char) over the sub-domain payload. Base32/64 of random
# bytes sits ~4.5-5; english/hostnames ~2.5-3.5.
ENTROPY_THRESHOLD = float(os.environ.get("DNS_ENTROPY_THRESHOLD", "3.8"))
# Only score entropy once there is enough payload for it to be meaningful.
ENTROPY_MIN_CHARS = int(os.environ.get("DNS_ENTROPY_MIN_CHARS", "16"))

# Volume rule: this many *unique* subdomains under one apex from one source
# within the sliding window is treated as a tunnel.
VOLUME_THRESHOLD = int(os.environ.get("DNS_VOLUME_THRESHOLD", "8"))
VOLUME_WINDOW_SEC = float(os.environ.get("DNS_VOLUME_WINDOW_SEC", "60"))


def shannon_entropy(text: str) -> float:
    """Per-character Shannon entropy in bits."""
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


@dataclass
class QnameFeatures:
    qname: str
    apex: str
    subdomain: str          # everything to the left of the apex, dots removed
    longest_label: int
    total_len: int
    entropy: float


def extract_features(qname: str) -> QnameFeatures:
    """Split a qname into apex/subdomain and compute string features."""
    qname = qname.rstrip(".")
    labels = [l for l in qname.split(".") if l]
    apex = ".".join(labels[-APEX_LABELS:]) if len(labels) >= APEX_LABELS else qname
    sub_labels = labels[:-APEX_LABELS] if len(labels) > APEX_LABELS else []
    subdomain = "".join(sub_labels)
    longest = max((len(l) for l in labels), default=0)
    return QnameFeatures(
        qname=qname,
        apex=apex,
        subdomain=subdomain,
        longest_label=longest,
        total_len=len(qname),
        entropy=shannon_entropy(subdomain),
    )


@dataclass
class _FlowState:
    """Per (source_ip, apex) sliding-window state for the volume rule."""
    seen: deque[tuple[float, str]] = field(default_factory=deque)  # (ts, subdomain)
    unique: set[str] = field(default_factory=set)
    volume_alerted: bool = False


class DnsTunnelDetector:
    """Stateful DNS-tunnel detector. One instance per sniffer process."""

    def __init__(self) -> None:
        self._flows: dict[tuple[str, str], _FlowState] = {}

    def inspect(
        self,
        src_ip: str,
        dst_ip: str,
        qname: str,
        qtype: str = "A",
        now: float | None = None,
    ) -> list[dict]:
        """Return a list of alert dicts for one query. Empty list = benign.

        Pure w.r.t. I/O: callers (the sniffer) forward each alert to log_alert.
        """
        now = time.time() if now is None else now
        feats = extract_features(qname)
        alerts: list[dict] = []

        # Rule 1: content-agnostic length (fires on naive plaintext too).
        if feats.longest_label >= LABEL_LEN_THRESHOLD or feats.total_len >= QNAME_LEN_THRESHOLD:
            alerts.append(
                self._alert(
                    "DNS_LONG_QNAME", "MEDIUM", src_ip, feats, qtype,
                    {"longest_label": feats.longest_label, "qname_len": feats.total_len},
                )
            )

        # Rule 2: high-entropy payload (encoded exfil).
        if len(feats.subdomain) >= ENTROPY_MIN_CHARS and feats.entropy >= ENTROPY_THRESHOLD:
            alerts.append(
                self._alert(
                    "DNS_HIGH_ENTROPY", Severity.HIGH, src_ip, feats, qtype,
                    {"entropy": round(feats.entropy, 3), "payload_len": len(feats.subdomain)},
                )
            )

        # Rule 3: volume of unique subdomains under one apex (burst / low-and-slow).
        vol_alert = self._update_volume(src_ip, feats, qtype, now)
        if vol_alert is not None:
            alerts.append(vol_alert)

        return alerts

    def _update_volume(
        self, src_ip: str, feats: QnameFeatures, qtype: str, now: float
    ) -> dict | None:
        key = (src_ip, feats.apex)
        state = self._flows.get(key)
        if state is None:
            state = self._flows[key] = _FlowState()

        # Evict entries outside the window and rebuild the unique set lazily.
        cutoff = now - VOLUME_WINDOW_SEC
        while state.seen and state.seen[0][0] < cutoff:
            state.seen.popleft()
        if feats.subdomain:
            state.seen.append((now, feats.subdomain))
        state.unique = {sub for _, sub in state.seen}

        if len(state.unique) < VOLUME_THRESHOLD:
            state.volume_alerted = False  # reset once traffic quiets down
            return None
        if state.volume_alerted:
            return None  # already alerted for this ongoing burst
        state.volume_alerted = True
        return self._alert(
            "DNS_TUNNEL_VOLUME", Severity.HIGH, src_ip, feats, qtype,
            {
                "unique_subdomains": len(state.unique),
                "window_sec": VOLUME_WINDOW_SEC,
            },
        )

    @staticmethod
    def _alert(
        rule_id: str,
        severity: str,
        src_ip: str,
        feats: QnameFeatures,
        qtype: str,
        details: dict,
    ) -> dict:
        return {
            "rule_id": rule_id,
            "severity": severity,
            "source_ip": src_ip,
            "destination": feats.apex,
            "details": {"qname": feats.qname, "qtype": qtype, **details},
        }


# Module-level singleton used by the sniffer dispatch.
_DETECTOR = DnsTunnelDetector()


def analyze_dns_packet(pkt) -> None:
    """scapy entry point: extract the query and feed the detector.

    Only inspects queries (qr == 0); responses from the sink are ignored.
    """
    from scapy.all import DNS, IP  # local import keeps this module test-friendly

    if not pkt.haslayer(DNS) or not pkt.haslayer(IP):
        return
    dns = pkt[DNS]
    # qdcount can be None on freshly-built packets; qd presence is the reliable check.
    if dns.qr != 0 or dns.qd is None:
        return

    qname_raw = dns.qd.qname
    qname = qname_raw.decode("latin-1") if isinstance(qname_raw, bytes) else str(qname_raw)
    qtype = {1: "A", 16: "TXT", 28: "AAAA"}.get(int(getattr(dns.qd, "qtype", 1)), "OTHER")

    for alert in _DETECTOR.inspect(pkt[IP].src, pkt[IP].dst, qname, qtype):
        log_alert(
            channel="DNS_COVERT",
            rule_id=alert["rule_id"],
            severity=alert["severity"],
            source_ip=alert["source_ip"],
            destination=alert["destination"],
            details=alert["details"],
            blocked=False,  # passive sniffer: detect-only, gateway does blocking
        )
