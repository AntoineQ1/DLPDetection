"""DNS covert-channel detection engine - Parsing & heuristics (Workstream C).

Holds everything that only makes sense for DNS: query parsing, thresholds,
qname feature extraction (apex / subdomain split) and the tunnelling rules. Generic
primitives are reused from ``detection.l7_web`` (``shannon_entropy`` and the
``scan_all`` content engine); only how DNS applies them (thresholds, what text
is scored) lives here.

``parse_dns_query`` turns a scapy packet into a plain ``DnsQuery``; all
detection logic then operates on plain strings/ints, so it is unit-testable
without live capture. Alert logging is done by ``sniffer.py``.

Complementary rules cover the attack's stealth ladder (D1..D4, defined in
docs/dns-detection-mechanism.md):

  DNS_LONG_QNAME          long overall qname / long single label  -> catches D1 naive
  DNS_SENSITIVE_DATA_*    L7 content rules (regex/Luhn) on labels -> catches D1 naive content
  DNS_HIGH_ENTROPY        encoded (random-looking) labels          -> catches D2 hex/base32/base64
  DNS_TUNNEL_VOLUME       many unique subdomains under one apex     -> catches D3 burst / D4 slow

Thresholds are environment-overridable so the lab can be tuned without edits.
"""

from __future__ import annotations

import os
import time
from collections import deque
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from scapy.layers.dns import DNS
from scapy.layers.inet import IP

from detection.common.types import Severity
from detection.l7_web import scan_all
from detection.l7_web.entropy import shannon_entropy
from detection.l7_web.luhn import scan as scan_luhn

if TYPE_CHECKING:
    from scapy.packet import Packet

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


QTYPE_NAMES = {1: "A", 16: "TXT", 28: "AAAA"}


@dataclass(frozen=True)
class DnsQuery:
    """Represents a parsed DNS query with the fields the detector needs."""

    source_ip: str
    destination_ip: str
    qname: str
    qtype: str


def parse_dns_query(pkt: Packet) -> DnsQuery | None:
    """Parse a DNS query packet. Responses (qr == 1) are ignored."""
    if not (pkt.haslayer(IP) and pkt.haslayer(DNS)):
        return None
    dns = pkt[DNS]
    # scapy parses the raw packet into named layers, so pkt[DNS] reads DNS fields directly.
    # qr is the query/response bit: we keep only queries (qr == 0), since the reply echoes
    # the same qname and scoring both would double-count every subdomain.
    # qd is the questions list; we check it directly (qdcount can be None) and use the first.
    if dns.qr != 0 or not dns.qd:
        return None

    question = dns.qd[0]
    qname_raw = question.qname
    qname = qname_raw.decode("latin-1") if isinstance(qname_raw, bytes) else str(qname_raw)
    qtype = QTYPE_NAMES.get(int(getattr(question, "qtype", 1)), "OTHER")

    return DnsQuery(
        source_ip=pkt[IP].src,
        destination_ip=pkt[IP].dst,
        qname=qname,
        qtype=qtype,
    )


@dataclass
class QnameFeatures:
    qname: str
    apex: str
    subdomain: str          # everything to the left of the apex, dots removed
    sub_labels: list[str]   # the individual labels left of the apex
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

    global_entropy = (
        shannon_entropy(subdomain) if len(subdomain) >= ENTROPY_MIN_CHARS else 0.0
    )

    long_sub_labels = [l for l in sub_labels if len(l) >= ENTROPY_MIN_CHARS]
    max_label_entropy = max(
        (shannon_entropy(l) for l in long_sub_labels),
        default=0.0,
    )

    effective_entropy = max(global_entropy, max_label_entropy)

    return QnameFeatures(
        qname=qname,
        apex=apex,
        subdomain=subdomain,
        sub_labels=sub_labels,
        longest_label=longest,
        total_len=len(qname),
        entropy=effective_entropy,
    )


def _numeric_label_runs(labels: list[str]) -> list[tuple[str, int]]:
    """Join runs of consecutive all-digit labels. Returns (digits, label_count)
    per run; a non-numeric label ends the current run."""
    runs: list[tuple[str, int]] = []
    cur: list[str] = []
    for label in labels:
        if label.isdigit():
            cur.append(label)
        elif cur:
            runs.append(("".join(cur), len(cur)))
            cur = []
    if cur:
        runs.append(("".join(cur), len(cur)))
    return runs


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
        self._cleanup_counter: int = 0

    def _periodic_cleanup(self, now: float) -> None:
        cutoff = now - VOLUME_WINDOW_SEC
        stale_keys = [
            key
            for key, state in self._flows.items()
            if not state.seen or state.seen[-1][0] < cutoff
        ]
        for key in stale_keys:
            del self._flows[key]

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
                    "DNS_LONG_QNAME", Severity.MEDIUM, src_ip, feats, qtype,
                    {"longest_label": feats.longest_label, "qname_len": feats.total_len},
                )
            )

        # Rule 2: shared L7 content rules (regex/Luhn) on the payload labels.
        alerts.extend(self._check_content(src_ip, feats, qtype))

        # Rule 3: high-entropy payload (encoded exfil).
        if len(feats.subdomain) >= ENTROPY_MIN_CHARS and feats.entropy >= ENTROPY_THRESHOLD:
            alerts.append(
                self._alert(
                    "DNS_HIGH_ENTROPY", Severity.HIGH, src_ip, feats, qtype,
                    {"entropy": round(feats.entropy, 3), "payload_len": len(feats.subdomain)},
                )
            )

        # Rule 4: volume of unique subdomains under one apex (burst / low-and-slow).
        vol_alert = self._update_volume(src_ip, feats, qtype, now)
        if vol_alert is not None:
            alerts.append(vol_alert)

        return alerts

    def _check_content(
        self, src_ip: str, feats: QnameFeatures, qtype: str
    ) -> list[dict]:
        # Per-label scan: single-label content (cards, AWS keys, JWTs, entropy).
        # Joining every label would glue the chunk index (c0, c1, ...) onto the
        # payload and corrupt digit runs, so content is scored label-by-label.
        alerts: list[dict] = []
        for label in feats.sub_labels:
            for hit in scan_all(label, source="dns_qname"):
                alerts.append(
                    self._alert(
                        f"DNS_SENSITIVE_DATA_{hit.rule_id.upper()}", hit.severity,
                        src_ip, feats, qtype,
                        {
                            "matched": hit.matched,
                            "detector": hit.detector,
                            "source": hit.source,
                            "l7_rule_id": hit.rule_id,
                            **hit.meta,
                        },
                    )
                )

        # Catch cards split across consecutive numeric labels
        # (41111111.11111111); single labels are already covered above.
        for digits, span in _numeric_label_runs(feats.sub_labels):
            if span < 2:
                continue
            for hit in scan_luhn(digits):
                alerts.append(
                    self._alert(
                        f"DNS_SENSITIVE_DATA_{hit.rule_id.upper()}", hit.severity,
                        src_ip, feats, qtype,
                        {
                            "matched": hit.matched,
                            "detector": hit.detector,
                            "source": "dns_qname",
                            "l7_rule_id": hit.rule_id,
                            "split_labels": span,
                            **hit.meta,
                        },
                    )
                )
        return alerts

    def _update_volume(
        self, src_ip: str, feats: QnameFeatures, qtype: str, now: float
    ) -> dict | None:
        self._cleanup_counter += 1
        if self._cleanup_counter % 500 == 0:
            self._periodic_cleanup(now)

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
        if not state.seen:
            self._flows.pop(key, None)
            return None
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
        severity: Severity,
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
