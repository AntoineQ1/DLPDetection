"""Unit tests for the DNS covert-channel detector (Workstream C).

These test the string-level heuristics directly, mirroring how the sniffer feeds
qnames produced by attacks/dns_exfiltrate.py, plus parse_dns_query on crafted
scapy packets. No live capture required.
"""

import base64

from detection.common.types import Severity
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, UDP

from detection.covert_channel.dns_detector import (
    DnsTunnelDetector,
    extract_features,
    parse_dns_query,
)
from detection.l7_web.entropy import shannon_entropy

APEX = "attacker.example"
BASE_DOMAIN = f"exfil.{APEX}"  # note: apex is the trailing 2 labels


def _qname(idx: int, label: str) -> str:
    """Reproduce the generator's qname layout: c<idx>.<label>.<base-domain>."""
    return f"c{idx}.{label}.{BASE_DOMAIN}"


def _encode(secret: bytes, mode: str) -> str:
    if mode == "hex":
        return secret.hex()
    if mode == "base32":
        return base64.b32encode(secret).decode().rstrip("=").lower()
    if mode == "base64":
        return base64.urlsafe_b64encode(secret).decode().rstrip("=")
    raise ValueError(mode)


# --- shannon_entropy ----------------------------------------------------------

def test_entropy_empty_is_zero():
    assert shannon_entropy("") == 0.0


def test_entropy_uniform_is_low():
    assert shannon_entropy("aaaaaaaa") == 0.0


def test_entropy_random_higher_than_english():
    encoded = _encode(b"VISA 4111111111111111", "base32")
    assert shannon_entropy(encoded) > shannon_entropy("www.google.example")


# --- extract_features ---------------------------------------------------------

def test_extract_features_apex_and_subdomain():
    feats = extract_features(_qname(0, "mzxw6ytb"))
    assert feats.apex == APEX
    # apex is the trailing 2 labels, so everything left of attacker.example
    # (index label, encoded chunk, and the "exfil" label) is the payload.
    assert feats.subdomain == "c0mzxw6ytbexfil"
    assert feats.total_len == len(_qname(0, "mzxw6ytb"))


def test_extract_features_trailing_dot():
    assert extract_features("a.b.example.").qname == "a.b.example"


# --- detector rules -----------------------------------------------------------

def test_high_entropy_encoded_label_alerts():
    det = DnsTunnelDetector()
    label = _encode(b"VISA 4111111111111111 exp 12/26", "base32")
    alerts = det.inspect("172.20.0.3", "172.21.0.10", _qname(0, label), "A", now=1000.0)
    assert any(a["rule_id"] == "DNS_HIGH_ENTROPY" for a in alerts)


def test_benign_hostname_no_alert():
    det = DnsTunnelDetector()
    alerts = det.inspect("172.20.0.3", "8.8.8.8", "www.google.example", "A", now=1000.0)
    assert alerts == []


def test_naive_long_qname_alerts_on_length():
    det = DnsTunnelDetector()
    # naive mode keeps low entropy but produces a long single label.
    label = "SECRET-CARD-" + "4111111111111111" + "-EXP-1226"
    alerts = det.inspect("172.20.0.3", "172.21.0.10", _qname(0, label), "A", now=1000.0)
    assert any(a["rule_id"] == "DNS_LONG_QNAME" for a in alerts)


def test_volume_rule_fires_once_per_burst():
    det = DnsTunnelDetector()
    fired = 0
    for i in range(20):
        label = _encode(f"chunk{i}".encode(), "base32")
        alerts = det.inspect("172.20.0.3", "172.21.0.10", _qname(i, label), "A", now=1000.0 + i)
        fired += sum(1 for a in alerts if a["rule_id"] == "DNS_TUNNEL_VOLUME")
    assert fired == 1  # one alert for the ongoing burst, not one per query


def test_volume_rule_respects_window():
    det = DnsTunnelDetector()
    # Two unique queries spaced far apart never accumulate inside the window.
    for i in range(20):
        label = _encode(f"slow{i}".encode(), "base32")
        alerts = det.inspect(
            "172.20.0.3", "172.21.0.10", _qname(i, label), "A", now=1000.0 + i * 1000
        )
        assert all(a["rule_id"] != "DNS_TUNNEL_VOLUME" for a in alerts)


def test_alert_payload_shape():
    det = DnsTunnelDetector()
    # Repetitive digits encode to low entropy, so this trips DNS_LONG_QNAME
    # (28-char label) rather than DNS_HIGH_ENTROPY -- either way an alert fires
    # and every alert carries the same detail shape we check here.
    label = _encode(b"VISA 4111111111111111", "base64")
    alerts = det.inspect("172.20.0.3", "172.21.0.10", _qname(0, label), "TXT", now=1000.0)
    assert alerts, "expected at least one alert"
    a = alerts[0]
    assert a["source_ip"] == "172.20.0.3"
    assert a["destination"] == APEX
    assert a["details"]["qtype"] == "TXT"
    assert "qname" in a["details"]


# --- content rules reused from l7_web (scan_all) --------------------------------

def _naive(secret: str) -> str:
    """Reproduce the generator's naive encoding: non-alnum chars become '-'."""
    return "".join(c if c.isalnum() else "-" for c in secret)


def test_naive_card_number_triggers_l7_luhn_rule():
    det = DnsTunnelDetector()
    qname = _qname(0, _naive("VISA 4111111111111111"))
    alerts = det.inspect("172.20.0.3", "172.21.0.10", qname, "A", now=1000.0)
    content = [a for a in alerts if a["rule_id"] == "DNS_SENSITIVE_DATA_LUHN_CC"]
    assert len(content) == 1
    a = content[0]
    assert a["severity"] == Severity.HIGH  # severity comes from the l7_web finding
    assert a["destination"] == APEX
    assert a["details"]["l7_rule_id"] == "luhn_cc"
    assert a["details"]["source"] == "dns_qname"
    assert a["details"]["matched"] == "4111111111111111"


def test_chunk_index_label_does_not_break_card_detection():
    # c7 sits right before the payload label; scanning labels separately keeps
    # the "7" from being glued onto the card number.
    extract = extract_features(_qname(7, "4111111111111111"))
    assert extract.sub_labels == ["c7", "4111111111111111", "exfil"]
    det = DnsTunnelDetector()
    alerts = det.inspect("172.20.0.3", "172.21.0.10", _qname(7, "4111111111111111"), now=1000.0)
    assert any(a["rule_id"] == "DNS_SENSITIVE_DATA_LUHN_CC" for a in alerts)


def test_encoded_card_number_does_not_trigger_content_rule():
    det = DnsTunnelDetector()
    label = _encode(b"VISA 4111111111111111", "base32")
    alerts = det.inspect("172.20.0.3", "172.21.0.10", _qname(0, label), "A", now=1000.0)
    assert not any(a["rule_id"].startswith("DNS_SENSITIVE_DATA_") for a in alerts)


def test_apex_labels_are_not_content_scanned():
    det = DnsTunnelDetector()
    alerts = det.inspect("172.20.0.3", "8.8.8.8", "4111111111111111.example", now=1000.0)
    assert not any(a["rule_id"].startswith("DNS_SENSITIVE_DATA_") for a in alerts)


# --- parse_dns_query ------------------------------------------------------------

def test_parse_dns_query_extracts_fields():
    pkt = IP(src="172.20.0.3", dst="172.21.0.10") / UDP(dport=53) / DNS(
        rd=1, qd=DNSQR(qname=_qname(0, "mzxw6ytb"), qtype="TXT")
    )
    query = parse_dns_query(pkt)
    assert query is not None
    assert query.source_ip == "172.20.0.3"
    assert query.destination_ip == "172.21.0.10"
    assert query.qname.rstrip(".") == _qname(0, "mzxw6ytb")
    assert query.qtype == "TXT"


def test_parse_dns_query_ignores_responses():
    pkt = IP(src="172.21.0.10", dst="172.20.0.3") / UDP(sport=53) / DNS(
        qr=1, qd=DNSQR(qname="www.google.example")
    )
    assert parse_dns_query(pkt) is None


def test_parse_dns_query_ignores_non_dns():
    assert parse_dns_query(IP(dst="172.21.0.10") / ICMP()) is None
