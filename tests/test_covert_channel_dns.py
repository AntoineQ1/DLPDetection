"""Unit tests for the DNS covert-channel analyzer (Workstream C).

These test the string-level heuristics directly, mirroring how the sniffer feeds
qnames produced by attacks/dns_exfiltrate.py. No scapy / live capture required.

icmp_analyzer tests are pending on attacks/icmp_exfiltrate.py (still a TODO).
"""

import base64

from detection.covert_channel.dns_analyzer import (
    DnsTunnelDetector,
    extract_features,
    shannon_entropy,
)

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
