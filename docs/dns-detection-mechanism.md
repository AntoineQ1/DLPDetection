# DNS Covert-Channel Detection Mechanism

How the passive covert-channel sniffer detects DNS tunneling. This document details the design and rationale of `detection/covert_channel/dns_detector.py` (query parsing plus DNS-only thresholds, features, and rules) and the `sniffer.py` capture layer that feeds it and logs the alerts. This mirrors the ICMP layout (`icmp_detector.py` + `sniffer.py::_handle_icmp`).

Generic primitives are reused from `detection/l7_web` rather than duplicated: `shannon_entropy` lives in `detection/l7_web/entropy.py`. Only the math is shared; thresholds and what text gets scored stay in `dns_detector.py`.

---

## 1. Threat model

An attacker who cannot exfiltrate over HTTP (blocked by the L7 gateway) can smuggle data inside DNS queries. The secret is encoded, chunked into DNS labels, and sent as queries for `c<idx>.<encoded-chunk>.exfil.attacker.example` toward a DNS server the attacker controls. To ordinary DNS infrastructure, it just looks like a lot of lookups for one domain.

The generator we defend against is `attacks/dns_exfiltrate.py`, whose modes escalate in stealth. The taxonomy (D1–D4) is a stealth ladder local to this project — each level is harder to catch than the last:

| Level | What the attacker does | How we catch it |
| --- | --- | --- |
| D1 | naive plaintext labels | length + content/Luhn rules |
| D2 | encoded (hex / base32 / base64) | high entropy |
| D3 | burst of many queries (`--count`) | volume to one apex |
| D4 | low-and-slow, jittered (`--delay`) | volume to one apex over time |

The modes below map onto that ladder:

| Mode | Level | Technique | Naive weakness we exploit |
| --- | --- | --- | --- |
| `naive` | D1 | plaintext-ish labels | long, human-readable label |
| `hex` | D2 | base16 encoding | high-entropy label |
| `base32` | D2 | base32 (classic tunnel charset) | high-entropy label |
| `base64` | D2 | urlsafe base64 | high-entropy label |
| + `--count` | D3 | burst of many queries | volume to one apex |
| + `--delay` | D4 | low-and-slow, jittered | volume to one apex over time |

---

## 2. Where we capture (and why it matters)

The `covert-detector` container runs with `network_mode: "service:gateway"`, so it shares the gateway's network namespace. The gateway is **dual-homed**:

- `internal_net` → `172.20.0.2` (victim side, `172.20.0.0/24`)
- `external_net` → `172.21.0.2` (attacker side, `172.21.0.0/24`)

`sniffer.py::pick_interfaces()` prefers the interface whose IPv4 starts with `172.20.0.` (the `INTERNAL_SUBNET_PREFIX`). This is deliberate:

```
victim 172.20.0.3 ──query──▶ [gateway internal NIC]  ← we sniff HERE
                                     │ forward + MASQUERADE
                                     ▼
                             [gateway external NIC] ──▶ attacker 172.21.0.10
                             (src rewritten to 172.21.0.2)
```

Sniffing the **internal** side means:

1. We see each exfil packet **once** — not again after it is forwarded out the external side, avoiding double-counting.
2. The `source_ip` in every alert is the **victim's real address**, before NAT rewrites it. That address is our ground truth for attributing the leak.

If the lab addressing ever changes, `pick_interfaces()` falls back to every non-loopback interface with an IPv4, so capture still works.

Supporting robustness in `sniffer.py`:

- **Startup race** — polls up to 30×1s for shared-netns interfaces to come up before opening the capture socket (avoids Scapy's "Network is down").
- **Resilience** — `sniff(...)` runs in a `while True` loop that catches `OSError`, waits, and re-picks interfaces, so a transient interface flap does not kill the detector.
- **BPF filter** — `"icmp or udp port 53"` limits capture to the channels we care about; `store=False` keeps memory flat over long runs.

The sniffer is a thin dispatcher: DNS packets go to `_handle_dns`, which parses the query with `dns_detector.parse_dns_query` (responses, `qr == 1`, are ignored), feeds the process-wide `DnsTunnelDetector`, and logs each alert. ICMP packets go to `_handle_icmp` the same way.

---

## 3. Feature extraction

For each query name, we compute string-level features (`dns_detector.extract_features`) with no dependency on Scapy, so the logic is unit-testable:

- **apex** — the trailing `DNS_APEX_LABELS` labels (default 2), an approximation of the registered domain. For `c0.MZXW6.exfil.attacker.example`, the apex is `attacker.example`.
- **subdomain (payload)** — everything to the left of the apex, dots removed (`c0MZXW6exfil`). This is the attacker-controlled carrier.
- **longest_label** — length of the longest single label (RFC max is 63).
- **total_len** — length of the whole qname.
- **entropy** — per-character Shannon entropy (bits/char) over the payload, computed with the shared `detection.l7_web.entropy.shannon_entropy`.

**Shannon entropy** measures how unpredictable the characters are:

$$H = -\sum_{c} p(c) \log_2 p(c)$$

Random-looking encoded data (base32/base64 of arbitrary bytes) sits around 4.5–5 bits/char; ordinary hostnames and English-ish text sit around 2.5–3.5. A caveat we rely on: **repetitive** secrets (e.g. `4111111111111111`) encode to *lower* entropy — those are caught by the length rule instead.

---

## 4. Detection rules

Four complementary rules, because no single signal covers the whole stealth ladder.

### DNS_LONG_QNAME — severity MEDIUM

Fires when `longest_label >= DNS_LABEL_LEN_THRESHOLD` (default 20) **or** `total_len >= DNS_QNAME_LEN_THRESHOLD` (default 50).

Content-agnostic: catches **naive plaintext** (D1), which is low-entropy but produces labels far longer than real hostnames.

### DNS_SENSITIVE_DATA_* — severity from the L7 rule

Runs the shared L7 content engine (`detection.l7_web.scan_all`: regex rules and Luhn-validated card numbers) on each subdomain label, with `source="dns_qname"`. One alert per L7 hit, named `DNS_SENSITIVE_DATA_<L7 RULE ID>` (e.g. `DNS_SENSITIVE_DATA_LUHN_CC`); the severity is the L7 finding's own `Severity`, and `details` carries `l7_rule_id`, `detector`, `matched`, and the detector's metadata.

Catches **naive plaintext** content (D1) with the exact same rules as the web gateway, no DNS-specific duplicates. Labels are scanned one by one (not joined) so the chunk-index label (`c0`, `c1`, …) is not glued onto a digit run. Apex labels are not scanned. Encoded modes (D2) hide the content from these rules and are left to the entropy rule.

### DNS_HIGH_ENTROPY — severity HIGH

Fires when the payload is at least `DNS_ENTROPY_MIN_CHARS` (default 16) long **and** its entropy `>= DNS_ENTROPY_THRESHOLD` (default 3.8 bits/char).

Catches **encoded** exfil (D2 hex/base32/base64). Encoding defeats keyword/regex rules, but the resulting randomness is exactly what entropy flags. The minimum-length guard prevents scoring entropy on payloads too short to be meaningful.

### DNS_TUNNEL_VOLUME — severity HIGH

Fires when a single source sends `>= DNS_VOLUME_THRESHOLD` (default 8) **unique** subdomains under the **same apex** within a sliding window of `DNS_VOLUME_WINDOW_SEC` (default 60s).

Catches the **burst** (D3) and **low-and-slow** (D4) patterns. Even if each query were short and low-entropy, tunneling a real secret still requires many distinct lookups to one domain — the pattern gives it away.

State is kept per `(source_ip, apex)`:

- a deque of `(timestamp, subdomain)` pairs, evicted once older than the window;
- the count of unique subdomains currently in the window;
- a `volume_alerted` flag so an ongoing burst raises **one** alert, not one per query. The flag resets when traffic drops back below the threshold, so a later burst alerts again.

**Why four rules together:** encoding raises entropy (→ rule 3), but a naive attacker stays readable (→ rules 1 & 2); a careful attacker can keep each query short and low-entropy, but volume to a single apex still betrays them (→ rule 4). The gaps of each rule are covered by the others.

---

## 5. Alert output

Every hit is emitted through the shared helper `detection/common/logger.py::log_alert`, producing one JSON line prefixed with `[DLP-ALERT]`:

```json
[DLP-ALERT] {
  "timestamp": 1790333178.47,
  "channel": "DNS_COVERT",
  "rule_id": "DNS_HIGH_ENTROPY",
  "severity": "high",
  "source_ip": "172.20.0.3",
  "destination": "attacker.example",
  "blocked": false,
  "details": { "qname": "...", "qtype": "A", "entropy": 4.07, "payload_len": 57 }
}
```

- `channel` is `DNS_COVERT`, matching the standardized format in the README so the L7 addon and `evaluation/` metrics parse it identically.
- `blocked` is always `false`: this sniffer is **detect-only**. Blocking is the gateway's responsibility; keeping detection passive lets us measure detection rate vs. false positives before wiring in enforcement.
- A query may raise more than one alert (e.g. a long **and** high-entropy label).

---

## 6. Tuning

All thresholds are environment-overridable — no code change needed to retune per environment:

| Env var | Default | Controls |
| --- | --- | --- |
| `DNS_APEX_LABELS` | 2 | how many trailing labels count as the apex |
| `DNS_LABEL_LEN_THRESHOLD` | 20 | long single-label trigger |
| `DNS_QNAME_LEN_THRESHOLD` | 50 | long full-name trigger |
| `DNS_ENTROPY_THRESHOLD` | 3.8 | bits/char to flag as encoded |
| `DNS_ENTROPY_MIN_CHARS` | 16 | min payload length before scoring entropy |
| `DNS_VOLUME_THRESHOLD` | 8 | unique subdomains per apex per window |
| `DNS_VOLUME_WINDOW_SEC` | 60 | sliding-window length in seconds |

---

## 7. Testing

The string-level heuristics are covered offline (no Docker/scapy) in `tests/test_covert_channel_dns.py` — entropy behavior, apex/payload splitting, each rule, and the volume window:

```bash
uv run pytest tests/test_covert_channel_dns.py -v
```

---

## 8. Limitations & next steps

- **Apex heuristic** — trailing-2-labels is an eTLD+1 approximation; a domain like `foo.co.uk` would be misgrouped. Acceptable in the closed lab.
- **DNS-over-HTTPS/TLS** — encrypted DNS would bypass the plaintext UDP/53 sniffer; out of scope for this channel (would surface at the L7 layer instead).
- **Enforcement** — a natural follow-up is blocking flagged apexes inline rather than alerting only.