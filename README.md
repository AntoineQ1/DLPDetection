# Network Data Loss Prevention (DLP) Gateway

Containerized network security gateway that detects and blocks data exfiltration across:
- **Application Layer (L7)** 
- **Covert Channels** 

Course project — DD2391 Cybersecurity, KTH.

## Team & Workstreams

| Name | Workstream | Contribution |
|---|---|---|
| Antoine | A, C | |
| Diogo | A, B | |
| Jonas | B | |
| Sofia | C | |

## Problem Statement

<!-- To be filled -->

## Related Work

<!-- To be filled -->

## Architecture

<!-- To be filled -->

## Repository Structure

```text
.
├── attacks/                 # Traffic generation and exfiltration tooling (Victim)
│   ├── samples/             # Datasets used for detection testing
│   │   ├── sensitive/       # Mock confidential data (API keys, credit cards, proprietary files)
│   │   └── benign/          # Legitimate everyday traffic to evaluate false positives
│   ├── web_exfiltrate.py    # Web traffic exfiltration (HTTP/HTTPS)
│   ├── dns_exfiltrate.py    # DNS covert channel exfiltration
│   └── icmp_exfiltrate.py   # ICMP covert channel exfiltration
├── config/                  # Static configuration
│   └── certs/               # Custom test CA certificates for TLS inspection
├── detection/               # Core DLP inspection engine (Gateway)
│   ├── common/              # Shared utilities (logging, analyzers)
│   ├── covert_channel/      # L3/L4 passive traffic inspection (DNS, ICMP)
│   └── l7_web/              # L7 inline proxy inspection (HTTP/HTTPS)
├── docker/                  # Dockerfiles and network initialization scripts
├── docs/                    # Architecture notes and guides
├── evaluation/              # Metrics collection (detection rates, false positives, latency)
├── servers/                 # Destination listeners and C2 sinks (Attacker)
├── tests/                   # Unit tests runnable offline (pytest)
├── docker-compose.yml       # Network and container topology definition
└── pyproject.toml           # Project dependencies managed by uv
```

## Quick Start

### 0. Specific guides

- See [uv_guide](docs/uv_guide.md) for a detailed guide about using `uv` (required to add/update python dependencies)

### 1. Prerequisites
- [Docker](https://docs.docker.com/get-docker/) & Docker Compose
- [uv](https://docs.astral.sh/uv/) (optional, for local development and offline testing)

### 2. Launch the Lab

If you have never launched the lab, first create the certificate for `mitmproxy` :
```bash
./config/certs/generate_ca.sh
```

Start all containers in detached mode:
```bash
docker compose up -d
```

Check the status of the network nodes:

```bash
docker compose ps
```

## Testing Workflows

The repository is configured with live volume mounts (`./detection:/app/detection`). Any code changes made on your host machine take effect immediately inside the containers without rebuilding images.

### Workstream 1: Application Layer (L7 Web DLP)

The Gateway intercepts all outbound HTTP/HTTPS traffic from the Victim.

1. **Watch Gateway logs in real time:**
```bash
docker compose logs -f gateway
```

2. **Send legitimate traffic (Allowed - HTTP 200):**
```bash
docker compose exec victim python attacks/web_exfiltrate.py --secret "benign business payload"
```

3. **Simulate a data leak (Blocked - HTTP 403):**
```bash
docker compose exec victim python attacks/web_exfiltrate.py --secret "CONFIDENTIAL: SECRET API TOKEN"
```

* The client will receive an immediate `403 Forbidden` response.
* A structured `[DLP-ALERT]` JSON entry will appear in the `gateway` logs.

*Note: Changes made to `detection/l7_web/addon.py` are automatically reloaded by `mitmproxy` upon file save.*

### Workstream 2: Covert Channels (L3/L4 Sniffer)

The passive sniffer runs concurrently on the Gateway network namespace, while the Attacker node acts as the exfiltration destination.

1. **Start the C2 listener on the Attacker container:**
```bash
docker compose exec -d attacker python servers/icmp_sink.py
```

2. **Watch alerts from the Covert Sniffer:**
```bash
docker compose logs -f covert-detector
```

3. **Trigger covert exfiltration from the Victim:**
```bash
docker compose exec victim python attacks/icmp_exfiltrate.py --data "StolenToken"
```

* If detected, the sniffer outputs a `[DLP-ALERT]` log.
* If not blocked/mitigated, the Attacker terminal records the incoming stolen payload.

*Note: When updating `detection/covert_channel/sniffer.py`, restart the sniffer container with:*

```bash
docker compose restart covert-detector
```

## Local Development & Unit Tests (Offline)

You do **not** need to start Docker to develop and validate detection algorithms.

1. **Set up the virtual environment with all dependencies:**
```bash
uv sync
```

2. **Run test suites locally:**
```bash
uv run pytest
```

3. **Run a single test file:**
```bash
uv run pytest tests/test_l7_web.py
```

## Standardized Alert Format

All detection engines (`l7_web` and `covert_channel`) must log detections using `detection.common.logger.log_alert`:

```python
from detection.common.logger import log_alert

log_alert(
    channel="L7_WEB",          # "L7_WEB" | "DNS_COVERT" | "ICMP_COVERT"
    rule_id="KEYWORD_DETECTED",
    severity="HIGH",           # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    source_ip="172.20.0.3",
    destination="example.com",
    details={"match": "SECRET"},
    blocked=True               # True for inline drops (L7), False for passive alerts
)
```

This produces standard JSON lines prefixed with `[DLP-ALERT]` for automated parsing and evaluation metrics.