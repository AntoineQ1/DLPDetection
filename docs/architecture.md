# System Architecture & Network Design

This document details the network setup, container routing, and traffic interception mechanisms used by the DLP Gateway.


## 1. Overview

The gateway simulates an enterprise perimeter to test both web-based leaks and covert channel exfiltration:

- **Inline L7 Proxy (`mitmproxy`):** Intercepts outbound HTTP/HTTPS synchronously. Requests matching DLP rules (sensitive data, credit card numbers, tokens) are dropped with an HTTP 403 before leaving the network.
- **Passive L3/L4 Sniffer (`Scapy`):** Captures ICMP Echo and DNS traffic asynchronously on the internal interface. It inspects packet headers, payload structure, entropy, and query rates without slowing down forwarded traffic.


## 2. Network Topology

The lab uses two Docker bridge networks to isolate zones:

| Network | Subnet | Gateway IP | Role |
|---|---|---|---|
| `internal_net` | `172.20.0.0/24` | `172.20.0.2` | Internal corporate network (Victim host) |
| `external_net` | `172.21.0.0/24` | `172.21.0.2` | External network (Attacker C2 sinks) |

The gateway is dual-homed and acts as the default gateway for the internal subnet:

```text
+-----------------------------------------------------------------------------------+
| INTERNAL NETWORK: internal_net (172.20.0.0/24)                                    |
|                                                                                   |
|   +--------------------------+                                                    |
|   |      Victim Host         |                                                    |
|   |      (172.20.0.3)        |                                                    |
|   | Default Route -> Gateway |                                                    |
|   +------------+-------------+                                                    |
+----------------|------------------------------------------------------------------+
                 |
                 | Egress Traffic
                 v
+-----------------------------------------------------------------------------------+
| GATEWAY HOST (Shared Network Namespace)                                           |
|                                                                                   |
|   [ Inbound NIC: 172.20.0.2 ]                                                     |
|          |                                                                        |
|          +--- [ ICMP / UDP:53 ] -----------------------------------+              |
|          |                                                         |              |
|          |                                            +------------v------------+ |
|          |                                            | Covert Sniffer (Scapy)  | |
|          |                                            |  - DNS                  | |
|          |                                            |  - ICMP                 | |
|          |                                            +------------+------------+ |
|          |                                                         |              |
|          v                                                         v              |
|   [ iptables PREROUTING ]                                  Log and/or Block       |
|          |                                                                        |
|          +---> TCP 80/443 --[ REDIRECT :8080 ]------> +-------------------------+ |
|          |                                            |   mitmproxy (Inline)    | |
|          |                                            |      Web DLP Addon      | |
|          |                                            +------------+------------+ |
|          |                                                         |              |
|          | [ Other traffic ]                                       v              |
|          v                                                 Log and/or Block       |
|   [ iptables POSTROUTING: MASQUERADE ]                             |              |
|          |                                                         | (Allowed)    |
|          +----------------------------+----------------------------+              |
|                                       |                                           |
|   [ Outbound NIC: 172.21.0.2 ]        |                                           |
+---------------------------------------|-------------------------------------------+
                                        |
+---------------------------------------|-------------------------------------------+
| EXTERNAL NETWORK: external_net (172.21.0.0/24)                                    |
|                                       |                                           |
|                                       v                                           |
|                        +------------------------------+                           |
|                        |        Attacker Sinks        |                           |
|                        |        (172.21.0.10)         |                           |
|                        |  - HTTP Sink      (:80)      |                           |
|                        |  - DNS Sink       (:53)      |                           |
|                        |  - ICMP Echo Sink (Listener) |                           |
|                        +------------------------------+                           |
+-----------------------------------------------------------------------------------+

```


## 3. Containers & Docker Setup

### Container Roles

| Container | Service | Network | Main Process |
| --- | --- | --- | --- |
| `dlp-victim` | `victim` | `internal_net` | Data exfiltration scripts and commands |
| `dlp-gateway` | `gateway` | `internal_net`, `external_net` | `mitmproxy` |
| `dlp-covert-detector` | `covert-detector` | `service:gateway` *(shared)* | Scapy sniffer (`sniffer.py`) |
| `dlp-attacker` | `attacker` | `external_net` | Python listeners (HTTP, DNS, ICMP) |

### Shared Network Namespace

The covert channel detector runs in its own container but shares the gateway network stack using `network_mode: "service:gateway"`.

This keeps `mitmproxy` and the Scapy sniffer in separate containers (easier to restart or debug independently) while giving the sniffer direct access to the gateway interfaces.

### Required Capabilities & Sysctls

- **`cap_add: [NET_ADMIN, NET_RAW]`:** Used on the gateway and sniffer to configure `iptables` rules, change routes, and open raw sockets. The victim also needs `NET_ADMIN` to update its default route.
- **`net.ipv4.ip_forward = 1`:** Enables packet forwarding across the two interfaces.
- **`net.ipv4.conf.all.send_redirects = 0`:** Disables ICMP redirects so internal traffic always passes through the gateway.
- **Volume Mounts (`:ro`):** Code directories (`./detection`, `./tests`, `./attacks`) are mounted read-only for fast iteration during testing without having to rebuild images.


## 4. Routing & Traffic Interception

### Client Routing (`victim-entrypoint.sh`)

By default, Docker routes container traffic to the bridge host. At startup, the victim container replaces its default route:

```bash
ip route replace default via 172.20.0.2
```

All egress traffic is redirected through the gateway.

### Gateway NAT & Redirection (`gateway-entrypoint.sh`)

The gateway configures basic `iptables` rules:

1. **HTTP/HTTPS Redirection:**

```bash
iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080
iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8080
```

Outbound web traffic is sent to `mitmdump` listening on port 8080.

2. **Outbound MASQUERADE:**

```bash
iptables -t nat -A POSTROUTING -j MASQUERADE
```

Non-HTTP traffic is NATed so external targets can reply.

### Pre-NAT Packet Capture

The sniffer (`sniffer.py`) listens on the internal interface (`172.20.0.2`) with the following filter:

```text
icmp or udp port 53
```

### HTTPS Interception (CA Setup)

To inspect HTTPS without client errors:

1. `./config/certs/generate_ca.sh` creates a local root CA (`mitmproxy-ca-cert.crt`).
2. `mitmproxy` uses this CA to generate leaf certificates dynamically.
3. The victim container installs this root cert in `/usr/local/share/ca-certificates/` and sets `REQUESTS_CA_BUNDLE` and `SSL_CERT_FILE` so curl and Python scripts trust intercepted connections.


## 5. Detection Pipelines

### Web L7 Pipeline (`detection/l7_web`)

For HTTP traffic handled by `mitmproxy`:

1. `addon.py` hooks incoming requests before forwarding.
2. `decoder.py` parses headers, query parameters, form fields, and JSON bodies.
3. `scan_all()` runs three detectors:
    - `regex_rules.py`: matches known patterns (API keys, secrets).
    - `luhn.py`: detects credit card numbers and checks validity with Luhn algorithm.
    - `entropy.py`: detects high-entropy strings (tokens, private keys).


4. If a rule triggers, `log_alert()` records the event and the proxy returns a `403 Forbidden`.

### Covert Channel Pipeline (`detection/covert_channel`)

1. `sniffer.py` captures packets via Scapy and routes them by protocol:
* **ICMP (`icmp_detector.py`):** Checks payload size, compares patterns against standard OS pings (Windows/Linux), tracks packet rate per source IP, and scans payload content with the shared L7 engine.
* **DNS (`dns_detector.py`):** Checks query length, subdomain entropy, payload patterns, and query volume per apex domain.


2. Both modules share common utilities (`scan_all`, `shannon_entropy`).

For detailed rules and thresholds, see:

* `docs/icmp-detection-mechanism.md`
* `docs/dns-detection-mechanism.md`


## 6. Alert Format & Logging

All detectors use a common JSON alert format (`detection.common.logger.log_alert`):

```json
[DLP-ALERT] {
  "timestamp": 1790333178.47,
  "channel": "L7_WEB | covert_icmp | DNS_COVERT",
  "rule_id": "RULE_IDENTIFIER",
  "severity": "low | medium | high | critical",
  "source_ip": "172.20.0.3",
  "destination": "172.21.0.10",
  "blocked": true,
  "details": { ... }
}

```

The attacker container runs simple sink servers (`servers/http_sink.py`, `servers/dns_sink.py`, `servers/icmp_sink.py`). Comparing data received by the sinks against `[DLP-ALERT]` logs makes it straightforward to verify detection accuracy and false positive rates.