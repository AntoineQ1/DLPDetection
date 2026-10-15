# ICMP Covert-Channel Detection Mechanism

## 1. Introduction & Background

The Internet Control Message Protocol (ICMP) is traditionally used for operational feedback, routing failure reporting, and network diagnostics via Echo Request (Type 8) and Echo Reply (Type 0) packets. As ICMP is necessary for troubleshooting, perimeter firewalls and gateway security systems often leave it uninspected or permitted by default.

This operational tolerance makes ICMP a common medium for **covert channels**. Instead of using application-layer channels that may very well trigger proxy or WAF inspection, an attacker can embed exfiltrated data directly inside the payload field of standard Echo Requests.

The detection strategy implemented here is partially inspired by research from Sayadi et al. (*Detection of Covert Channels over ICMP Protocol*, AICCSA 2017). Their work highlights that benign OS-generated pings exhibit rigid structural characteristics (fixed payload lengths and deterministic padding bytes), and that malicious covert traffic typically deviates in size, payload structure, or transmission frequency. Building on these observations, we deployed a lightweight, passive detection pipeline which offers structural inspection, rate analysis, and content scanning.

---

## 2. Threat Model

- **Attacker Profile:** An insider threat or a compromised host located on the internal lab network (`172.20.0.0/24`) trying to exfiltrate confidential records (such as payment card data or API secrets) toward an external endpoint (`172.21.0.10`).
- **Evasion Strategy:** 
  * The attacker avoids standard Web/HTTP channels to bypass L7 gateway proxy controls.
  * The attacker injects data into raw ICMP Echo Request frames, either by sending large chunks (bulk exfiltration), splitting data into small custom packets, or flooding packets in rapid bursts to minimize dwell time.
- **Monitoring Posture:** All traffic originating from the victim host is routed through our central gateway, which acts as the perimeter barrier. While the gateway actively intercepts and proxies L7 web flows, it also hosts the covert detection engine listening on the inbound interface (`172.20.0.0/24`). This allows it to passively inspect ICMP frames on the fly and log alerts immediately as packets traverse the gateway, without introducing processing delays into standard network traffic.

## 3. Detection Architecture

Every captured packet is parsed by `parse_icmp_echo()`. If the packet is an ICMP Echo Request (Type 8), it is run through three successive checks:

```
                  +-----------------------------+
                  |   Inbound ICMP Packet       |
                  +-----------------------------+
                                 |
                     [ Type 8 Echo Request? ]
                                 | Yes
                                 v
             +---------------------------------------+
             | Stage 1: Structural Checks            |
             | - Payload size (> 64B or != 32/56B)   |
             | - Known benign payload validation     |
             +---------------------------------------+
                                 |
                                 v
             +---------------------------------------+
             | Stage 2: Deep Content Inspection      |
             | - Handled by the shared L7 engine     |
             +---------------------------------------+
                                 |
                                 v
             +---------------------------------------+
             | Stage 3: Rate Limiting & Tracking     |
             | - Sliding window per source IP        |
             +---------------------------------------+

```

### 3.1 Structural Inspection (`check_structure`)
Standard operating systems build predictable payloads:
- **Windows:** Exactly 32 bytes of ASCII padding (`abcdefghijklmnopqrstuvwabcdefghi`).
- **Linux:** Exactly 56 bytes total (an 8-byte kernel timestamp followed by fixed bytes `range(16, 56)`).

To avoid unnecessary alerts, any packet matching these exact byte layouts is immediately flagged as clean via `is_known_benign_payload()`. For everything else, the engine applies three structural rules:

1. **`icmp_oversized_payload` (Severity: HIGH):** Flags any Echo payload strictly larger than 64 bytes (`MAX_STANDARD_PAYLOAD_SIZE`). Standard pings rarely exceed this threshold unless an operator manually overrides the sizes.
2. **`icmp_non_standard_size` (Severity: MEDIUM):** Flags payloads that do not match the expected 32 or 56-byte standards.
3. **`icmp_abnormal_pattern` (Severity: MEDIUM):** Catches evasion attempts where the attacker sizes the payload to exactly 32 or 56 bytes to look benign, but fills the buffer with custom bytes for exfiltration, instead of the expected OS pattern.

### 3.2 Deep Content Inspection (`check_content`)
If an ICMP packet contains arbitrary text data, we delegate string inspection to the shared L7 inspection engine developed in the parallel L7 workstream (`detection.l7_web.scan_all`). 

The payload is evaluated against the existing rules and algorithms (such as the Luhn algorithm for credit card numbers or patterns matching cloud credentials). When a match occurs, the sniffer raises an alert (`icmp_sensitive_data_<rule_id>`) detailing the matched pattern and detector type.

### 3.3 Behavioral Rate Limiting (`ICMPRateTracker`)
Human diagnostic usage rarely exceeds 1 packet per second under standard tool defaults. Attackers moving data over ICMP often increase transmission rates to maximize throughput.

We track packet timestamps per source IP using a sliding time window (`collections.deque`):
- **Window:** `1.0` second (`DEFAULT_WINDOW_SECONDS`).
- **Threshold:** `4` requests per window (`DEFAULT_MAX_REQUESTS_PER_WINDOW`).

If an internal IP dispatches more than 4 Echo Requests within a single 1-second interval, the engine generates an `icmp_high_frequency` alert with the current packet count and window metrics.

## 4. Test Scenarios & Validation

To validate each detection heuristic against real traffic, we developed a dedicated test harness (`attacks/icmp_exfiltrate.py`). It covers four key test scenarios:

- **Benign Baseline:** Standard system ping generating 56-byte Linux packets to verify the absence of false positives.
- **Oversized Bulk Exfiltration (`--mode oversized`):** Sends single frames exceeding the standard 64-byte threshold to validate the structural detection engine (`icmp_oversized_payload`).
- **Sensitive Cleartext Leak (`--mode sensitive`):** Transmits financial identifiers (credit card numbers) inside the payload to verify integration with the shared L7 DLP rules (`icmp_sensitive_data_*`).
- **High-Frequency Burst (`--mode burst`):** Emits rapid bursts (6 packets with a 50 ms interval) using benign padding to validate the sliding-window rate tracker (`icmp_high_frequency`).

> **Note:** For the step-by-step reproduction instructions, for the exact commands, and finally the expected JSON alert outputs, don't hesitate to refer to the **Live Demo Cheatsheet** (`demo_guide.md`, cf. Section 2).