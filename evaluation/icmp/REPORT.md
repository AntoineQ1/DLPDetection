# ICMP detector evaluation

Malicious traffic: packets built by the documented [`icmp.py` covert-channel tool](https://github.com/Smendowski/hidden-communication-using-covert-channels/blob/main/icmp.py) by Smendowski et al., using 100 distinct seeded dummy files and source IPs, one transfer per session. Tool SHA-256: `6a1afd034959323e24164f1cb717a8746854776d1da9f28cdddf31420895eb90`. Benign traffic: 100 locally generated Linux/Windows/default and custom diagnostic Echo sessions, with three requests per session.

## Tool relevance and research connection

The selected project code fragments a file, base64-encodes its chunks, adds
sequence and file-identification fields, and builds ICMP Echo Requests. This
directly tests the detector's handling of payload-bearing ICMP diagnostics.
Its documented packet builder permits distinct, reproducible offline transfer
sessions. The source is a project repository with implementation notes; we
found no peer-reviewed publication directly tied to this exact tool.

[Tu et al., *Computers, Materials & Continua* 71(2) (2022), 2315–2331](https://doi.org/10.32604/cmc.2022.022540)
study ICMP covert tunnels and generate samples with icmptunnel, ptunnel, and
icmpsh. The paper establishes the relevance of malicious ICMP payload traffic
as a detection target, but does not evaluate Smendowski et al.'s implementation
or validate this detector's scores. Testing those additional, paper-used tools
would broaden the evidence beyond the current single-tool result.

## Method

Offline packet replay through the production packet parser and detector functions. Each class has fresh detector state. A session is one source/destination flow (also grouped by apex for DNS), split after more than 60 seconds of inactivity. A session is detected if any of its packets emits an alert. `sessions.csv` is the primary evaluation; `results.csv` retains packet-level diagnostics and messages. This tests alerting, not live capture or blocking.

## Session-level results

| Metric | Count / value |
| --- | ---: |
| Benign sessions | 100 |
| Malicious sessions | 100 |
| Detected malicious sessions | 100 |
| Missed malicious sessions | 0 |
| Flagged benign sessions | 30 |
| Unflagged benign sessions | 70 |
| Benign session alert rate | 30.0% |
| Malicious session detection rate | 100.0% |

### By session scenario

| Scenario | TP | FN | FP | TN |
| --- | ---: | ---: | ---: | ---: |
| custom_120_byte_ping | 0 | 0 | 10 | 0 |
| custom_32_byte_ping | 0 | 0 | 20 | 0 |
| external_icmp_file_transfer | 100 | 0 | 0 | 0 |
| linux_default_ping | 0 | 0 | 0 | 40 |
| windows_default_ping | 0 | 0 | 0 | 30 |

## Packet-level diagnostics

A packet without an alert is not a missed session when another packet in the same session alerted. The packet `outcome` column describes individual alert emission only.

| Metric | Count / value |
| --- | ---: |
| Benign samples | 300 |
| Malicious samples | 180 |
| True positives | 180 |
| False negatives | 0 |
| False positives | 90 |
| True negatives | 210 |
| Benign packet alert rate | 30.0% |
| Malicious packet alert rate | 100.0% |

### By scenario

| Scenario | TP | FN | FP | TN |
| --- | ---: | ---: | ---: | ---: |
| custom_120_byte_ping | 0 | 0 | 30 | 0 |
| custom_32_byte_ping | 0 | 0 | 60 | 0 |
| external_icmp_file_transfer | 180 | 0 | 0 | 0 |
| linux_default_ping | 0 | 0 | 0 | 120 |
| windows_default_ping | 0 | 0 | 0 | 90 |

### Rules fired

| Rule | Findings |
| --- | ---: |
| icmp_oversized_payload | 210 |
| icmp_sensitive_data_high_entropy | 180 |
| icmp_abnormal_pattern | 60 |

## Review packet examples

### Flagged benign packets

- `icmp-0022` (custom_32_byte_ping): `icmp_abnormal_pattern`
- `icmp-0023` (custom_32_byte_ping): `icmp_abnormal_pattern`
- `icmp-0024` (custom_32_byte_ping): `icmp_abnormal_pattern`
- `icmp-0025` (custom_32_byte_ping): `icmp_abnormal_pattern`
- `icmp-0026` (custom_32_byte_ping): `icmp_abnormal_pattern`

### Malicious packets without an alert

- None in this sample.

## Interpretation

The external tool produced 100 distinct dummy-file transfers, each with its own source and file content. Its packet payloads exceed the 64-byte structure threshold, so `icmp_oversized_payload` catches these transfers. This establishes detection for this tool's packet construction, not for all ICMP tunnels.

The 30 false-positive sessions are legitimate custom Echo payloads: 20 at 32 bytes trigger `icmp_abnormal_pattern` and ten at 120 bytes trigger `icmp_oversized_payload`. Default Linux and Windows ping examples produce no alerts. The benign traffic is synthetic, so the alert rates apply only to this scenario mix.

The current local ICMP test suite also has a failing case, `test_whitelisted_linux_ping_prefix_is_still_inspected`: a 56-byte payload with an encoded card in the first 16 bytes and the Linux tail produces no alert. This is a separate false-negative vector from the external tool's default large-packet output.

## Limits

The replay calls the production parser and detector on packets, but does not exercise live sniffing, dropped packets, routing, gateway logs, or blocking. The benign traffic is synthetic and the malicious traffic comes from one tool per protocol; broader traffic sources and more tools are needed before estimating field precision or recall.
