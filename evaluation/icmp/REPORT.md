# ICMP detector evaluation

Malicious traffic comes from two real tools, sampled with a fixed seed. [DhavalKapil/icmptunnel](https://github.com/DhavalKapil/icmptunnel) `send_icmp_packet`, source commit `267a9ec7af03bf05f467d94550f15a969bfb8611`: 50 raw transfers drawn by stratified random sampling across oversized / tiny / burst / cleartext-secret profiles (random sizes, packet counts, send cadence, and dummy tokens). Input PCAP SHA-256: `cc1ab06a4ff270ac78ae982dcd9b7cbd44886d23b6794b71f73719612a55ea47`. [Smendowski et al.'s covert-channel tool](https://github.com/Smendowski/hidden-communication-using-covert-channels), vendored as `external_icmp.py` (`vendored-sha256:6a1afd034959323e24164f1cb717a8746854776d1da9f28cdddf31420895eb90`): 50 base64 transfers with random file sizes. Input PCAP SHA-256: `48b09ef168ba04fadf79b5fab7e2b380c33a0dee963a20c708023c400cad6ab6`. Each transfer has a distinct input and source IP. Benign traffic: 100 locally generated Linux/Windows/default and random custom-size Echo sessions, with a random number of requests per session.

## Tool relevance and research connection

The detector inspects ICMP payloads three ways -- structure (size / pattern), rate (per-source frequency), and content (regex, Luhn, Shannon entropy) -- so the evaluation uses **two** real tools, driven across several input profiles, to reach every path. [DhavalKapil/icmptunnel](https://github.com/DhavalKapil/icmptunnel) frames raw IPv4/UDP data inside ICMP Echo Requests; fed different inputs and cadences it produces oversized payloads (`icmp_oversized_payload`), tiny payloads (`icmp_non_standard_size`), sub-second bursts (`icmp_high_frequency`), and cleartext dummy secrets that its raw framing leaves readable (`luhn_cc` and the API-token regexes). [Smendowski et al.'s covert-channel tool](https://github.com/Smendowski/hidden-communication-using-covert-channels) **base64-encodes** each file chunk, placing a high-entropy ASCII token in the payload -- the `icmp_sensitive_data_high_entropy` signal raw binary never forms, because the content scan's UTF-8 decode drops non-ASCII bytes.

The [ICMPTend paper](https://doi.org/10.32604/cmc.2022.022540) describes an ICMP covert-tunnel **detector**, not an attack generator, and names icmptunnel, ptunnel, and icmpsh among its sample sources; it does not publish the exact repository, version, or capture, so this is not a replication of its dataset or detector. The base64-over-ICMP technique is itself documented by purpose-built data-exfiltration test tools such as [PyExfil](https://github.com/ytisf/PyExfil) (whose ICMP module base64-encodes files for DLP testing) and [SensePost's DET](https://github.com/sensepost/DET); these are cited as evidence that the technique is real, not run here (PyExfil's ICMP module is Python 2 / impacket and not offline-runnable unmodified).

Both bundled PCAPs were built offline by the tools' own packet builders with no socket opened: icmptunnel's C `send_icmp_packet` with `sendto` intercepted, and Smendowski's scapy `create_icmp_payload` whose packets are written straight to a PCAP. Distinct seeded dummy files were used per transfer. No live tunnel, packet transmission, or receiving endpoint was exercised.

## Method

Offline packet replay through the production packet parser and detector functions. Each class has fresh detector state. A session is one source/destination flow (also grouped by apex for DNS), split after more than 60 seconds of inactivity. A session is detected if any of its packets emits an alert. `sessions.csv` is the primary evaluation; `results.csv` retains packet-level diagnostics and messages. This tests alerting, not live capture or blocking.

## Session-level results

| Metric | Count / value |
| --- | ---: |
| Benign sessions | 100 |
| Malicious sessions | 100 |
| Detected malicious sessions | 100 |
| Missed malicious sessions | 0 |
| Flagged benign sessions | 27 |
| Unflagged benign sessions | 73 |
| Benign session alert rate | 27.0% |
| Malicious session detection rate | 100.0% |

### By session scenario

| Scenario | TP | FN | FP | TN |
| --- | ---: | ---: | ---: | ---: |
| custom_100_byte_ping | 0 | 0 | 7 | 0 |
| custom_120_byte_ping | 0 | 0 | 6 | 0 |
| custom_32_byte_ping | 0 | 0 | 3 | 0 |
| custom_48_byte_ping | 0 | 0 | 1 | 0 |
| custom_56_byte_ping | 0 | 0 | 7 | 0 |
| custom_64_byte_ping | 0 | 0 | 3 | 0 |
| icmptunnel_burst | 10 | 0 | 0 | 0 |
| icmptunnel_oversized | 20 | 0 | 0 | 0 |
| icmptunnel_secret | 10 | 0 | 0 | 0 |
| icmptunnel_tiny | 10 | 0 | 0 | 0 |
| linux_default_ping | 0 | 0 | 0 | 38 |
| smendowski_base64_exfil | 50 | 0 | 0 | 0 |
| windows_default_ping | 0 | 0 | 0 | 35 |

## Packet-level diagnostics

A packet without an alert is not a missed session when another packet in the same session alerted. The packet `outcome` column describes individual alert emission only.

| Metric | Count / value |
| --- | ---: |
| Benign samples | 315 |
| Malicious samples | 200 |
| True positives | 200 |
| False negatives | 0 |
| False positives | 85 |
| True negatives | 230 |
| Benign packet alert rate | 27.0% |
| Malicious packet alert rate | 100.0% |

### By scenario

| Scenario | TP | FN | FP | TN |
| --- | ---: | ---: | ---: | ---: |
| custom_100_byte_ping | 0 | 0 | 21 | 0 |
| custom_120_byte_ping | 0 | 0 | 18 | 0 |
| custom_32_byte_ping | 0 | 0 | 7 | 0 |
| custom_48_byte_ping | 0 | 0 | 2 | 0 |
| custom_56_byte_ping | 0 | 0 | 24 | 0 |
| custom_64_byte_ping | 0 | 0 | 13 | 0 |
| icmptunnel_burst | 73 | 0 | 0 | 0 |
| icmptunnel_oversized | 57 | 0 | 0 | 0 |
| icmptunnel_secret | 10 | 0 | 0 | 0 |
| icmptunnel_tiny | 10 | 0 | 0 | 0 |
| linux_default_ping | 0 | 0 | 0 | 128 |
| smendowski_base64_exfil | 50 | 0 | 0 | 0 |
| windows_default_ping | 0 | 0 | 0 | 102 |

### Rules fired

| Rule | Findings |
| --- | ---: |
| icmp_oversized_payload | 229 |
| icmp_sensitive_data_high_entropy | 57 |
| icmp_high_frequency | 33 |
| icmp_abnormal_pattern | 31 |
| icmp_non_standard_size | 25 |
| icmp_sensitive_data_luhn_cc | 10 |
| icmp_sensitive_data_Stripe key | 3 |
| icmp_sensitive_data_AWS Token | 3 |
| icmp_sensitive_data_Google Cloud API Key | 2 |
| icmp_sensitive_data_GitHub Token | 2 |

## Review packet examples

### Flagged benign packets

- `icmp-0011` (custom_100_byte_ping): `icmp_oversized_payload`
- `icmp-0012` (custom_100_byte_ping): `icmp_oversized_payload`
- `icmp-0013` (custom_100_byte_ping): `icmp_oversized_payload`
- `icmp-0014` (custom_100_byte_ping): `icmp_oversized_payload`
- `icmp-0015` (custom_100_byte_ping): `icmp_oversized_payload`

### Malicious packets without an alert

- None in this sample.

## Interpretation

The two tools produced 100 distinct offline transfer sessions (stratified random sampling: each run drawn from a profile, with sizes, packet counts, send cadence, and secret tokens sampled from fixed seeded distributions). Every malicious session is detected, and together the profiles exercise all three detection paths. Structure: icmptunnel's raw payloads trip `icmp_oversized_payload`, its tiny payloads trip `icmp_non_standard_size`. Rate: its burst profile exceeds the per-second threshold and trips `icmp_high_frequency`. Content: Smendowski's base64 payloads trip `icmp_sensitive_data_high_entropy` (a high-entropy ASCII token raw binary never forms), and icmptunnel's cleartext-secret profile trips `luhn_cc` and the API-token regexes. This establishes detection across the structure, rate, and content paths, not detection of all ICMP tunnels.

The 27 false-positive sessions are legitimate custom Echo payloads: standard-size (32/56 B) pings with altered content trip `icmp_abnormal_pattern`, non-standard sizes (48/64 B) trip `icmp_non_standard_size`, and larger diagnostics (100/120 B) trip `icmp_oversized_payload` -- see the benign rows of the session scenario table. Default Linux and Windows pings produce no alerts. The benign traffic is synthetic, so the alert rates apply only to this scenario mix.

The current local ICMP test suite also has a failing case, `test_whitelisted_linux_ping_prefix_is_still_inspected`: a 56-byte payload with an encoded card in the first 16 bytes and the Linux tail produces no alert. This is a separate false-negative vector from the large-packet output of either tool.

## Limits

The replay calls the production parser and detector on packets, but does not exercise live sniffing, dropped packets, routing, gateway logs, or blocking. The benign traffic is synthetic and the malicious traffic comes from one tool per protocol; broader traffic sources and more tools are needed before estimating field precision or recall.

