# L7 Web DLP Detection Mechanism

## 1. Introduction & Background

The L7 engine runs inside mitmproxy and scans every outbound HTTP(S) request for credit cards, API tokens, and high-entropy strings. If any rule fires, the request is logged and dropped with a 403.

mitmproxy terminates TLS with its own CA certificate. The victim container trusts this CA at build time, matching the enterprise setup where IT pushes a corporate CA to every laptop. For non-TLS traffic the pipeline is identical, minus the TLS step. The techniques themselves are standard: Luhn's checksum from 1954, regex patterns reused from *Gitleaks* and *Trufflehog*, Shannon entropy from 1948.

## 2. Threat Model

- **Attacker:** An insider or a compromised host inside the internal network `172.20.0.0/24`. The attacker wants to send credit card numbers, API keys or similar secrets to an external endpoint at `172.21.0.10`.
- **Evasion:** The attacker will not type `card=4111 1111 1111 1111` into a form if a simple keyword filter can catch it. More realistic payloads use URL-encoded separators (`4111%2D1111...`), hide the value deep inside a JSON object, or split it across HTTP header values.
- **Monitoring posture:** All traffic from the victim is routed through the gateway container. mitmproxy intercepts, decrypts and inspects every request before it reaches the outside world (and the attacker). If any detector produces a finding, the request never leaves the gateway.

## 3. Detection Architecture

```
                  +---------------------------------+
                  | Inbound HTTP(S) request via     |
                  | mitmproxy (MITM w/ trusted CA)  |
                  +---------------------------------+
                                 |
                                 v
             +---------------------------------------+
             | Stage 1: Collect scannable text       |
             | - URL path & query parameters         |
             | - Request body via decode_body()      |
             |   -> urlencoded / JSON / plain text   |
             +---------------------------------------+
                                 |
                                 v
             +---------------------------------------+
             | Stage 2: Multi-detector scan          |
             | scan_all() runs three detectors on    |
             | each decoded value:                   |
             | - regex_rules  (structured secrets)   |
             | - luhn         (credit-card numbers)  |
             | - entropy      (high-entropy tokens)  |
             +---------------------------------------+
                                 |
                                 v
             +---------------------------------------+
             | Stage 3: Decision & Alert             |
             | - Any Finding -> log_alert + 403      |
             | - Request never reaches the target    |
             +---------------------------------------+
```

The addon that drives this pipeline lives in `detection/l7_web/addon.py`. mitmproxy calls its `request()` hook on every outbound flow, before the request is forwarded.

### 3.1 Body decoding (`decode_body`)

mitmproxy hands us a `flow.request.content` field as raw bytes. A naive `bytes.decode()` on it is not enough for two realistic cases:

- An HTML form POST sends `card=4111%2D1111%2D1111%2D1111` where `%2D` is a URL-encoded dash. If we scan the raw bytes, the regex pre-filter breaks on `%` and sees only short digit runs, so the Luhn stage never gets to run.
- A JSON body like `{"user":{"payment":{"cc":"4111-1111-1111-1111"}}}` works by accident when the regex scans the raw string, but we have no idea in which field the value sat, and nested keys deeper than one level still get scanned as a flat blob.

`decode_body(content, content_type)` solves both. It looks at the `Content-Type` header (parameters like `; charset=utf-8` are stripped, casing is normalized), and then dispatches:

- `application/x-www-form-urlencoded` is parsed with `urllib.parse.parse_qs`, which decodes percent-escapes and returns a list of values. The function flattens that list so the detectors see one value at a time.
- `application/json` is parsed with `json.loads` and recursed through: dictionaries get walked on their values, lists get walked element by element, scalars (strings, numbers, booleans) are added to the result. `None` is dropped.
- Anything else, and anything that fails to parse (broken JSON, invalid bytes), falls back to a plain UTF-8 decode of the raw body. A broken request should never bring the gateway down.

*Multipart form data is out of scope.*

### 3.2 Structured credential detection (`regex_rules`)

Some secrets have fixed, well-known shapes. AWS access key IDs always start with `AKIA` and are followed by 16 uppercase letters or digits. JWTs look like `eyJ...eyJ....`. GitHub personal access tokens start with `ghp_`. For every one of these there is a tight regex that will match the real thing and almost nothing else.

The `regex_rules.RULES` list holds these patterns. Each rule has a `rule_id` (what shows up in the alert), a compiled `re.Pattern`, and a severity. The `scan()` function runs each pattern over the input text with `finditer` and emits a `Finding` for every match.

The concrete patterns were derived independently from documentation, blogs and other websites. These are kept in a central list rather than hardcoded per detector so that adding a new rule is a one-line change. This is even a easier change if we consider that its possible to copy directly regexes from projects such as *Gitleaks* and others, but we decided to derive some regexes by ourselves to prevent eventual licensing constraints from those projects. 

### 3.3 Credit-card detection (`luhn` + issuer prefix)

A 16-digit number that passes Luhn is not necessarily a credit card (about 10% of random 16-digit strings satisfy the checksum), so the pipeline has three stages:

- **Regex pre-filter:** `(?<!\d)(?:\d[ ._-]?){11,18}\d(?!\d)` 12 to 19 digits with optional space/dot/underscore/dash separators. Lookarounds prevent matches inside longer digit runs.
- **Luhn checksum:** Implementation from scratch following the Wikipedia description.
- **Issuer prefix and length:** candidates are checked against ~36 real issuers (Visa, Mastercard, Amex, Maestro, JCB, UnionPay, ...) by BIN prefix range and allowed lengths. Diogo added this stage after the FP rate on raw Luhn was too high.

If all three stages pass, the finding carries the matched substring, its offset in the body, the digit count, and the matched issuer name as metadata.

### 3.4 High-entropy tokens (`entropy`)

Not every secret has a known shape. Internal tokens, custom API keys, random session identifiers all look like base64 or hex strings of some length. Regex cannot match "a string of 32 characters with high entropy" because entropy is not a regular property.

The module exports a `shannon_entropy(text)` function that computes bits per character. The planned detector tokenizes the input and emits a Finding for every token with entropy over around 4.5 bits per char at length ≥ 20.

**Status:** `shannon_entropy` is implemented but the `scan()` function currently returns an empty list. The thresholds and the tokenization need to be tuned against the FPR benchmark before this detector is turned on. Covert channel detection (DNS workstream) also uses `shannon_entropy`, which is why the function is factored out.

### 3.5 Alerting and blocking (`addon.py`)

When `scan_all()` returns at least one finding, the addon logs a JSON alert through `detection.common.logger.log_alert()` *(channel `L7_WEB`, severity taken from the first finding, upper-cased, all matched substrings in `details`)* and sets `flow.response` to a 403. In mitmproxy's model, setting the response in the `request()` hook short-circuits the forward step: the request never reaches the target host, the client sees the 403 directly from the gateway.

## 4. Test Scenarios & Validation

Four scenarios cover the detectors end to end. The exact `curl` commands and expected outputs are in [demo_guide.md](demo_guide.md), under section 1.

- **Benign baseline:** `user=alice&status=ok`. Nothing to find. Verifies that normal form POSTs pass through with 200 OK and no alert.
- **Credit-card leak:** `card=4111-1111-1111-1111`. Hits the regex pre-filter, passes Luhn, matches Visa by prefix and length. Blocked, alert `luhn_cc`.
- **AWS key leak:** `token=AKIAIOSFODNN7EXAMPLE`. Caught by the `regex_rules` AWS pattern. Blocked, alert `AWS_ACCESS_KEY_ID`.
- **URL-encoded card leak:** `card=4111%2D1111%2D1111%2D1111`. Without the decoder, the pre-filter would miss this. With the decoder, the value is unescaped before scanning and the full pipeline runs normally.

In addition, the `tests/test_l7_web.py` unit test suite covers:

- Luhn edge cases *(invalid checksum, non-standard lengths, trivial `"0"`, Amex 15-digit, Mastercard 16-digit, Wikipedia's 11-digit example)*.
- Scan integration with mixed separators, multiple cards in one body, offset-correctness of the `Finding.start`/`end` fields.
- False-positive protection on long random digit runs, 20-digit opaque IDs, and short numbers that happen to satisfy Luhn.
- The decoder itself: content-type normalization, nested JSON walk, URL-encoded multi-values, broken bodies.

Quantitative FPR / TPR / latency results for these scenarios are in `evaluation/l7_web/REPORT.md` and the main `README.md` section 4.1.
