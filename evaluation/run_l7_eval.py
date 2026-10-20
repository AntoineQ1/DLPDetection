"""Offline L7 session evaluation: pushes 14 malicious + 10 benign scenarios through decode_body + scan_all."""

import csv
import gzip
import statistics
import time
from pathlib import Path
from typing import NamedTuple

from detection.l7_web import scan_all
from detection.l7_web.decoder import decode_body

OUTPUT_DIR = Path(__file__).resolve().parent / "l7_web"

REQUEST_FIELDS = [
    "id",
    "session_id",
    "label",
    "source",
    "scenario",
    "content_type",
    "payload_preview",
    "detected",
    "outcome",
    "rule_ids",
    "detector_message",
    "latency_us_median",
    "latency_us_p95",
]
SESSION_FIELDS = [
    "session_id",
    "label",
    "source",
    "scenario",
    "request_count",
    "alerted_request_count",
    "detected",
    "outcome",
    "rule_ids",
    "payload_preview",
    "detector_message",
    "total_latency_us_median",
]

LATENCY_ITERATIONS = 100
PREVIEW_CHARS = 60


# Payload corpus

class Request(NamedTuple):
    content: bytes
    content_type: str

class Scenario(NamedTuple):
    session_id: str
    label: str
    source: str
    scenario: str
    requests: list


def gzip_payload(secret: bytes) -> bytes:
    return gzip.compress(secret)


def zwsp_card(digits: str) -> bytes:
    return ("card=" + "\u200b".join(digits)).encode("utf-8")


MALICIOUS: list[Scenario] = [
    # credit cards
    Scenario(
        "mal_visa_plain", "malicious", "handcrafted", "visa_plain",
        [Request(b"card=4111111111111111", "application/x-www-form-urlencoded")],
    ),
    Scenario(
        "mal_visa_dashed", "malicious", "handcrafted", "visa_dashed",
        [Request(b"card=4111-1111-1111-1111", "application/x-www-form-urlencoded")],
    ),
    Scenario(
        "mal_visa_url_encoded_dashes", "malicious", "handcrafted", "visa_url_encoded_dashes",
        [Request(b"card=4111%2D1111%2D1111%2D1111", "application/x-www-form-urlencoded")],
    ),
    Scenario(
        "mal_mastercard", "malicious", "handcrafted", "mastercard_plain",
        [Request(b"card=5555555555554444", "application/x-www-form-urlencoded")],
    ),
    Scenario(
        "mal_amex_15_digits", "malicious", "handcrafted", "amex_15_digits",
        [Request(b"card=378282246310005", "application/x-www-form-urlencoded")],
    ),
    Scenario(
        "mal_visa_nested_json", "malicious", "handcrafted", "visa_nested_json",
        [Request(b'{"user":{"payment":{"cc":"4111-1111-1111-1111"}}}', "application/json")],
    ),
    Scenario(
        "mal_visa_zwsp", "malicious", "handcrafted", "visa_with_zero_width_spaces",
        [Request(zwsp_card("4111111111111111"), "application/x-www-form-urlencoded")],
    ),
    # API keys / tokens
    Scenario(
        "mal_aws_access_key", "malicious", "handcrafted", "aws_access_key",
        [Request(b"token=AKIAIOSFODNN7EXAMPLE", "application/x-www-form-urlencoded")],
    ),
    Scenario(
        "mal_github_token", "malicious", "handcrafted", "github_token",
        [Request(b"token=ghp_" + b"A" * 36, "application/x-www-form-urlencoded")],
    ),
    Scenario(
        "mal_openai_user_key", "malicious", "handcrafted", "openai_user_key",
        [Request(b"key=sk-" + b"A" * 48, "application/x-www-form-urlencoded")],
    ),
    Scenario(
        "mal_jwt_token", "malicious", "handcrafted", "jwt_token",
        [Request(b"token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijk",
                 "application/x-www-form-urlencoded")],
    ),
    Scenario(
        "mal_stripe_test_key", "malicious", "handcrafted", "stripe_test_key",
        [Request(b"key=sk_test_" + b"a1b2c3d4e5f6g7h8", "application/x-www-form-urlencoded")],
    ),
    # web exfiltration via gzip compression
    Scenario(
        "mal_visa_gzipped", "malicious", "handcrafted", "visa_gzipped",
        [Request(gzip_payload(b"4111111111111111"), "text/plain")],
    ),
    # multi-request chunking
    Scenario(
        "mal_visa_chunked", "malicious", "handcrafted", "visa_multi_request_chunking",
        [
            Request(b"card=41111111", "application/x-www-form-urlencoded"),
            Request(b"card=11111111", "application/x-www-form-urlencoded"),
        ],
    ),
]


BENIGN: list[Scenario] = [
    Scenario(
        "ben_normal_form", "benign", "handcrafted", "normal_form_submission",
        [Request(b"user=alice&status=ok", "application/x-www-form-urlencoded")],
    ),
    Scenario(
        "ben_tracking_number", "benign", "handcrafted", "ups_tracking_number",
        [Request(b"tracking=1Z999AA10123456784", "application/x-www-form-urlencoded")],
    ),
    Scenario(
        "ben_random_16digit_id", "benign", "handcrafted", "random_16digit_order_id",
        [Request(b"order=1234567890123456", "application/x-www-form-urlencoded")],
    ),
    Scenario(
        "ben_uuid", "benign", "handcrafted", "uuid_in_query",
        [Request(b"id=550e8400-e29b-41d4-a716-446655440000", "application/x-www-form-urlencoded")],
    ),
    Scenario(
        "ben_sha256_hash", "benign", "handcrafted", "sha256_hex_hash",
        [Request(b"hash=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                 "application/x-www-form-urlencoded")],
    ),
    Scenario(
        "ben_ipv4_addresses", "benign", "handcrafted", "ipv4_addresses_in_body",
        [Request(b"src=172.20.0.3&dst=10.0.0.1", "application/x-www-form-urlencoded")],
    ),
    Scenario(
        "ben_price_qty", "benign", "handcrafted", "ecommerce_price_qty",
        [Request(b"qty=42&price=1999", "application/x-www-form-urlencoded")],
    ),
    Scenario(
        "ben_json_api_response", "benign", "handcrafted", "normal_json_api_response",
        [Request(b'{"status":"ok","count":42,"version":"1.2.3"}', "application/json")],
    ),
    Scenario(
        "ben_email_in_form", "benign", "handcrafted", "email_in_form",
        [Request(b"email=alice@example.com&name=Alice", "application/x-www-form-urlencoded")],
    ),
    Scenario(
        "ben_lorem_ipsum", "benign", "handcrafted", "lorem_ipsum_plain_text",
        [Request(b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. "
                 b"Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.",
                 "text/plain")],
    ),
]


# scan helpers

def scan_request(req: Request):
    findings = []
    for value in decode_body(req.content, req.content_type):
        findings.extend(scan_all(value))
    return findings


def measure_latency_us(req: Request, iterations: int) -> tuple[int, int]:
    times: list[float] = []
    for _ in range(iterations):
        start = time.perf_counter_ns()
        for value in decode_body(req.content, req.content_type):
            scan_all(value)
        times.append((time.perf_counter_ns() - start) / 1000)
    median = int(statistics.median(times))
    if len(times) >= 20:
        p95 = int(statistics.quantiles(times, n=20)[18])
    else:
        p95 = int(max(times))
    return median, p95


def classify(label: str, detected: bool) -> str:
    if label == "malicious":
        if detected:
            return "TP"
        else:
            return "FN"
    else:
        if detected:
            return "FP"
        else:
            return "TN"


def preview(content: bytes) -> str:
    text = content.decode("utf-8", errors="replace")
    text = text.replace("\n", " ").replace("\r", " ")

    if len(text) > PREVIEW_CHARS:
        return text[:PREVIEW_CHARS] + "..."
    else:
        return text


def summarize(findings) -> str:
    if not findings:
        return ""
    else:
        return " | ".join(f"{f.rule_id}:{str(f.matched)[:20]}" for f in findings[:3])


def run_scenario(scenario: Scenario) -> tuple[list[dict], dict]:
    request_rows: list[dict] = []
    session_findings = []
    session_latency_sum = 0
    for idx, req in enumerate(scenario.requests, start=1):
        findings = scan_request(req)
        median_us, p95_us = measure_latency_us(req, LATENCY_ITERATIONS)
        detected = bool(findings)
        request_rows.append({
            "id": f"{scenario.session_id}_req{idx}",
            "session_id": scenario.session_id,
            "label": scenario.label,
            "source": scenario.source,
            "scenario": scenario.scenario,
            "content_type": req.content_type,
            "payload_preview": preview(req.content),
            "detected": detected,
            "outcome": classify(scenario.label, detected),
            "rule_ids": "|".join(sorted({f.rule_id for f in findings})),
            "detector_message": summarize(findings),
            "latency_us_median": median_us,
            "latency_us_p95": p95_us,
        })
        session_findings.extend(findings)
        session_latency_sum += median_us
    session_detected = bool(session_findings)
    session_row = {
        "session_id": scenario.session_id,
        "label": scenario.label,
        "source": scenario.source,
        "scenario": scenario.scenario,
        "request_count": len(scenario.requests),
        "alerted_request_count": sum(1 for r in request_rows if r["detected"]),
        "detected": session_detected,
        "outcome": classify(scenario.label, session_detected),
        "rule_ids": "|".join(sorted({f.rule_id for f in session_findings})),
        "payload_preview": preview(scenario.requests[0].content),
        "detector_message": summarize(session_findings),
        "total_latency_us_median": session_latency_sum,
    }
    return request_rows, session_row


# output writers

def write_csv(path: Path, fields: list[str], rows: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def write_report(path: Path, sessions: list[dict], requests: list[dict]) -> None:
    tp = sum(1 for s in sessions if s["outcome"] == "TP")
    fn = sum(1 for s in sessions if s["outcome"] == "FN")
    fp = sum(1 for s in sessions if s["outcome"] == "FP")
    tn = sum(1 for s in sessions if s["outcome"] == "TN")
    malicious_total = tp + fn
    benign_total = fp + tn

    if malicious_total:
        tpr = (tp / malicious_total * 100)
    else:
        tpr = 0.0

    if benign_total:
        fpr = (fp / benign_total * 100)
    else:
        fpr = 0.0

    for r in requests:
        if r["latency_us_median"] is None or r["latency_us_p95"] is None:
            raise ValueError(f"Missing latency for request {r['id']}")

    latencies_us = [r["latency_us_median"] for r in requests]
    median_us = int(statistics.median(latencies_us))
    if len(latencies_us) >= 20:
        p95_us = int(statistics.quantiles(latencies_us, n=20)[18])
    else:
        p95_us = int(max(latencies_us))

    scenarios = sorted({(r["scenario"], r["label"], r["outcome"]) for r in sessions})

    lines: list[str] = []
    lines.append("# L7 Web DLP detector evaluation (result tables)\n")
    lines.append("Generated by `evaluation/run_l7_eval.py`. Numbers only; see the "
                 "report write-up for method, corpus provenance, and interpretation.\n")

    lines.append("## Session-level results\n")
    lines.append("| Metric | Count / value |")
    lines.append("| --- | ---: |")
    lines.append(f"| Benign sessions | {benign_total} |")
    lines.append(f"| Malicious sessions | {malicious_total} |")
    lines.append(f"| Detected malicious sessions (TP) | {tp} |")
    lines.append(f"| Missed malicious sessions (FN) | {fn} |")
    lines.append(f"| Flagged benign sessions (FP) | {fp} |")
    lines.append(f"| Unflagged benign sessions (TN) | {tn} |")
    lines.append(f"| Benign session alert rate (FPR) | {fpr:.1f}% |")
    lines.append(f"| Malicious session detection rate (TPR) | {tpr:.1f}% |\n")

    lines.append("### By scenario\n")
    lines.append("| Scenario | Label | Outcome |")
    lines.append("| --- | --- | --- |")
    for scenario, label, outcome in scenarios:
        lines.append(f"| {scenario} | {label} | **{outcome}** |")
    lines.append("")

    lines.append("## Pipeline latency (detector only, no mitmproxy / TLS)\n")
    lines.append("Measured with `time.perf_counter_ns` over "
                 f"{LATENCY_ITERATIONS} iterations per request.\n")
    lines.append("| Metric | Value |")
    lines.append("| --- | ---: |")
    lines.append(f"| Median per-request latency | {median_us} us |")
    lines.append(f"| p95 per-request latency | {p95_us} us |")
    lines.append(f"| Requests measured | {len(requests)} |\n")

    lines.append("End-to-end latency through the full mitmproxy stack is measured "
                 "out-of-band (victim container -> gateway -> attacker sink via "
                 "`curl`) and reported in the main `README.md` section 4.1 "
                 "alongside the pipeline-isolated numbers above.\n")

    path.write_text("\n".join(lines), encoding="utf-8")


# main

def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    all_requests: list[dict] = []
    all_sessions: list[dict] = []
    for scenario in MALICIOUS + BENIGN:
        request_rows, session_row = run_scenario(scenario)
        all_requests.extend(request_rows)
        all_sessions.append(session_row)

    write_csv(OUTPUT_DIR / "results.csv", REQUEST_FIELDS, all_requests)
    write_csv(OUTPUT_DIR / "sessions.csv", SESSION_FIELDS, all_sessions)
    write_report(OUTPUT_DIR / "REPORT.md", all_sessions, all_requests)

    tp = sum(1 for s in all_sessions if s["outcome"] == "TP")
    fn = sum(1 for s in all_sessions if s["outcome"] == "FN")
    fp = sum(1 for s in all_sessions if s["outcome"] == "FP")
    tn = sum(1 for s in all_sessions if s["outcome"] == "TN")
    print(f"L7 evaluation complete. Sessions: TP={tp} FN={fn} FP={fp} TN={tn}")
    print(f"Artifacts: {OUTPUT_DIR}/results.csv  sessions.csv  REPORT.md")


if __name__ == "__main__":
    main()
