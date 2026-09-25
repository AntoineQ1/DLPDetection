"""Unit tests for L7 detectors (Workstream B).

Direct calls into `detection.l7_web` — no mitmproxy needed.
"""

from detection.l7_web import scan_all
from detection.l7_web.luhn import luhn_valid

def test_luhn_empty():
    assert luhn_valid("") is False

def test_luhn_receives_char():
    assert luhn_valid("411111111111111a") is False

def test_luhn_valid_visa_test_pan():
    assert luhn_valid("4111111111111111") is True


def test_luhn_rejects_bad_checksum():
    assert luhn_valid("4111111111111112") is False


def test_luhn_valid_amex_test_pan_15_digits():
    assert luhn_valid("378282246310005") is True


def test_luhn_valid_mastercard_test_pan():
    assert luhn_valid("5555555555554444") is True


def test_luhn_valid_wikipedia_11_digit_example():
    assert luhn_valid("79927398713") is True


def test_luhn_valid_trivial_zero():
    assert luhn_valid("0") is True


def test_scan_finds_cc_with_dashes():
    body = 'POST /pay {"card":"4111-1111-1111-1111"}'
    findings = scan_all(body)
    assert any(f.rule_id == "luhn_cc" for f in findings)

def test_scan_finds_cc_with_dots():
    body = 'POST /pay {"card":"4111.1111.1111.1111"}'
    findings = scan_all(body)
    assert any(f.rule_id == "luhn_cc" for f in findings)

def test_scan_finds_cc_with_underscores():
    body = 'POST /pay {"card":"4111_1111_1111_1111"}'
    findings = scan_all(body)
    assert any(f.rule_id == "luhn_cc" for f in findings)

def test_scan_finds_cc_with_spaces():
    body = "Please charge card 4111 1111 1111 1111 today."
    findings = scan_all(body)
    assert any(f.rule_id == "luhn_cc" for f in findings)


def test_scan_finds_cc_without_separators():
    body = "cc=4111111111111111&amount=42"
    findings = scan_all(body)
    assert any(f.rule_id == "luhn_cc" for f in findings)


def test_scan_finds_mixed_separators():
    body = "card: 4111-1111 1111-1111"
    findings = scan_all(body)
    assert any(f.rule_id == "luhn_cc" for f in findings)


def test_scan_finds_multiple_cards_in_one_body():
    body = '{"a":"4111111111111111","b":"5555555555554444"}'
    findings = scan_all(body)
    cc_hits = [f for f in findings if f.rule_id == "luhn_cc"]
    assert len(cc_hits) == 2


def test_scan_finding_carries_correct_metadata():
    body = "leak: 4111-1111-1111-1111"
    findings = scan_all(body)
    cc_hits = [f for f in findings if f.rule_id == "luhn_cc"]
    assert len(cc_hits) == 1
    f = cc_hits[0]
    assert f.detector == "luhn"
    assert f.severity == "high"
    assert f.meta.get("digits") == 16
    assert body[f.start:f.end] == f.matched


def test_scan_ignores_benign_text_without_digits():
    findings = scan_all("hello world, this is a benign request body.")
    assert not any(f.rule_id == "luhn_cc" for f in findings)


def test_scan_ignores_body_with_invalid_pan():
    body = 'POST payload {"card":"4111-1111-1111-1112"}'
    findings = scan_all(body)
    assert not any(f.rule_id == "luhn_cc" for f in findings)


def test_scan_ignores_long_random_digit_run_failing_luhn():
    assert luhn_valid("1234567890123456") is False
    body = "Order tracking id 1234567890123456 shipped."
    findings = scan_all(body)
    assert not any(f.rule_id == "luhn_cc" for f in findings)


def test_scan_ignores_valid_luhn_but_too_short():
    assert luhn_valid("00000018") is True
    body = "invoice number 00000018 paid"
    findings = scan_all(body)
    assert not any(f.rule_id == "luhn_cc" for f in findings)


def test_scan_ignores_digit_run_too_long_to_be_a_card():
    body = "opaque id 41111111111111111111 end"
    findings = scan_all(body)
    assert not any(f.rule_id == "luhn_cc" for f in findings)

def test_scan_ignores_all_zeros_but_luhn_isvalid():
    assert luhn_valid("0000000000000000") is True
    body = "Your id is 0000000000000000."
    findings = scan_all(body)
    assert not any(f.rule_id == "luhn_cc" for f in findings)

def test_scan_ignores_milisecond_timestamp_but_luhn_isvalid():
    seconds = "1700000000" # for example: seconds since 1970
    ms = "004"
    assert luhn_valid(seconds + ms) is True
    body = f"Timestamp: {seconds + ms}"
    findings = scan_all(body)
    assert not any(f.rule_id == "luhn_cc" for f in findings)


# ===== REGEX TESTS =====
def test_regex_rules_dummy_api_key_is_detected(): # remove later
    findings = scan_all("the key is api-key")
    assert any(f.rule_id == "AWS_VERY_REAL_API_KEY" for f in findings)

# === END REGEX TESTS ===