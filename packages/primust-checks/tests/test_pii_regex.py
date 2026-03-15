"""Tests for the pii_regex built-in check."""

from primust_checks.builtin.pii_regex import check_pii_regex, _luhn_check


def test_ssn_detected():
    result = check_pii_regex(input="SSN: 123-45-6789")
    assert result.passed is False
    assert "ssn" in result.details["pattern_types_matched"]


def test_email_detected():
    result = check_pii_regex(input="Contact me at user@example.com")
    assert result.passed is False
    assert "email" in result.details["pattern_types_matched"]


def test_phone_detected():
    result = check_pii_regex(input="Call 555-123-4567")
    assert result.passed is False
    assert "phone" in result.details["pattern_types_matched"]


def test_credit_card_detected_with_luhn():
    # 4111111111111111 is a well-known Luhn-valid test number
    result = check_pii_regex(input="Card: 4111111111111111")
    assert result.passed is False
    assert "credit_card" in result.details["pattern_types_matched"]


def test_credit_card_fails_luhn():
    # 4111111111111112 fails Luhn
    result = check_pii_regex(input="Card: 4111111111111112")
    assert "credit_card" not in result.details["pattern_types_matched"]


def test_clean_string_passes():
    result = check_pii_regex(input="The weather is nice today.")
    assert result.passed is True
    assert result.details["pattern_types_matched"] == []


def test_luhn_valid():
    assert _luhn_check("4111111111111111") is True
    assert _luhn_check("5500000000000004") is True  # Mastercard test number


def test_luhn_invalid():
    assert _luhn_check("1234567890") is False
    assert _luhn_check("12") is False  # too short


def test_multiple_pii_types():
    result = check_pii_regex(input="SSN 123-45-6789 email test@test.com")
    assert result.passed is False
    assert "ssn" in result.details["pattern_types_matched"]
    assert "email" in result.details["pattern_types_matched"]


def test_disable_patterns():
    result = check_pii_regex(
        input="SSN 123-45-6789",
        config={"disable_patterns": ["ssn"]},
    )
    assert "ssn" not in result.details["pattern_types_matched"]
