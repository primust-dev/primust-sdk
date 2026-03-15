"""Tests for the secrets_scanner built-in check."""

from primust_checks.builtin.secrets_scanner import check_secrets_scanner


def test_aws_key_detected():
    result = check_secrets_scanner(input="My key is AKIAIOSFODNN7EXAMPLE")
    assert result.passed is False
    assert "aws_access_key" in result.details["matched_patterns"]


def test_github_token_detected():
    result = check_secrets_scanner(input="token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijk")
    assert result.passed is False
    assert "github_token" in result.details["matched_patterns"]


def test_gcp_key_detected():
    result = check_secrets_scanner(input="key=AIzaSyA-valid-looking-key_1234567890abcde")
    assert result.passed is False
    assert "gcp_api_key" in result.details["matched_patterns"]


def test_clean_string_passes():
    result = check_secrets_scanner(input="This is a normal sentence with no secrets.")
    assert result.passed is True
    assert result.details["matched_patterns"] == []


def test_configurable_patterns():
    custom_patterns = {"custom_secret": r"SECRET_[A-Z]{8}"}
    result = check_secrets_scanner(
        input="Found SECRET_ABCDEFGH here",
        config={"patterns": custom_patterns},
    )
    assert result.passed is False
    assert "custom_secret" in result.details["matched_patterns"]


def test_skip_generic_config():
    # A 32-char hex string that would match generic but not other patterns
    long_token = "a" * 32
    result_with_generic = check_secrets_scanner(input=f"token: {long_token}")
    result_without_generic = check_secrets_scanner(
        input=f"token: {long_token}",
        config={"skip_generic": True},
    )
    # With generic enabled, it may match; without, it should not match specific patterns
    assert result_without_generic.passed is True


def test_output_also_scanned():
    result = check_secrets_scanner(input="clean", output="AKIAIOSFODNN7EXAMPLE")
    assert result.passed is False
