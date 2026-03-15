"""Tests for the cost_bounds built-in check."""

from primust_checks.builtin.cost_bounds import check_cost_bounds


def test_under_threshold_passes():
    result = check_cost_bounds(input={"token_count": 500, "cost_usd": 0.10})
    assert result.passed is True


def test_over_token_threshold_fails():
    result = check_cost_bounds(input={"token_count": 200_000, "cost_usd": 0.50})
    assert result.passed is False
    assert any("token_count" in v for v in result.details["violations"])


def test_over_cost_threshold_fails():
    result = check_cost_bounds(input={"token_count": 100, "cost_usd": 5.00})
    assert result.passed is False
    assert any("cost_usd" in v for v in result.details["violations"])


def test_custom_config_thresholds():
    config = {"max_tokens_per_run": 50, "max_cost_usd": 0.01}
    result = check_cost_bounds(
        input={"token_count": 100, "cost_usd": 0.05},
        config=config,
    )
    assert result.passed is False
    assert len(result.details["violations"]) == 2


def test_missing_fields_passes():
    """When no cost/token data is provided, the check passes (nothing to violate)."""
    result = check_cost_bounds(input={"unrelated": "data"})
    assert result.passed is True
    assert "no cost/token data" in result.evidence


def test_string_input_passes():
    """Non-dict input with no cost data passes."""
    result = check_cost_bounds(input="just a string")
    assert result.passed is True


def test_context_values_used():
    """Values from context dict are also checked."""
    result = check_cost_bounds(
        input="some text",
        context={"token_count": 999_999},
    )
    assert result.passed is False


def test_exactly_at_threshold_passes():
    result = check_cost_bounds(input={"token_count": 100_000, "cost_usd": 1.00})
    assert result.passed is True
