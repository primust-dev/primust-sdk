"""Tests for the reconciliation_check built-in check."""

from primust_checks.builtin.reconciliation_check import check_reconciliation


def test_matching_records_pass():
    source = [
        {"id": 1, "name": "Alice", "amount": 100},
        {"id": 2, "name": "Bob", "amount": 200},
    ]
    target = [
        {"id": 1, "name": "Alice", "amount": 100},
        {"id": 2, "name": "Bob", "amount": 200},
    ]
    result = check_reconciliation(
        input={
            "source": source,
            "target": target,
            "key_fields": ["id"],
            "sum_fields": ["amount"],
        }
    )
    assert result.passed is True
    assert result.check_id == "reconciliation_check"
    assert result.details["common_keys"] == 2


def test_missing_target_records_fail():
    source = [
        {"id": 1, "amount": 100},
        {"id": 2, "amount": 200},
    ]
    target = [
        {"id": 1, "amount": 100},
    ]
    result = check_reconciliation(
        input={
            "source": source,
            "target": target,
            "key_fields": ["id"],
        }
    )
    assert result.passed is False
    assert result.details["source_only_keys"] > 0


def test_sum_field_mismatch_fails():
    source = [
        {"id": 1, "amount": 100},
        {"id": 2, "amount": 200},
    ]
    target = [
        {"id": 1, "amount": 100},
        {"id": 2, "amount": 999},
    ]
    result = check_reconciliation(
        input={
            "source": source,
            "target": target,
            "key_fields": ["id"],
            "sum_fields": ["amount"],
        }
    )
    assert result.passed is False
    assert len(result.details["sum_mismatches"]) > 0


def test_numeric_tolerance_allows_small_diff():
    source = [{"id": 1, "amount": 100.001}]
    target = [{"id": 1, "amount": 100.002}]
    result = check_reconciliation(
        input={
            "source": source,
            "target": target,
            "key_fields": ["id"],
            "sum_fields": ["amount"],
        },
        config={"tolerance": 0.01},
    )
    assert result.passed is True


def test_numeric_tolerance_rejects_large_diff():
    source = [{"id": 1, "amount": 100}]
    target = [{"id": 1, "amount": 200}]
    result = check_reconciliation(
        input={
            "source": source,
            "target": target,
            "key_fields": ["id"],
            "sum_fields": ["amount"],
        },
        config={"tolerance": 0.01},
    )
    assert result.passed is False


def test_missing_input_keys_fails():
    result = check_reconciliation(input={"source": []})
    assert result.passed is False
    assert "Missing required" in result.evidence


def test_composite_key_fields():
    source = [{"region": "US", "product": "A", "qty": 10}]
    target = [{"region": "US", "product": "A", "qty": 10}]
    result = check_reconciliation(
        input={
            "source": source,
            "target": target,
            "key_fields": ["region", "product"],
        }
    )
    assert result.passed is True


def test_proof_ceiling_is_mathematical():
    result = check_reconciliation(
        input={
            "source": [{"id": 1}],
            "target": [{"id": 1}],
            "key_fields": ["id"],
        }
    )
    assert result.proof_ceiling == "mathematical"
