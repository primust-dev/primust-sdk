"""Tests for the schema_validation built-in check."""

from primust_checks.builtin.schema_validation import check_schema_validation


def test_required_fields_present_passes():
    result = check_schema_validation(
        input={
            "data": {"name": "Alice", "age": 30},
            "required_fields": ["name", "age"],
        }
    )
    assert result.passed is True
    assert result.check_id == "schema_validation"


def test_required_fields_missing_fails():
    result = check_schema_validation(
        input={
            "data": {"name": "Alice"},
            "required_fields": ["name", "age"],
        }
    )
    assert result.passed is False
    assert any("age" in e for e in result.details["errors"])


def test_strict_mode_rejects_extra_fields():
    result = check_schema_validation(
        input={
            "data": {"name": "Alice", "age": 30, "extra": True},
            "required_fields": ["name", "age"],
        },
        config={"strict": True},
    )
    assert result.passed is False
    assert any("extra" in e for e in result.details["errors"])


def test_non_strict_allows_extra_fields():
    result = check_schema_validation(
        input={
            "data": {"name": "Alice", "age": 30, "extra": True},
            "required_fields": ["name", "age"],
        },
        config={"strict": False},
    )
    assert result.passed is True


def test_json_schema_valid():
    """Test with a JSON Schema dict (uses manual fallback if jsonschema not installed)."""
    schema = {
        "type": "object",
        "required": ["id", "value"],
        "properties": {
            "id": {"type": "string"},
            "value": {"type": "number"},
        },
    }
    result = check_schema_validation(
        input={"data": {"id": "abc", "value": 42}, "schema": schema}
    )
    assert result.passed is True


def test_json_schema_missing_required():
    schema = {
        "type": "object",
        "required": ["id", "value"],
        "properties": {
            "id": {"type": "string"},
            "value": {"type": "number"},
        },
    }
    result = check_schema_validation(
        input={"data": {"id": "abc"}, "schema": schema}
    )
    assert result.passed is False
    assert any("value" in e for e in result.details["errors"])


def test_json_schema_wrong_type():
    schema = {
        "type": "object",
        "properties": {
            "count": {"type": "integer"},
        },
    }
    result = check_schema_validation(
        input={"data": {"count": "not-a-number"}, "schema": schema}
    )
    assert result.passed is False


def test_no_data_fails():
    result = check_schema_validation(input={})
    assert result.passed is False
    assert "No 'data' key" in result.evidence


def test_no_schema_or_fields_fails():
    result = check_schema_validation(input={"data": {"a": 1}})
    assert result.passed is False
    assert any("Neither" in e for e in result.details["errors"])


def test_proof_ceiling_is_mathematical():
    result = check_schema_validation(
        input={"data": {"x": 1}, "required_fields": ["x"]}
    )
    assert result.proof_ceiling == "mathematical"
