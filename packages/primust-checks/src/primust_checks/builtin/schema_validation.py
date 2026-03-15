"""Schema validation check -- mathematical proof ceiling.

Validates data against a JSON schema or expected field set.
Domain-neutral: works for any structured data (API payloads,
config files, SBOM entries, clinical records, financial data).
"""

from __future__ import annotations

from typing import Any

from ..result import CheckResult


def check_schema_validation(
    *,
    input: Any,
    output: Any = None,
    context: dict[str, Any] | None = None,
    config: dict[str, Any] | None = None,
) -> CheckResult:
    """Validate data against a JSON schema or required field list.

    input must be a dict containing:
      - data: the object/dict to validate
      - schema: (optional) JSON Schema dict
      - required_fields: (optional) list of field names that must be present

    config options:
      - strict: bool (default True) — if True, fail when data contains
        fields not listed in schema properties or required_fields.
    """
    config = config or {}
    input_data = input if isinstance(input, dict) else {}
    data = input_data.get("data")

    if data is None:
        return CheckResult(
            passed=False,
            check_id="schema_validation",
            evidence="No 'data' key in input",
            proof_ceiling="mathematical",
        )

    schema = input_data.get("schema")
    required_fields = input_data.get("required_fields")
    strict = config.get("strict", True)
    errors: list[str] = []

    # JSON Schema validation (if jsonschema is available)
    if schema is not None:
        try:
            import jsonschema

            try:
                jsonschema.validate(instance=data, schema=schema)
            except jsonschema.ValidationError as exc:
                errors.append(f"Schema validation error: {exc.message}")
            except jsonschema.SchemaError as exc:
                errors.append(f"Invalid schema: {exc.message}")
        except ImportError:
            # Fallback: manual property + type checks
            _validate_schema_manual(data, schema, strict, errors)
    elif required_fields is not None:
        if not isinstance(data, dict):
            errors.append("Data must be a dict when using required_fields")
        else:
            for field_name in required_fields:
                if field_name not in data:
                    errors.append(f"Missing required field: {field_name}")

            if strict:
                extra = set(data.keys()) - set(required_fields)
                if extra:
                    errors.append(
                        f"Unexpected fields (strict mode): {', '.join(sorted(extra))}"
                    )
    else:
        errors.append("Neither 'schema' nor 'required_fields' provided in input")

    passed = len(errors) == 0
    return CheckResult(
        passed=passed,
        check_id="schema_validation",
        evidence="schema valid" if passed else f"{len(errors)} validation error(s)",
        details={"errors": errors},
        proof_ceiling="mathematical",
    )


def _validate_schema_manual(
    data: Any,
    schema: dict[str, Any],
    strict: bool,
    errors: list[str],
) -> None:
    """Minimal JSON Schema validation without jsonschema library."""
    schema_type = schema.get("type")

    if schema_type == "object" and isinstance(data, dict):
        # Check required properties
        for req in schema.get("required", []):
            if req not in data:
                errors.append(f"Missing required field: {req}")

        # Check additional properties
        props = schema.get("properties", {})
        if strict and schema.get("additionalProperties") is False:
            extra = set(data.keys()) - set(props.keys())
            if extra:
                errors.append(
                    f"Unexpected fields (strict mode): {', '.join(sorted(extra))}"
                )

        # Check property types
        for prop_name, prop_schema in props.items():
            if prop_name in data:
                expected_type = prop_schema.get("type")
                value = data[prop_name]
                if expected_type and not _type_matches(value, expected_type):
                    errors.append(
                        f"Field '{prop_name}': expected type '{expected_type}', "
                        f"got '{type(value).__name__}'"
                    )
    elif schema_type and not _type_matches(data, schema_type):
        errors.append(f"Expected type '{schema_type}', got '{type(data).__name__}'")


_TYPE_MAP = {
    "string": str,
    "integer": int,
    "number": (int, float),
    "boolean": bool,
    "array": list,
    "object": dict,
    "null": type(None),
}


def _type_matches(value: Any, expected: str) -> bool:
    """Check if value matches a JSON Schema type string."""
    py_type = _TYPE_MAP.get(expected)
    if py_type is None:
        return True  # Unknown type — allow
    return isinstance(value, py_type)
