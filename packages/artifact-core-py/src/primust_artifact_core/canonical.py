"""Primust Canonical JSON Serialization (Python mirror).

Produces deterministic JSON output with recursively sorted keys
and no whitespace. Two structurally identical objects always produce
the same string regardless of key insertion order.

Rules:
- Object keys sorted lexicographically at every nesting depth
- Array element order preserved (never sorted)
- No whitespace (no spaces, no newlines, no indentation)
- Only JSON-native types accepted: str, int, float, bool, None, dict, list
- Non-JSON-native types (datetime, bytes, etc.) → TypeError

Reference: schemas/golden/canonical_vectors.json
Quarantine: Q1 (top-level-only sort), Q6 (no-sort), Q8 (default=str coercion)
"""

from __future__ import annotations

import json
import math
from typing import Any

# Allowed JSON-native types (no default=str, no silent coercion — Q8 quarantine)
_JSON_NATIVE = (str, int, float, bool, type(None), dict, list)


def canonical(value: Any) -> str:
    """Serialize a value to canonical JSON with recursive key sorting.

    Raises:
        TypeError: If the value contains non-JSON-native types.
    """
    return _serialize(value)


def _serialize(value: Any) -> str:
    if value is None:
        return "null"

    if isinstance(value, bool):
        # Must check bool before int (bool is subclass of int in Python)
        return "true" if value else "false"

    if isinstance(value, int):
        return str(value)

    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise TypeError(
                f"canonical: cannot serialize {value} (NaN/Infinity are not valid JSON)"
            )
        return json.dumps(value)

    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)

    if isinstance(value, list):
        return _serialize_array(value)

    if isinstance(value, dict):
        return _serialize_object(value)

    # Everything else is rejected (Q8: no default=str coercion)
    raise TypeError(
        f"canonical: unsupported type {type(value).__name__}. "
        "Only str, int, float, bool, None, dict, list are accepted."
    )


def _serialize_object(obj: dict) -> str:
    pairs: list[str] = []
    for key in sorted(obj.keys()):
        if not isinstance(key, str):
            raise TypeError(
                f"canonical: dict keys must be strings, got {type(key).__name__}"
            )
        pairs.append(f"{json.dumps(key, ensure_ascii=False)}:{_serialize(obj[key])}")
    return "{" + ",".join(pairs) + "}"


def _serialize_array(arr: list) -> str:
    elements = [_serialize(item) for item in arr]
    return "[" + ",".join(elements) + "]"
