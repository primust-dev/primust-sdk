"""Tests for Primust canonical JSON serialization (Python).

Validates against schemas/golden/canonical_vectors.json.
"""

import json
import math
from datetime import datetime
from pathlib import Path

import pytest

from primust_artifact_core.canonical import canonical

# Load golden vectors
_VECTORS_PATH = Path(__file__).resolve().parents[3] / "schemas" / "golden" / "canonical_vectors.json"
_VECTORS = json.loads(_VECTORS_PATH.read_text())


class TestGoldenVectors:
    """Every golden vector must produce identical output to the TypeScript implementation."""

    @pytest.mark.parametrize(
        "vec",
        _VECTORS["vectors"],
        ids=[v["id"] for v in _VECTORS["vectors"]],
    )
    def test_vector(self, vec):
        assert canonical(vec["input"]) == vec["expected"]


class TestHashVectors:
    def test_canonical_form_matches(self):
        vec = _VECTORS["hash_vectors"][0]
        assert canonical(vec["input"]) == vec["canonical"]


class TestInvalidVectors:
    """Non-JSON-native types must raise TypeError, not coerce (Q8 quarantine)."""

    def test_reject_date_object(self):
        with pytest.raises(TypeError):
            canonical({"ts": datetime.now()})

    def test_reject_bytes(self):
        with pytest.raises(TypeError):
            canonical({"data": b"\x01\x02\x03"})

    def test_reject_nan(self):
        with pytest.raises(TypeError):
            canonical({"val": float("nan")})

    def test_reject_infinity(self):
        with pytest.raises(TypeError):
            canonical({"val": float("inf")})

    def test_reject_negative_infinity(self):
        with pytest.raises(TypeError):
            canonical({"val": float("-inf")})

    def test_reject_set(self):
        with pytest.raises(TypeError):
            canonical({"val": {1, 2, 3}})

    def test_reject_tuple(self):
        """Tuples are not lists — they must be rejected."""
        with pytest.raises(TypeError):
            canonical({"val": (1, 2, 3)})

    def test_reject_custom_object(self):
        class Foo:
            pass

        with pytest.raises(TypeError):
            canonical({"val": Foo()})


class TestEdgeCases:
    def test_recursive_sorting_not_top_level_only(self):
        """Q1 quarantine: must recursively sort, not just top-level."""
        result = canonical({"outer": {"z": 1, "a": 2}})
        assert result == '{"outer":{"a":2,"z":1}}'
        assert result != '{"outer":{"z":1,"a":2}}'

    def test_non_string_dict_keys_rejected(self):
        with pytest.raises(TypeError):
            canonical({1: "a"})  # type: ignore
