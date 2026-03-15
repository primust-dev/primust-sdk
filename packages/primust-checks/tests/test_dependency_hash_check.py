"""Tests for the dependency_hash_check built-in check."""

from primust_checks.builtin.dependency_hash_check import check_dependency_hash


def test_matching_hashes_pass():
    result = check_dependency_hash(
        input={
            "artifacts": [
                {"name": "libfoo.so", "hash": "sha256:abc123"},
                {"name": "libbar.so", "hash": "sha256:def456"},
            ],
            "expected_hashes": {
                "libfoo.so": "sha256:abc123",
                "libbar.so": "sha256:def456",
            },
        }
    )
    assert result.passed is True
    assert result.check_id == "dependency_hash_check"
    assert result.details["verified"] == 2


def test_tampered_hash_fails():
    result = check_dependency_hash(
        input={
            "artifacts": [
                {"name": "libfoo.so", "hash": "sha256:TAMPERED"},
            ],
            "expected_hashes": {
                "libfoo.so": "sha256:abc123",
            },
        }
    )
    assert result.passed is False
    assert "libfoo.so" in result.details["mismatched"]


def test_missing_expected_hash_still_passes():
    """Artifacts without an expected hash are noted but don't cause failure."""
    result = check_dependency_hash(
        input={
            "artifacts": [
                {"name": "libfoo.so", "hash": "sha256:abc123"},
                {"name": "unknown.so", "hash": "sha256:xyz"},
            ],
            "expected_hashes": {
                "libfoo.so": "sha256:abc123",
            },
        }
    )
    assert result.passed is True
    assert "unknown.so" in result.details["missing_expected"]


def test_empty_artifacts_pass():
    result = check_dependency_hash(
        input={
            "artifacts": [],
            "expected_hashes": {},
        }
    )
    assert result.passed is True


def test_missing_input_keys_fails():
    result = check_dependency_hash(input={"artifacts": []})
    assert result.passed is False
    assert "Missing required" in result.evidence


def test_multiple_mismatches():
    result = check_dependency_hash(
        input={
            "artifacts": [
                {"name": "a.so", "hash": "bad1"},
                {"name": "b.so", "hash": "bad2"},
            ],
            "expected_hashes": {
                "a.so": "good1",
                "b.so": "good2",
            },
        }
    )
    assert result.passed is False
    assert len(result.details["mismatched"]) == 2


def test_proof_ceiling_is_mathematical():
    result = check_dependency_hash(
        input={
            "artifacts": [{"name": "x", "hash": "h"}],
            "expected_hashes": {"x": "h"},
        }
    )
    assert result.proof_ceiling == "mathematical"
