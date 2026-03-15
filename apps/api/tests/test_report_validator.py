"""
Tests for the inline _validate_artifact in report_generator.

Ensures the inline validator stays consistent with the canonical
primust_artifact_core.validate_artifact. If the canonical validator
adds new invariant checks, this test file should be updated to match.
"""

import sys
from pathlib import Path

import pytest

# Import the inline validator from report_generator
from primust_api.services.report_generator import (
    _validate_artifact,
    _ValidationResult,
)

# Try to import the canonical validator for drift comparison
_CANONICAL_AVAILABLE = False
try:
    from primust_artifact_core.validate_artifact import validate_artifact as canonical_validate
    _CANONICAL_AVAILABLE = True
except ImportError:
    pass


# ── Known-good fixtures ──

VALID_VPEC = {
    "schema_version": "4.0.0",
    "vpec_id": "vpec_abc123",
    "proof_level": "execution",
    "manifest_hashes": {"check_a": "sha256:aabbcc"},
    "proof_distribution": {"mathematical": 3, "execution": 1, "weakest_link": "execution"},
    "gaps": [],
    "issuer": {
        "public_key_url": "https://primust.com/.well-known/primust-pubkeys/kid_us_1.pem",
    },
}

VALID_VPEC_WITH_GAPS = {
    **VALID_VPEC,
    "vpec_id": "vpec_def456",
    "gaps": [
        {"gap_type": "check_missing", "severity": "High", "state": "open"},
        {"gap_type": "check_failed", "severity": "Medium", "state": "waived"},
    ],
}


# ── Known-bad fixtures ──

BAD_SCHEMA_VERSION = {**VALID_VPEC, "schema_version": "3.0.0"}
BAD_PROOF_LEVEL = {**VALID_VPEC, "proof_level": "quantum"}
BAD_MANIFEST_HASHES_LIST = {**VALID_VPEC, "manifest_hashes": ["sha256:aabbcc"]}
BAD_GAPS_MISSING_TYPE = {**VALID_VPEC, "gaps": [{"severity": "High"}]}
BAD_GAPS_MISSING_SEVERITY = {**VALID_VPEC, "gaps": [{"gap_type": "check_failed"}]}
BAD_RELIANCE_MODE = {**VALID_VPEC, "reliance_mode": "full"}


class TestInlineValidator:
    """Tests for the inline _validate_artifact function."""

    def test_valid_vpec_passes(self):
        result = _validate_artifact(VALID_VPEC)
        assert result.valid is True
        assert result.errors == []

    def test_valid_vpec_with_gaps_passes(self):
        result = _validate_artifact(VALID_VPEC_WITH_GAPS)
        assert result.valid is True
        assert result.errors == []

    def test_bad_schema_version(self):
        result = _validate_artifact(BAD_SCHEMA_VERSION)
        assert result.valid is False
        assert any(e.code == "SCHEMA_VERSION" for e in result.errors)

    def test_bad_proof_level(self):
        result = _validate_artifact(BAD_PROOF_LEVEL)
        assert result.valid is False
        assert any(e.code == "PROOF_LEVEL" for e in result.errors)

    def test_manifest_hashes_must_be_dict(self):
        result = _validate_artifact(BAD_MANIFEST_HASHES_LIST)
        assert result.valid is False
        assert any(e.code == "MANIFEST_HASHES" for e in result.errors)

    def test_gaps_missing_gap_type(self):
        result = _validate_artifact(BAD_GAPS_MISSING_TYPE)
        assert result.valid is False
        assert any(e.code == "GAP_FORMAT" for e in result.errors)

    def test_gaps_missing_severity(self):
        result = _validate_artifact(BAD_GAPS_MISSING_SEVERITY)
        assert result.valid is False
        assert any(e.code == "GAP_FORMAT" for e in result.errors)

    def test_forbidden_reliance_mode(self):
        result = _validate_artifact(BAD_RELIANCE_MODE)
        assert result.valid is False
        assert any(e.code == "NO_RELIANCE_MODE" for e in result.errors)

    def test_multiple_errors_accumulated(self):
        """Multiple violations should all be reported."""
        bad = {
            "schema_version": "2.0.0",
            "proof_level": "invalid",
            "manifest_hashes": ["wrong"],
            "reliance_mode": "full",
            "gaps": [{"no_type": True}],
        }
        result = _validate_artifact(bad)
        assert result.valid is False
        assert len(result.errors) >= 4


@pytest.mark.skipif(not _CANONICAL_AVAILABLE, reason="primust-artifact-core not installed")
class TestCanonicalDriftCheck:
    """Compare inline validator against canonical primust_artifact_core.

    These tests only run when primust-artifact-core is installed
    (e.g., in CI with the full monorepo). They catch drift between
    the inline stub and the source-of-truth package.
    """

    def test_valid_vpec_agreement(self):
        inline = _validate_artifact(VALID_VPEC)
        canonical = canonical_validate(VALID_VPEC)
        assert inline.valid == canonical.valid

    def test_bad_schema_agreement(self):
        inline = _validate_artifact(BAD_SCHEMA_VERSION)
        canonical = canonical_validate(BAD_SCHEMA_VERSION)
        assert inline.valid == canonical.valid

    def test_bad_reliance_mode_agreement(self):
        inline = _validate_artifact(BAD_RELIANCE_MODE)
        canonical = canonical_validate(BAD_RELIANCE_MODE)
        assert inline.valid == canonical.valid

    def test_bad_manifest_hashes_agreement(self):
        inline = _validate_artifact(BAD_MANIFEST_HASHES_LIST)
        canonical = canonical_validate(BAD_MANIFEST_HASHES_LIST)
        assert inline.valid == canonical.valid
