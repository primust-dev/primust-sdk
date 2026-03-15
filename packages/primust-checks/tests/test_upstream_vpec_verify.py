"""Tests for the upstream_vpec_verify built-in check."""

import datetime

from primust_checks.builtin.upstream_vpec_verify import check_upstream_vpec_verify


def _make_vpec(**overrides):
    """Build a minimal valid VPEC dict."""
    vpec = {
        "vpec_id": "vpec_abc123",
        "org_id": "org_upstream",
        "proof_level_floor": "mathematical",
        "signature": {
            "value": "deadbeef" * 16,
            "algorithm": "Ed25519",
            "kid": "key-001",
        },
        "environment": "production",
        "signed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "check_execution_records": [
            {"check_id": "secrets_scanner"},
            {"check_id": "pii_regex"},
        ],
    }
    vpec.update(overrides)
    return vpec


def test_valid_vpec_passes():
    """Structurally valid VPEC should pass (primust-verify not installed)."""
    result = check_upstream_vpec_verify(input={"vpec": _make_vpec()})
    assert result.passed is True
    assert result.check_id == "upstream_vpec_verify"
    assert "verified" in result.evidence


def test_missing_vpec_fails():
    result = check_upstream_vpec_verify(input={})
    assert result.passed is False
    assert "No VPEC" in result.evidence


def test_vpec_not_dict_fails():
    result = check_upstream_vpec_verify(input={"vpec": "not-a-dict"})
    assert result.passed is False
    assert "must be a dict" in result.evidence


def test_missing_required_fields_fails():
    result = check_upstream_vpec_verify(input={"vpec": {"vpec_id": "x"}})
    assert result.passed is False
    assert "Structural validation failed" in result.evidence
    assert "org_id" in result.details["errors"][0] or "signature" in str(
        result.details["errors"]
    )


def test_org_id_mismatch_fails():
    vpec = _make_vpec(org_id="org_wrong")
    result = check_upstream_vpec_verify(
        input={"vpec": vpec},
        config={"expected_org_id": "org_expected"},
    )
    assert result.passed is False
    assert any("Org mismatch" in e for e in result.details["errors"])


def test_org_id_matches():
    vpec = _make_vpec(org_id="org_expected")
    result = check_upstream_vpec_verify(
        input={"vpec": vpec},
        config={"expected_org_id": "org_expected"},
    )
    assert result.passed is True


def test_proof_level_too_low_fails():
    vpec = _make_vpec(proof_level_floor="attestation")
    result = check_upstream_vpec_verify(
        input={"vpec": vpec},
        config={"minimum_proof_level_floor": "mathematical"},
    )
    assert result.passed is False
    assert any("Proof level too low" in e for e in result.details["errors"])


def test_proof_level_sufficient_passes():
    vpec = _make_vpec(proof_level_floor="mathematical")
    result = check_upstream_vpec_verify(
        input={"vpec": vpec},
        config={"minimum_proof_level_floor": "execution"},
    )
    assert result.passed is True


def test_required_checks_missing_fails():
    vpec = _make_vpec()  # has secrets_scanner and pii_regex
    result = check_upstream_vpec_verify(
        input={"vpec": vpec},
        config={"required_checks": ["secrets_scanner", "cost_bounds"]},
    )
    assert result.passed is False
    assert any("Missing required checks" in e for e in result.details["errors"])


def test_required_checks_present_passes():
    vpec = _make_vpec()
    result = check_upstream_vpec_verify(
        input={"vpec": vpec},
        config={"required_checks": ["secrets_scanner", "pii_regex"]},
    )
    assert result.passed is True


def test_test_mode_rejected():
    vpec = _make_vpec(environment="test")
    result = check_upstream_vpec_verify(
        input={"vpec": vpec},
        config={"reject_test_mode": True},
    )
    assert result.passed is False
    assert any("test mode" in e for e in result.details["errors"])


def test_test_mode_allowed():
    vpec = _make_vpec(environment="test")
    result = check_upstream_vpec_verify(
        input={"vpec": vpec},
        config={"reject_test_mode": False},
    )
    assert result.passed is True


def test_expired_vpec_fails():
    old_time = (
        datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=48)
    ).isoformat()
    vpec = _make_vpec(signed_at=old_time)
    result = check_upstream_vpec_verify(
        input={"vpec": vpec},
        config={"max_age_hours": 24},
    )
    assert result.passed is False
    assert any("too old" in e for e in result.details["errors"])


def test_fresh_vpec_passes_age_check():
    fresh_time = datetime.datetime.now(datetime.timezone.utc).isoformat()
    vpec = _make_vpec(signed_at=fresh_time)
    result = check_upstream_vpec_verify(
        input={"vpec": vpec},
        config={"max_age_hours": 24},
    )
    assert result.passed is True


def test_graceful_fallback_no_verifier():
    """Without primust-verify, should still do structural checks and warn."""
    vpec = _make_vpec()
    result = check_upstream_vpec_verify(input={"vpec": vpec})
    assert result.passed is True
    # Should have a warning about structural-only mode
    assert any(
        "primust-verify not installed" in w
        for w in result.details.get("warnings", [])
    )


def test_no_signature_value_fails():
    vpec = _make_vpec()
    vpec["signature"] = {"algorithm": "Ed25519", "kid": "key-001"}
    result = check_upstream_vpec_verify(input={"vpec": vpec})
    assert result.passed is False
    assert any("No signature value" in e for e in result.details["errors"])


def test_proof_ceiling_is_mathematical():
    result = check_upstream_vpec_verify(input={"vpec": _make_vpec()})
    assert result.proof_ceiling == "mathematical"
