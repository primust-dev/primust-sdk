"""
upstream_vpec_verify — Cross-org VPEC verification check.

Verifies that an upstream organization's VPEC is valid before accepting
their output. This is the relying party verification primitive.

Proof ceiling: Mathematical (Ed25519 signature verification is deterministic).

Use cases:
  - Enterprise receiving AI outputs from a vendor
  - Platform verifying ISV governance before routing
  - Bank verifying fintech vendor's data quality checks
  - Deployer verifying provider governance per EU AI Act Article 25
  - Build pipeline verifying upstream SBOM governance
  - Clinical trial sponsor verifying CRO data integrity checks

The check is domain-neutral — it verifies any VPEC regardless of what
the upstream process was (AI, financial, manufacturing, build pipeline).
"""

from __future__ import annotations

from typing import Any

from ..result import CheckResult


def check_upstream_vpec_verify(
    *,
    input: Any,
    output: Any = None,
    context: dict[str, Any] | None = None,
    config: dict[str, Any] | None = None,
) -> CheckResult:
    """
    Verify an upstream VPEC.

    input must be a dict containing:
      - vpec: dict — the VPEC artifact JSON to verify

    config options:
      - expected_org_id: str | None — if set, VPEC must be from this org
      - minimum_proof_level_floor: str | None — minimum acceptable proof level
        (mathematical > verifiable_inference > execution > witnessed > attestation)
      - required_checks: list[str] | None — check IDs that must be present in VPEC
      - trust_root_pem: str | None — path to PEM file for offline verification
      - reject_test_mode: bool — if True, reject VPECs issued with test keys (default: True)
      - max_age_hours: int | None — reject VPECs older than this

    Returns CheckResult with:
      - passed: True if VPEC is valid and meets all config requirements
      - evidence: verification summary
      - details: full verification result dict
    """
    config = config or {}
    input_data = input if isinstance(input, dict) else {}
    vpec = input_data.get("vpec")

    if vpec is None:
        return CheckResult(
            passed=False,
            check_id="upstream_vpec_verify",
            evidence="No VPEC provided in input['vpec']",
            proof_ceiling="mathematical",
        )

    if not isinstance(vpec, dict):
        return CheckResult(
            passed=False,
            check_id="upstream_vpec_verify",
            evidence="VPEC must be a dict (parsed JSON)",
            proof_ceiling="mathematical",
        )

    errors: list[str] = []
    warnings: list[str] = []

    # 1. Structural validation
    required_fields = ["vpec_id", "org_id", "signature", "proof_level_floor"]
    for field in required_fields:
        if field not in vpec:
            errors.append(f"Missing required field: {field}")

    if errors:
        return CheckResult(
            passed=False,
            check_id="upstream_vpec_verify",
            evidence=f"Structural validation failed: {'; '.join(errors)}",
            details={"errors": errors},
            proof_ceiling="mathematical",
        )

    # 2. Signature verification (Ed25519)
    signature = vpec.get("signature", {})
    sig_value = signature.get("value") or signature.get("signature_hex")
    verification_mode = "structural"

    if not sig_value:
        errors.append("No signature value in VPEC")
    else:
        # Try to verify using primust-verify if available
        try:
            from primust_verify.verifier import verify
            from primust_verify.types import VerifyOptions

            opts = VerifyOptions(
                production=config.get("reject_test_mode", True),
                skip_network=config.get("skip_network", False),
                trust_root=config.get("trust_root_pem"),
            )
            result = verify(vpec, opts)
            verification_mode = "full"

            if not result.valid:
                for err in result.errors:
                    errors.append(f"Verification failed: {err}")
            for w in result.warnings:
                warnings.append(w)

        except ImportError:
            # primust-verify not installed — do structural checks only
            warnings.append(
                "primust-verify not installed. Only structural validation performed. "
                "Install with: pip install primust-verify"
            )
            # Basic signature structure check
            if not signature.get("algorithm"):
                errors.append("Missing signature algorithm")
            if not signature.get("kid"):
                errors.append("Missing signer key ID (kid)")

    # 3. Org ID check
    expected_org = config.get("expected_org_id")
    if expected_org and vpec.get("org_id") != expected_org:
        errors.append(
            f"Org mismatch: expected '{expected_org}', got '{vpec.get('org_id')}'"
        )

    # 4. Proof level floor check
    min_level = config.get("minimum_proof_level_floor")
    if min_level:
        level_order = {
            "mathematical": 5,
            "verifiable_inference": 4,
            "execution": 3,
            "witnessed": 2,
            "attestation": 1,
        }
        vpec_level = vpec.get("proof_level_floor", "attestation")
        if level_order.get(vpec_level, 0) < level_order.get(min_level, 0):
            errors.append(
                f"Proof level too low: VPEC has '{vpec_level}', "
                f"minimum required is '{min_level}'"
            )

    # 5. Required checks presence
    required_checks = config.get("required_checks")
    if required_checks:
        vpec_checks: set[str] = set()
        for record in vpec.get("check_execution_records", []):
            check_id = record.get("check_id") or record.get("manifest_id", "")
            vpec_checks.add(check_id)

        missing = set(required_checks) - vpec_checks
        if missing:
            errors.append(f"Missing required checks: {', '.join(sorted(missing))}")

    # 6. Test mode check
    if config.get("reject_test_mode", True):
        env = vpec.get("environment", "")
        if env in ("test", "sandbox"):
            errors.append(f"VPEC is in {env} mode (reject_test_mode=True)")

    # 7. Age check
    max_age_hours = config.get("max_age_hours")
    if max_age_hours is not None:
        import datetime

        signed_at = vpec.get("signed_at") or vpec.get("issued_at")
        if signed_at:
            try:
                issued = datetime.datetime.fromisoformat(
                    signed_at.replace("Z", "+00:00")
                )
                now = datetime.datetime.now(datetime.timezone.utc)
                age_hours = (now - issued).total_seconds() / 3600
                if age_hours > max_age_hours:
                    errors.append(
                        f"VPEC too old: {age_hours:.1f}h (max {max_age_hours}h)"
                    )
            except (ValueError, TypeError):
                warnings.append(f"Could not parse signed_at: {signed_at}")

    passed = len(errors) == 0

    evidence_parts: list[str] = []
    if passed:
        evidence_parts.append(f"VPEC {vpec.get('vpec_id', '?')} verified")
        evidence_parts.append(f"org={vpec.get('org_id', '?')}")
        evidence_parts.append(f"proof_level={vpec.get('proof_level_floor', '?')}")
    else:
        evidence_parts.append(f"{len(errors)} verification error(s)")

    details: dict[str, Any]
    if passed:
        details = {
            "vpec_id": vpec.get("vpec_id"),
            "upstream_org_id": vpec.get("org_id"),
            "proof_level_floor": vpec.get("proof_level_floor"),
            "errors": errors,
            "warnings": warnings,
            "verification_mode": verification_mode,
        }
    else:
        details = {
            "errors": errors,
            "warnings": warnings,
        }

    return CheckResult(
        passed=passed,
        check_id="upstream_vpec_verify",
        evidence="; ".join(evidence_parts),
        details=details,
        proof_ceiling="mathematical",
    )
