"""primust-verify — Offline VPEC artifact verifier.

ZERO runtime dependencies on Primust infrastructure after initial
public key fetch. Must verify a VPEC produced today in 10 years.
"""

from __future__ import annotations

import re
from typing import Any, Optional

from primust_artifact_core.validate_artifact import validate_artifact
from primust_artifact_core.signing import verify as ed25519_verify
from primust_artifact_core.types import SignatureEnvelope

from primust_verify.key_cache import get_key
from primust_verify.types import VerifyOptions, VerificationResult


def _has_reliance_mode(obj: dict[str, Any], path: str = "") -> Optional[str]:
    """Recursively check for reliance_mode field anywhere."""
    for key, value in obj.items():
        current_path = f"{path}.{key}" if path else key
        if key == "reliance_mode":
            return current_path
        if isinstance(value, dict):
            found = _has_reliance_mode(value, current_path)
            if found:
                return found
    return None


def _base_result(artifact: dict[str, Any]) -> VerificationResult:
    """Build a default VerificationResult from an artifact dict."""
    sig = artifact.get("signature") or {}
    issuer = artifact.get("issuer") or {}
    proof_dist = artifact.get("proof_distribution") or {}
    coverage = artifact.get("coverage") or {}
    gaps_raw = artifact.get("gaps", [])

    gaps = []
    if isinstance(gaps_raw, list):
        for g in gaps_raw:
            if isinstance(g, dict):
                gaps.append({
                    "gap_id": g.get("gap_id", ""),
                    "gap_type": g.get("gap_type", ""),
                    "severity": g.get("severity", ""),
                })

    return VerificationResult(
        vpec_id=artifact.get("vpec_id", ""),
        valid=False,
        schema_version=artifact.get("schema_version", ""),
        proof_level=artifact.get("proof_level", ""),
        proof_distribution=proof_dist if isinstance(proof_dist, dict) else {},
        org_id=artifact.get("org_id", ""),
        workflow_id=artifact.get("workflow_id", ""),
        process_context_hash=artifact.get("process_context_hash"),
        partial=artifact.get("partial", False),
        test_mode=artifact.get("test_mode", False),
        signer_id=issuer.get("signer_id", "") or sig.get("signer_id", ""),
        kid=issuer.get("kid", "") or sig.get("kid", ""),
        signed_at=sig.get("signed_at", ""),
        timestamp_anchor_valid=None,
        rekor_status="skipped",
        zk_proof_valid=None,
        manifest_hashes={},
        gaps=gaps,
        coverage=coverage if isinstance(coverage, dict) else {},
        errors=[],
        warnings=[],
    )


def _extract_key_from_pem(pem: str) -> str:
    """Extract base64url key from PEM or raw base64url string."""
    if "-----BEGIN" in pem:
        b64 = re.sub(r"-----[A-Z ]+-----", "", pem).strip()
        b64 = b64.replace("\n", "").replace("\r", "")
        return b64.replace("+", "-").replace("/", "_").rstrip("=")
    return pem.strip()


def verify(
    artifact: dict[str, Any],
    options: Optional[VerifyOptions] = None,
) -> VerificationResult:
    """Verify a VPEC artifact.

    Args:
        artifact: Parsed artifact JSON dict.
        options: Verification options.

    Returns:
        VerificationResult with errors/warnings.
    """
    if options is None:
        options = VerifyOptions()

    result = _base_result(artifact)

    # ── Step 1: Schema validation ──
    schema_result = validate_artifact(artifact)
    if not schema_result.valid:
        for err in schema_result.errors:
            if err.code == "RELIANCE_MODE_FORBIDDEN":
                result.errors.append("banned_field_reliance_mode")
            elif err.code == "MANIFEST_HASHES_NOT_MAP":
                result.errors.append("manifest_hashes_not_object")
            else:
                result.errors.append(f"schema_validation_failed: {err.code}")
        return result

    # Extra check: reliance_mode anywhere
    reliance_path = _has_reliance_mode(artifact)
    if reliance_path:
        result.errors.append("banned_field_reliance_mode")
        return result

    # ── Step 4 (early): Kid resolution ──
    issuer = artifact.get("issuer", {})
    sig = artifact.get("signature", {})

    if not issuer or not sig:
        result.errors.append("missing_issuer_or_signature")
        return result

    if issuer.get("kid") != sig.get("kid"):
        result.errors.append("kid_mismatch")
        return result

    # ── Step 2+3: Integrity + Ed25519 signature ──
    document_body = {k: v for k, v in artifact.items() if k != "signature"}

    # Resolve public key
    try:
        pem = get_key(
            sig["kid"],
            issuer.get("public_key_url", ""),
            options.trust_root,
        )
        public_key_b64url = _extract_key_from_pem(pem)
    except Exception as e:
        result.errors.append(str(e))
        return result

    signature_envelope = SignatureEnvelope(
        signer_id=sig.get("signer_id", ""),
        kid=sig.get("kid", ""),
        algorithm=sig.get("algorithm", "Ed25519"),
        signature=sig.get("signature", ""),
        signed_at=sig.get("signed_at", ""),
    )

    sig_valid = ed25519_verify(document_body, signature_envelope, public_key_b64url)
    if not sig_valid:
        result.errors.append("integrity_check_failed")
        return result

    # ── Step 5: Signer status check (Rekor — stubbed in v1) ──
    if options.skip_network:
        result.rekor_status = "skipped"
    else:
        # TODO: Integrate with Sigstore Rekor for key revocation events
        result.rekor_status = "unavailable"
        result.warnings.append("rekor_check_not_implemented")

    # ── Step 6: RFC 3161 timestamp verification (stubbed in v1) ──
    ts_anchor = artifact.get("timestamp_anchor")
    if isinstance(ts_anchor, dict) and ts_anchor.get("type") == "rfc3161":
        # TODO: Verify RFC 3161 token against TSA certificate chain
        result.timestamp_anchor_valid = None
        result.warnings.append("rfc3161_verification_not_implemented")
    else:
        result.timestamp_anchor_valid = None

    # ── Step 7: Proof level integrity ──
    proof_dist = artifact.get("proof_distribution", {})
    if artifact.get("proof_level") != proof_dist.get("weakest_link"):
        result.errors.append("proof_level_mismatch")
        return result

    # ── Step 8: Manifest hash audit ──
    manifest_hashes = artifact.get("manifest_hashes", {})
    if isinstance(manifest_hashes, dict):
        result.manifest_hashes = manifest_hashes

    # ── Step 9: ZK proof verification (stubbed in v1) ──
    pending_flags = artifact.get("pending_flags", {})
    if artifact.get("zk_proof") and not pending_flags.get("proof_pending"):
        # TODO: Verify via Barretenberg WASM (ultrahonk) or EZKL
        result.zk_proof_valid = None
        result.warnings.append("zk_proof_verification_not_implemented")
    else:
        result.zk_proof_valid = None

    # ── Step 10: test_mode check ──
    if artifact.get("test_mode") is True:
        if options.production:
            result.errors.append("test_mode_rejected_in_production")
            return result
        result.warnings.append("test_credential")

    # All checks passed
    result.valid = len(result.errors) == 0
    return result
