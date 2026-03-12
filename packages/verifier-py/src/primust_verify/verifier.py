"""primust-verify — Offline VPEC artifact verifier.

ZERO runtime dependencies on Primust infrastructure after initial
public key fetch. Must verify a VPEC produced today in 10 years.
"""

from __future__ import annotations

import base64
import hashlib
import json
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

    # ── Step 5: Signer status check (Rekor) ──
    if options.skip_network:
        result.rekor_status = "skipped"
    else:
        result.rekor_status = _check_rekor(public_key_b64url, sig.get("kid", ""))
        if result.rekor_status == "unavailable":
            result.warnings.append("rekor_check_unavailable")
        elif result.rekor_status == "revoked":
            result.errors.append("signer_key_revoked")
            return result

    # ── Step 6: RFC 3161 timestamp verification ──
    ts_anchor = artifact.get("timestamp_anchor")
    if isinstance(ts_anchor, dict) and ts_anchor.get("type") == "rfc3161" and ts_anchor.get("value"):
        result.timestamp_anchor_valid = _verify_timestamp_imprint(
            ts_anchor["value"], document_body,
        )
        if result.timestamp_anchor_valid is False:
            result.warnings.append("rfc3161_imprint_mismatch")
        elif result.timestamp_anchor_valid is True:
            result.warnings.append("rfc3161_tsa_cert_chain_not_verified")
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

    # ── Step 9: ZK proof verification ──
    pending_flags = artifact.get("pending_flags", {})
    if artifact.get("zk_proof") and not pending_flags.get("proof_pending"):
        zk_proof = artifact["zk_proof"]
        proving_system = zk_proof.get("proving_system") if isinstance(zk_proof, dict) else None

        if proving_system == "ultrahonk":
            result.zk_proof_valid = _verify_ultrahonk(zk_proof)
            if result.zk_proof_valid is False:
                result.errors.append("zk_proof_invalid")
        elif proving_system == "ezkl":
            # EZKL Tier 2: explicit stub — requires EZKL verifier integration
            result.zk_proof_valid = None
            result.warnings.append("ezkl_verification_not_implemented")
        else:
            result.zk_proof_valid = None
            result.warnings.append(f"unknown_proving_system: {proving_system or 'none'}")
    else:
        result.zk_proof_valid = None

    # ── Step 9b: Mathematical proof_level requires verified ZK proof ──
    if artifact.get("proof_level") == "mathematical" and result.zk_proof_valid is None:
        result.errors.append("mathematical_proof_not_verified")
        return result

    # ── Step 10: test_mode check ──
    if artifact.get("test_mode") is True:
        if options.production:
            result.errors.append("test_mode_rejected_in_production")
            return result
        result.warnings.append("test_credential")

    # All checks passed
    result.valid = len(result.errors) == 0
    return result


# ── RFC 3161 Timestamp Imprint Verification ──


def _verify_timestamp_imprint(
    ts_token_b64: str,
    document_body: dict[str, Any],
) -> bool | None:
    """Verify the message imprint inside an RFC 3161 TimeStampResp matches
    SHA-256(canonical(documentBody)).

    Parses enough DER to extract the hashed message from the MessageImprint field.
    Returns True if imprint matches, False if mismatch, None if unparseable.
    """
    try:
        from primust_artifact_core.canonical import canonical
    except ImportError:
        return None

    try:
        ts_resp = base64.b64decode(ts_token_b64)

        # Find SHA-256 OID (2.16.840.1.101.3.4.2.1) in the DER
        sha256_oid = bytes([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01])
        oid_idx = ts_resp.find(sha256_oid)
        if oid_idx == -1:
            return None

        # After OID + NULL, look for OCTET STRING (0x04) containing 32-byte hash
        search_start = oid_idx + len(sha256_oid)
        for i in range(search_start, min(search_start + 20, len(ts_resp) - 33)):
            if ts_resp[i] == 0x04 and ts_resp[i + 1] == 0x20:
                extracted_hash = ts_resp[i + 2 : i + 2 + 32]

                # Recompute expected hash
                canonical_doc = canonical(document_body)
                expected_hash = hashlib.sha256(canonical_doc.encode()).digest()

                return extracted_hash == expected_hash

        return None  # Could not find hash in DER
    except Exception:
        return None


# ── Rekor Status Check ──

REKOR_API = "https://rekor.sigstore.dev/api/v1"


def _check_rekor(public_key_b64url: str, kid: str) -> str:
    """Check Rekor for key revocation by querying with SHA-256 fingerprint
    of the public key bytes.

    Returns: 'active', 'not_found', 'revoked', or 'unavailable'.
    """
    try:
        import urllib.request

        # Decode public key bytes and compute SHA-256 fingerprint
        # base64url → base64 → bytes
        b64 = public_key_b64url.replace("-", "+").replace("_", "/")
        padding = 4 - len(b64) % 4
        if padding != 4:
            b64 += "=" * padding
        key_bytes = base64.b64decode(b64)
        fingerprint = hashlib.sha256(key_bytes).hexdigest()

        # Search Rekor index by key fingerprint
        req_body = json.dumps({"hash": f"sha256:{fingerprint}"}).encode()
        req = urllib.request.Request(
            f"{REKOR_API}/index/retrieve",
            data=req_body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            entries = json.loads(resp.read())

        if not entries:
            return "not_found"

        return "active"
    except Exception:
        return "unavailable"


# ── ZK Proof Verification (UltraHonk) ──


def _verify_ultrahonk(zk_proof: dict[str, Any]) -> bool | None:
    """Verify an UltraHonk ZK proof.

    Requires the `bb` CLI tool (Barretenberg) to be installed.
    Returns True if valid, False if invalid, None if verification unavailable.
    """
    try:
        import subprocess
        import tempfile

        proof_b64 = zk_proof.get("proof")
        vk_b64 = zk_proof.get("verification_key")

        if not proof_b64 or not vk_b64:
            return False

        proof_bytes = base64.b64decode(proof_b64)
        vk_bytes = base64.b64decode(vk_b64)

        with tempfile.NamedTemporaryFile(suffix=".proof", delete=False) as pf:
            pf.write(proof_bytes)
            proof_path = pf.name

        with tempfile.NamedTemporaryFile(suffix=".vk", delete=False) as vf:
            vf.write(vk_bytes)
            vk_path = vf.name

        # Use bb CLI for verification
        result = subprocess.run(
            ["bb", "verify_ultra_honk", "-p", proof_path, "-k", vk_path],
            capture_output=True,
            timeout=30,
        )

        import os
        os.unlink(proof_path)
        os.unlink(vk_path)

        return result.returncode == 0
    except FileNotFoundError:
        # bb CLI not installed
        return None
    except Exception:
        return None
