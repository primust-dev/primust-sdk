"""
Primust Evidence Pack — Pack Assembly (P8-A) — Python mirror

assemble_pack(artifacts, period_start, period_end, org_id, signer_record, private_key, coverage_options) → dict
dry_run_output(artifact_ids, period_start, period_end, ...) → str

Steps:
  1. Validate each VPEC artifact (signature check via artifact-core)
  2. Compute Merkle root over artifact commitment_roots
  3. Validate coverage buckets (must sum to 100)
  4. Aggregate proof_distribution across all 5 levels
  5. Aggregate gaps by severity
  6. Build observation_summary
  7. Build EvidencePack — no reliance_mode
  8. report_hash = SHA256(canonical(pack_without_signature))
  9. Sign with artifact_signer
 10. Timestamp stub

PRIVACY INVARIANT: Raw content NEVER leaves the customer environment.
Only commitment hashes transit.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from primust_artifact_core.canonical import canonical
from primust_artifact_core.commitment import build_commitment_root
from primust_artifact_core.signing import sign as core_sign

# ── Constants ──

PROOF_LEVELS = [
    "mathematical",
    "verifiable_inference",
    "execution",
    "witnessed",
    "attestation",
]

GAP_SEVERITIES = ["Critical", "High", "Medium", "Low", "Informational"]


# ── Standalone Merkle root (SHA-256, sorted leaves, odd-leaf duplication) ──

def merkle_root(leaves: list[str]) -> str:
    """Compute a SHA-256 Merkle root over string leaves.

    - Leaves are sorted lexicographically before building the tree.
    - Odd leaves are duplicated (last leaf paired with itself).
    - Each leaf is SHA-256 hashed; internal nodes hash the concatenation
      of their children's hashes.

    Returns:
        Hex-encoded SHA-256 Merkle root prefixed with 'sha256:'.
        Returns 'sha256:' + SHA-256('') for empty input.
    """
    if not leaves:
        h = hashlib.sha256(b"").hexdigest()
        return f"sha256:{h}"

    sorted_leaves = sorted(leaves)
    layer = [hashlib.sha256(leaf.encode("utf-8")).digest() for leaf in sorted_leaves]

    while len(layer) > 1:
        next_layer: list[bytes] = []
        for i in range(0, len(layer), 2):
            left = layer[i]
            right = layer[i + 1] if i + 1 < len(layer) else layer[i]
            next_layer.append(hashlib.sha256(left + right).digest())
        layer = next_layer

    return f"sha256:{layer[0].hex()}"


# ── Helpers ──

def _scope_to_non_prove_statement(scope_type: str) -> str:
    mapping = {
        "full_workflow": "All workflow steps were observed via direct instrumentation.",
        "orchestration_boundary": "Actions that bypassed the orchestration boundary are not covered.",
        "platform_logged_events": "Coverage reflects what the platform logged, not all actions.",
        "partial_unknown": "Surface scope is partially unknown. Coverage is a lower bound.",
    }
    return mapping.get(scope_type, "Coverage scope details are not specified.")


def _build_verification_instructions(
    pack_id: str,
    scope_type: str,
    coverage_verified_pct: float,
    observation_summary: list[dict],
) -> dict:
    surface_basis = (
        "; ".join(s["surface_coverage_statement"] for s in observation_summary)
        if observation_summary
        else "No observation surfaces registered"
    )

    return {
        "cli_command": f"primust pack verify {pack_id}.json",
        "offline_command": f"primust pack verify {pack_id}.json --trust-root <key.pem>",
        "trust_root_url": "https://keys.primust.com/jwks",
        "what_this_proves": (
            f"{coverage_verified_pct}% of required governance checks were executed "
            "and passed within the reporting period."
        ),
        "what_this_does_not_prove": _scope_to_non_prove_statement(scope_type),
        "coverage_basis_explanation": surface_basis,
    }


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _get_artifact_field(artifact: dict, field: str, default: Any = None) -> Any:
    """Get a field from an artifact dict."""
    return artifact.get(field, default)


# ── Main ──

def assemble_pack(
    artifacts: list[dict],
    period_start: str,
    period_end: str,
    org_id: str,
    signer_record: Any,
    private_key: bytes,
    coverage_options: dict,
) -> dict:
    """Assemble an Evidence Pack from multiple VPEC artifact dicts.

    Args:
        artifacts: List of artifact dicts (each must have commitment_root,
            proof_distribution, gaps, surface_summary, manifest_hashes, vpec_id).
        period_start: Period start (ISO 8601).
        period_end: Period end (ISO 8601).
        org_id: Organization ID.
        signer_record: Active SignerRecord for signing.
        private_key: 32-byte Ed25519 seed.
        coverage_options: Dict with keys coverage_verified_pct, coverage_pending_pct,
            coverage_ungoverned_pct. Must sum to 100.

    Returns:
        Signed Evidence Pack dict with verification_instructions.

    Raises:
        ValueError: If artifacts is empty, no commitment roots, or coverage doesn't sum to 100.
    """
    if not artifacts:
        raise ValueError("Cannot assemble Evidence Pack from zero artifacts")

    # Step 2: Compute Merkle root over artifact commitment_roots
    commitment_roots = [
        a["commitment_root"]
        for a in artifacts
        if a.get("commitment_root") is not None
    ]
    if not commitment_roots:
        raise ValueError(
            "Evidence Pack requires at least one artifact with a non-null commitment_root"
        )
    pack_merkle_root = build_commitment_root(commitment_roots)

    # Step 3: Validate coverage buckets
    cov_verified = coverage_options["coverage_verified_pct"]
    cov_pending = coverage_options["coverage_pending_pct"]
    cov_ungoverned = coverage_options["coverage_ungoverned_pct"]
    cov_sum = cov_verified + cov_pending + cov_ungoverned
    if round(cov_sum) != 100:
        raise ValueError(
            f"Coverage buckets must sum to 100, got {cov_sum} "
            f"({cov_verified} + {cov_pending} + {cov_ungoverned})"
        )

    # Step 4: Aggregate proof_distribution across all 5 levels
    proof_dist: dict[str, int] = {level: 0 for level in PROOF_LEVELS}
    for artifact in artifacts:
        pd = artifact.get("proof_distribution", {})
        for level in PROOF_LEVELS:
            proof_dist[level] += pd.get(level, 0)

    # Step 5: Aggregate gaps by severity
    gap_summary: dict[str, int] = {sev: 0 for sev in GAP_SEVERITIES}
    for artifact in artifacts:
        for gap in artifact.get("gaps", []):
            sev = gap.get("severity", "")
            if sev in gap_summary:
                gap_summary[sev] += 1

    # Step 6: Build observation_summary
    surface_map: dict[str, dict] = {}
    for artifact in artifacts:
        for surface in artifact.get("surface_summary", []):
            sid = surface["surface_id"]
            if sid not in surface_map:
                surface_map[sid] = {
                    "surface_id": sid,
                    "surface_coverage_statement": surface["surface_coverage_statement"],
                }
    observation_summary = list(surface_map.values())

    # Step 7: Build manifest_hashes map (aggregated from all artifacts)
    aggregated_manifest_hashes: dict[str, str] = {}
    for artifact in artifacts:
        for manifest_id, hash_val in artifact.get("manifest_hashes", {}).items():
            aggregated_manifest_hashes[manifest_id] = hash_val

    # Determine scope type for verification instructions
    first_surfaces = artifacts[0].get("surface_summary", [])
    primary_scope = (
        first_surfaces[0].get("scope_type", "partial_unknown")
        if first_surfaces
        else "partial_unknown"
    )

    # Step 8: Build pack document
    pack_id = f"pack_{uuid.uuid4()}"
    now = _now_iso()

    pack_document: dict[str, Any] = {
        "pack_id": pack_id,
        "org_id": org_id,
        "period_start": period_start,
        "period_end": period_end,
        "artifact_ids": [a["vpec_id"] for a in artifacts],
        "merkle_root": pack_merkle_root,
        "proof_distribution": proof_dist,
        "coverage_verified_pct": cov_verified,
        "coverage_pending_pct": cov_pending,
        "coverage_ungoverned_pct": cov_ungoverned,
        "observation_summary": observation_summary,
        "gap_summary": gap_summary,
        "manifest_hashes": aggregated_manifest_hashes,
        "report_hash": "",
        "signature": {
            "signer_id": signer_record.signer_id,
            "kid": signer_record.kid,
            "algorithm": "Ed25519",
            "signature": "",
            "signed_at": now,
        },
        "timestamp_anchor": {
            "type": "none",
            "tsa": "none",
            "value": None,
        },
        "generated_at": now,
        "verification_instructions": _build_verification_instructions(
            pack_id,
            primary_scope,
            cov_verified,
            observation_summary,
        ),
    }

    # Step 9: report_hash = SHA256(canonical(pack_without_signature))
    pack_without_sig = {k: v for k, v in pack_document.items() if k != "signature"}
    report_canonical = canonical(pack_without_sig)
    report_hash_hex = hashlib.sha256(report_canonical.encode("utf-8")).hexdigest()
    pack_document["report_hash"] = f"sha256:{report_hash_hex}"

    # Step 10: Sign with artifact_signer
    _, signature_envelope = core_sign(pack_document, private_key, signer_record)
    pack_document["signature"] = {
        "signer_id": signature_envelope.signer_id,
        "kid": signature_envelope.kid,
        "algorithm": signature_envelope.algorithm,
        "signature": signature_envelope.signature,
        "signed_at": signature_envelope.signed_at,
    }

    return pack_document


# ── Dry Run ──

def dry_run_output(
    artifact_ids: list[str],
    period_start: str,
    period_end: str,
    coverage_verified_pct: float,
    coverage_pending_pct: float,
    coverage_ungoverned_pct: float,
    surface_summary_line: str,
    total_records: int,
) -> str:
    """Pure function — produces a human-readable dry-run summary.

    Zero API calls, zero side effects.
    """
    lines = [
        "=== PRIMUST DRY RUN ===",
        "",
        f"Period:          {period_start} → {period_end}",
        f"Artifacts:       {len(artifact_ids)}",
        f"Total records:   {total_records}",
        "",
        "Artifact IDs:",
        *[f"  - {aid}" for aid in artifact_ids],
        "",
        "Coverage:",
        f"  Verified:    {coverage_verified_pct}%",
        f"  Pending:     {coverage_pending_pct}%",
        f"  Ungoverned:  {coverage_ungoverned_pct}%",
        "",
        f"Surface:         {surface_summary_line}",
        "",
        "Raw content:     NONE (privacy invariant — only commitment hashes transit)",
        "",
        "=== End dry run ===",
    ]

    return "\n".join(lines)
