"""Evidence Pack operations: verify and assemble.

Commands:
  primust pack verify <pack.json>
  primust pack assemble --artifacts a.json b.json --period-start ... --period-end ... --output pack.json
  primust pack assemble ... --dry-run
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from primust_verify.verifier import verify
from primust_verify.types import VerifyOptions


@dataclass
class PackVerifyResult:
    pack_id: str
    valid: bool
    artifact_count: int
    coverage_verified_pct: float
    coverage_pending_pct: float
    coverage_ungoverned_pct: float
    errors: list[str]


def verify_pack(
    pack: dict[str, Any],
    options: Optional[VerifyOptions] = None,
) -> PackVerifyResult:
    """Verify an evidence pack.

    Checks:
    - pack_id present
    - signature present
    - report_hash matches recomputed hash
    - coverage buckets sum to 100
    """
    errors: list[str] = []

    pack_id = pack.get("pack_id", "")
    if not pack_id:
        errors.append("missing_pack_id")

    sig = pack.get("signature")
    if not sig or (isinstance(sig, dict) and not sig.get("signature")):
        errors.append("missing_signature")

    # Verify report hash
    artifact_ids = pack.get("artifact_ids", [])
    proof_dist = pack.get("proof_distribution", {})
    expected_content = json.dumps(
        {"artifact_ids": artifact_ids, "proof_distribution": proof_dist},
        sort_keys=True,
    )
    expected_hash = "sha256:" + hashlib.sha256(expected_content.encode()).hexdigest()
    if pack.get("report_hash") and pack["report_hash"] != expected_hash:
        errors.append("report_hash_mismatch")

    # Coverage buckets
    v = pack.get("coverage_verified_pct", 0) or 0
    p = pack.get("coverage_pending_pct", 0) or 0
    u = pack.get("coverage_ungoverned_pct", 0) or 0
    if abs((v + p + u) - 100) > 0.01:
        errors.append("coverage_buckets_not_100")

    return PackVerifyResult(
        pack_id=pack_id,
        valid=len(errors) == 0,
        artifact_count=len(artifact_ids),
        coverage_verified_pct=v,
        coverage_pending_pct=p,
        coverage_ungoverned_pct=u,
        errors=errors,
    )


@dataclass
class AssembleResult:
    artifact_count: int
    artifact_ids: list[str]
    coverage_verified_pct: float
    coverage_pending_pct: float
    coverage_ungoverned_pct: float
    commitment_count: int
    dry_run: bool
    output_path: Optional[str]


def assemble_pack(
    artifact_paths: list[str],
    period_start: str,
    period_end: str,
    output_path: Optional[str] = None,
    dry_run: bool = False,
    api_url: Optional[str] = None,
) -> AssembleResult:
    """Assemble an evidence pack from artifact files.

    In dry-run mode: prints what would be sent, makes ZERO API calls.
    """
    artifacts: list[dict[str, Any]] = []
    for path in artifact_paths:
        raw = Path(path).read_text()
        artifacts.append(json.loads(raw))

    artifact_ids = [a.get("vpec_id", "") for a in artifacts]

    # Aggregate coverage
    total_verified = 0.0
    total_pending = 0.0
    total_ungoverned = 0.0
    commitment_count = 0

    for a in artifacts:
        cov = a.get("coverage", {})
        total_verified += cov.get("policy_coverage_pct", 0) or 0
        manifest_hashes = a.get("manifest_hashes", {})
        if isinstance(manifest_hashes, dict):
            commitment_count += len(manifest_hashes)

    n = len(artifacts) or 1
    avg_verified = total_verified / n
    avg_pending = 0.0
    avg_ungoverned = 100.0 - avg_verified

    if dry_run:
        return AssembleResult(
            artifact_count=len(artifacts),
            artifact_ids=artifact_ids,
            coverage_verified_pct=round(avg_verified, 1),
            coverage_pending_pct=round(avg_pending, 1),
            coverage_ungoverned_pct=round(avg_ungoverned, 1),
            commitment_count=commitment_count,
            dry_run=True,
            output_path=None,
        )

    # Build pack JSON
    proof_dist: dict[str, int] = {
        "mathematical": 0,
        "execution_zkml": 0,
        "execution": 0,
        "witnessed": 0,
        "attestation": 0,
    }
    for a in artifacts:
        dist = a.get("proof_distribution", {})
        for level in proof_dist:
            proof_dist[level] += dist.get(level, 0) if isinstance(dist.get(level), int) else 0

    report_content = json.dumps(
        {"artifact_ids": artifact_ids, "proof_distribution": proof_dist},
        sort_keys=True,
    )
    report_hash = "sha256:" + hashlib.sha256(report_content.encode()).hexdigest()

    pack = {
        "pack_id": f"pack_local_{hashlib.sha256(report_content.encode()).hexdigest()[:16]}",
        "period_start": period_start,
        "period_end": period_end,
        "artifact_ids": artifact_ids,
        "proof_distribution": proof_dist,
        "coverage_verified_pct": round(avg_verified, 1),
        "coverage_pending_pct": round(avg_pending, 1),
        "coverage_ungoverned_pct": round(avg_ungoverned, 1),
        "report_hash": report_hash,
        "signature": None,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

    out = output_path or "pack.json"
    Path(out).write_text(json.dumps(pack, indent=2))

    return AssembleResult(
        artifact_count=len(artifacts),
        artifact_ids=artifact_ids,
        coverage_verified_pct=round(avg_verified, 1),
        coverage_pending_pct=round(avg_pending, 1),
        coverage_ungoverned_pct=round(avg_ungoverned, 1),
        commitment_count=commitment_count,
        dry_run=False,
        output_path=out,
    )


def format_dry_run(result: AssembleResult) -> str:
    """Format dry-run output per spec."""
    ids_str = ", ".join(result.artifact_ids)
    return (
        "=== PRIMUST DRY RUN — Nothing was sent ===\n"
        "\n"
        "Would send to api.primust.com: POST /api/v1/packs\n"
        f"Artifacts: {result.artifact_count} ({ids_str})\n"
        f"Coverage: {result.coverage_verified_pct}% verified · "
        f"{result.coverage_pending_pct}% pending · "
        f"{result.coverage_ungoverned_pct}% ungoverned\n"
        "\n"
        "Data transmitted:\n"
        "  Raw content:         NONE\n"
        f"  Commitment hashes:   {result.commitment_count}\n"
        "  Normalized metadata: org_id, workflow_ids, timestamps, gap counts\n"
        "\n"
        "=== End dry run ==="
    )
