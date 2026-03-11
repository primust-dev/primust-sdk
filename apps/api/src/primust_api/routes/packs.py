"""
POST /api/v1/packs — Assemble Evidence Pack.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from ..auth import AuthContext, require_jwt
from ..banned import reject_banned_fields
from ..db import execute, fetch_all, fetch_one

router = APIRouter(prefix="/api/v1", tags=["packs"])


class CreatePackRequest(BaseModel):
    artifact_ids: list[str]
    period_start: str
    period_end: str


@router.post("/packs")
async def create_pack(
    body: CreatePackRequest,
    auth: AuthContext = Depends(require_jwt),
) -> dict[str, Any]:
    reject_banned_fields(body.model_dump())

    region = auth.org_region

    if not body.artifact_ids:
        raise HTTPException(status_code=422, detail="At least one artifact_id required")

    # Load all artifacts
    artifacts = []
    for vpec_id in body.artifact_ids:
        row = await fetch_one(
            region,
            "SELECT payload FROM vpecs WHERE vpec_id = $1 AND org_id = $2",
            vpec_id,
            auth.org_id,
        )
        if not row:
            raise HTTPException(status_code=404, detail=f"VPEC {vpec_id} not found")
        payload = row["payload"]
        if isinstance(payload, str):
            payload = json.loads(payload)
        artifacts.append(payload)

    # Aggregate proof distribution
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
            proof_dist[level] += dist.get(level, 0)

    # Aggregate gap summary
    gap_summary = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for a in artifacts:
        for gap in a.get("gaps", []):
            sev = gap.get("severity", "Informational")
            if sev in gap_summary:
                gap_summary[sev] += 1

    # Build observation summary
    surfaces: dict[str, str] = {}
    for a in artifacts:
        for s in a.get("surface_summary", []):
            sid = s.get("surface_id", "")
            if sid and sid not in surfaces:
                surfaces[sid] = s.get("surface_coverage_statement", "")
    observation_summary = [
        {"surface_id": k, "surface_coverage_statement": v} for k, v in surfaces.items()
    ]

    # Build pack
    pack_id = f"pack_{uuid.uuid4().hex[:16]}"
    now = datetime.now(timezone.utc).isoformat()

    # Report hash
    report_content = json.dumps(
        {"artifact_ids": body.artifact_ids, "proof_distribution": proof_dist},
        sort_keys=True,
    )
    report_hash = "sha256:" + hashlib.sha256(report_content.encode()).hexdigest()

    pack = {
        "pack_id": pack_id,
        "org_id": auth.org_id,
        "period_start": body.period_start,
        "period_end": body.period_end,
        "artifact_ids": body.artifact_ids,
        "merkle_root": "poseidon2:" + "0" * 64,  # stub — production uses buildCommitmentRoot
        "proof_distribution": proof_dist,
        "coverage_verified_pct": 100,
        "coverage_pending_pct": 0,
        "coverage_ungoverned_pct": 0,
        "observation_summary": observation_summary,
        "gap_summary": gap_summary,
        "report_hash": report_hash,
        "signature": {
            "signer_id": "api_signer",
            "kid": "kid_api",
            "algorithm": "Ed25519",
            "signature": "stub_pending_kms",
            "signed_at": now,
        },
        "generated_at": now,
    }

    # Store
    await execute(
        region,
        """INSERT INTO evidence_packs
           (pack_id, org_id, period_start, period_end, artifact_ids, merkle_root,
            proof_distribution, coverage_verified_pct, coverage_pending_pct,
            coverage_ungoverned_pct, observation_summary, gap_summary,
            report_hash, signature, generated_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)""",
        pack_id,
        auth.org_id,
        body.period_start,
        body.period_end,
        json.dumps(body.artifact_ids),
        pack["merkle_root"],
        json.dumps(proof_dist),
        100,
        0,
        0,
        json.dumps(observation_summary),
        json.dumps(gap_summary),
        report_hash,
        json.dumps(pack["signature"]),
        now,
    )

    return pack
