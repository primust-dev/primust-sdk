"""
POST /api/v1/runs — Create ProcessRun + snapshot PolicyPack.
POST /api/v1/runs/{run_id}/records — Create CheckExecutionRecord.
POST /api/v1/runs/{run_id}/close — Issue signed VPEC.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from ..auth import AuthContext, require_api_key
from ..banned import reject_banned_fields
from ..db import execute, fetch_all, fetch_one, get_region_config, transaction
from ..kms import kms_sign
from ..services.webhook_dispatcher import dispatch_vpec_issued, dispatch_gap_created
from ..tsa import get_timestamp_anchor

logger = logging.getLogger("primust.runs")


async def _check_raw_body(request: Request) -> dict[str, Any]:
    """Parse raw JSON body and check for banned fields before Pydantic strips unknowns."""
    raw = await request.json()
    reject_banned_fields(raw)
    return raw

router = APIRouter(prefix="/api/v1", tags=["runs"])


# ── Request schemas ──


class CreateRunRequest(BaseModel):
    workflow_id: str = Field(max_length=256)
    surface_id: str = Field(max_length=256)
    policy_pack_id: str = Field(max_length=256)
    process_context_hash: str | None = Field(default=None, max_length=256)


class CreateRecordRequest(BaseModel):
    manifest_id: str = Field(max_length=256)
    commitment_hash: str = Field(max_length=256)
    commitment_algorithm: Literal["poseidon2", "sha256"] = "poseidon2"
    commitment_type: Literal["input_only", "input_output"] = "input_only"
    check_result: Literal["pass", "fail", "degraded", "error", "not_applicable"]
    proof_level_achieved: Literal[
        "mathematical", "verifiable_inference", "execution", "witnessed", "attestation"
    ]
    output_commitment: str | None = Field(default=None, max_length=256)
    check_open_tst: str | None = Field(default=None, max_length=64)
    check_close_tst: str | None = Field(default=None, max_length=64)
    skip_rationale_hash: str | None = Field(default=None, max_length=256)
    reviewer_credential: dict[str, Any] | None = None
    idempotency_key: str = Field(max_length=256)


class CloseRunRequest(BaseModel):
    partial: bool = False
    request_zk: bool = False


# ── POST /api/v1/runs ──


@router.post("/runs")
async def create_run(
    body: CreateRunRequest,
    auth: AuthContext = Depends(require_api_key),
    raw: dict[str, Any] = Depends(_check_raw_body),
) -> dict[str, Any]:

    region = auth.org_region
    run_id = f"run_{uuid.uuid4().hex[:16]}"
    now = datetime.now(timezone.utc)

    # Snapshot policy pack → policy snapshot
    pack = await fetch_one(
        region,
        "SELECT * FROM policy_packs WHERE policy_pack_id = $1 AND org_id = $2",
        body.policy_pack_id,
        auth.org_id,
    )
    if not pack:
        raise HTTPException(status_code=404, detail="Policy pack not found")

    snapshot_id = f"snap_{uuid.uuid4().hex[:16]}"
    policy_snapshot_hash = "sha256:" + hashlib.sha256(
        json.dumps(pack["checks"], sort_keys=True).encode()
    ).hexdigest()

    # Atomic: snapshot + run creation
    async with transaction(region) as conn:
        await conn.execute(
            """INSERT INTO policy_snapshots
               (snapshot_id, policy_pack_id, policy_pack_version, effective_checks,
                snapshotted_at, policy_basis)
               VALUES ($1, $2, $3, $4, $5, $6)""",
            snapshot_id,
            body.policy_pack_id,
            pack["version"],
            json.dumps(pack["checks"]) if isinstance(pack["checks"], list) else pack["checks"],
            now,
            "P1_self_declared",
        )

        await conn.execute(
            """INSERT INTO process_runs
               (run_id, workflow_id, org_id, surface_id, policy_snapshot_hash,
                process_context_hash, state, started_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8)""",
            run_id,
            body.workflow_id,
            auth.org_id,
            body.surface_id,
            policy_snapshot_hash,
            body.process_context_hash,
            "open",
            now,
        )

    return {
        "run_id": run_id,
        "policy_snapshot_hash": policy_snapshot_hash,
        "process_context_hash": body.process_context_hash,
    }


# ── POST /api/v1/runs/{run_id}/records ──


@router.post("/runs/{run_id}/records")
async def create_record(
    run_id: str,
    body: CreateRecordRequest,
    auth: AuthContext = Depends(require_api_key),
    raw: dict[str, Any] = Depends(_check_raw_body),
) -> dict[str, Any]:

    region = auth.org_region

    # Validate run exists and is open
    run = await fetch_one(
        region,
        "SELECT * FROM process_runs WHERE run_id = $1 AND org_id = $2",
        run_id,
        auth.org_id,
    )
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    if run["state"] != "open":
        raise HTTPException(status_code=409, detail="Run is not open")

    # Enforce: skip_rationale_hash required if check_result = not_applicable
    if body.check_result == "not_applicable" and not body.skip_rationale_hash:
        raise HTTPException(
            status_code=422,
            detail="skip_rationale_hash required when check_result = not_applicable",
        )

    # Enforce: reviewer_credential required if proof_level_achieved = witnessed
    if body.proof_level_achieved == "witnessed":
        if not body.reviewer_credential:
            raise HTTPException(
                status_code=422,
                detail="reviewer_credential required when proof_level_achieved = witnessed",
            )
        # Validate internal structure
        _REQUIRED_CRED_FIELDS = ["reviewer_key_id", "reviewer_signature", "display_hash", "rationale_hash"]
        missing = [f for f in _REQUIRED_CRED_FIELDS if not body.reviewer_credential.get(f)]
        if missing:
            raise HTTPException(
                status_code=422,
                detail=f"reviewer_credential missing required fields: {', '.join(missing)}",
            )

    record_id = f"rec_{uuid.uuid4().hex[:16]}"
    now = datetime.now(timezone.utc)

    # Compute chain_hash from previous record
    prev = await fetch_one(
        region,
        """SELECT chain_hash FROM check_execution_records
           WHERE run_id = $1 ORDER BY recorded_at DESC LIMIT 1""",
        run_id,
    )
    prev_hash = prev["chain_hash"] if prev else "genesis"
    chain_input = f"{prev_hash}:{body.commitment_hash}:{body.idempotency_key}"
    chain_hash = "sha256:" + hashlib.sha256(chain_input.encode()).hexdigest()

    # Get manifest_hash from registry
    manifest = await fetch_one(
        region,
        "SELECT manifest_hash FROM check_manifests WHERE manifest_id = $1",
        body.manifest_id,
    )
    manifest_hash = manifest["manifest_hash"] if manifest else body.manifest_id

    await execute(
        region,
        """INSERT INTO check_execution_records
           (record_id, run_id, action_unit_id, manifest_id, manifest_hash,
            surface_id, commitment_hash, output_commitment, commitment_algorithm,
            commitment_type, check_result, proof_level_achieved,
            check_open_tst, check_close_tst, skip_rationale_hash,
            reviewer_credential, chain_hash, idempotency_key, recorded_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
                   $13, $14, $15, $16, $17, $18, $19)""",
        record_id,
        run_id,
        f"au_{uuid.uuid4().hex[:8]}",  # auto-create action_unit_id
        body.manifest_id,
        manifest_hash,
        run["surface_id"],
        body.commitment_hash,
        body.output_commitment,
        body.commitment_algorithm,
        body.commitment_type,
        body.check_result,
        body.proof_level_achieved,
        body.check_open_tst,
        body.check_close_tst,
        body.skip_rationale_hash,
        json.dumps(body.reviewer_credential) if body.reviewer_credential else None,
        chain_hash,
        body.idempotency_key,
        now,
    )

    return {"record_id": record_id, "chain_hash": chain_hash}


# ── POST /api/v1/runs/{run_id}/close ──


@router.post("/runs/{run_id}/close")
async def close_run(
    run_id: str,
    body: CloseRunRequest,
    auth: AuthContext = Depends(require_api_key),
    raw: dict[str, Any] = Depends(_check_raw_body),
) -> dict[str, Any]:

    region = auth.org_region

    # Load run
    run = await fetch_one(
        region,
        "SELECT * FROM process_runs WHERE run_id = $1 AND org_id = $2",
        run_id,
        auth.org_id,
    )
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    if run["state"] != "open":
        raise HTTPException(status_code=409, detail="Run is not open")

    # Load all records
    records = await fetch_all(
        region,
        "SELECT * FROM check_execution_records WHERE run_id = $1",
        run_id,
    )

    # H6-1: Zero records guard — cannot close a run with no check records
    if not records and not body.partial:
        raise HTTPException(
            status_code=422,
            detail="Cannot close run with zero check execution records",
        )

    # H6-2: Null policySnapshot guard
    snapshot = await fetch_one(
        region,
        "SELECT snapshot_id FROM policy_snapshots WHERE snapshot_id = $1",
        run.get("policy_snapshot_hash", ""),
    )
    if not snapshot:
        # Policy snapshot is missing — emit gap but continue (don't block close)
        gap_id = f"gap_policy_snapshot_missing_{run_id}_{uuid.uuid4().hex[:8]}"
        await execute(
            region,
            """INSERT INTO gaps (gap_id, run_id, gap_type, severity, state, details, detected_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7)""",
            gap_id,
            run_id,
            "policy_config_drift",
            "Critical",
            "open",
            json.dumps({"reason": "policy_snapshot_hash resolves to no snapshot record"}),
            datetime.now(timezone.utc),
        )

    # Load gaps
    gaps = await fetch_all(
        region,
        "SELECT * FROM gaps WHERE run_id = $1",
        run_id,
    )

    now = datetime.now(timezone.utc)

    # Build proof distribution
    proof_dist = {
        "mathematical": 0,
        "verifiable_inference": 0,
        "execution": 0,
        "witnessed": 0,
        "attestation": 0,
    }
    proof_hierarchy = ["mathematical", "verifiable_inference", "execution", "witnessed", "attestation"]
    weakest_idx = 0

    for rec in records:
        level = rec["proof_level_achieved"]
        if level in proof_dist:
            proof_dist[level] += 1
        idx = proof_hierarchy.index(level) if level in proof_hierarchy else 4
        if idx > weakest_idx:
            weakest_idx = idx

    weakest_link = proof_hierarchy[weakest_idx] if records else "attestation"
    proof_dist["weakest_link"] = weakest_link
    proof_dist["weakest_link_explanation"] = f"Weakest proof level is {weakest_link}"

    # Build coverage
    total = len(records)
    pass_count = sum(1 for r in records if r["check_result"] == "pass")
    fail_count = sum(1 for r in records if r["check_result"] == "fail")
    degraded_count = sum(1 for r in records if r["check_result"] == "degraded")
    na_count = sum(1 for r in records if r["check_result"] == "not_applicable")

    coverage = {
        "records_total": total,
        "records_pass": pass_count,
        "records_fail": fail_count,
        "records_degraded": degraded_count,
        "records_not_applicable": na_count,
        "policy_coverage_pct": round(pass_count / total * 100, 1) if total > 0 else 0,
        "instrumentation_surface_pct": None,
        "instrumentation_surface_basis": None,
    }

    # Build gap entries
    gap_entries = [
        {"gap_id": g["gap_id"], "gap_type": g["gap_type"], "severity": g["severity"]}
        for g in gaps
    ]

    # Build manifest_hashes map
    manifest_hashes = {}
    for rec in records:
        manifest_hashes[rec["manifest_id"]] = rec["manifest_hash"]

    # Build VPEC (unsigned — signature and timestamp added below)
    vpec_id = f"vpec_{uuid.uuid4()}"
    vpec = {
        "vpec_id": vpec_id,
        "schema_version": "4.0.0",
        "org_id": auth.org_id,
        "run_id": run_id,
        "workflow_id": run["workflow_id"],
        "process_context_hash": run["process_context_hash"],
        "policy_snapshot_hash": run["policy_snapshot_hash"],
        "policy_basis": "P1_self_declared",
        "partial": body.partial,
        "surface_summary": [],
        "proof_level": weakest_link,
        "proof_distribution": proof_dist,
        "state": "signed",
        "coverage": coverage,
        "gaps": gap_entries,
        "manifest_hashes": manifest_hashes,
        "commitment_root": None,
        "commitment_algorithm": "sha256",
        "zk_proof": None,
        "issuer": {
            "signer_id": "api_signer",
            "kid": "kid_api",
            "algorithm": "Ed25519",
            "public_key_url": "https://keys.primust.com/jwks",
            "org_region": region,
        },
        "signature": None,  # placeholder — signed below
        "timestamp_anchor": None,  # placeholder — timestamped below
        "transparency_log": {
            "rekor_log_id": None,
            "rekor_entry_url": None,
            "published_at": None,
        },
        "issued_at": now.isoformat(),
        "pending_flags": {
            "signature_pending": False,
            "proof_pending": body.request_zk,
            "zkml_proof_pending": False,
            "submission_pending": False,
            "rekor_pending": False,
        },
        "test_mode": auth.test_mode,
    }

    # GCP KMS signing
    region_config = get_region_config(region)
    vpec_json = json.dumps(vpec, sort_keys=True, separators=(",", ":"))
    sig_envelope = await kms_sign(vpec_json, region_config.kms_key)
    vpec["signature"] = sig_envelope

    # Detect provisional (KMS failure) — set state and pending flags
    is_provisional = sig_envelope.get("algorithm") == "UNSIGNED_PENDING"
    if is_provisional:
        vpec["state"] = "provisional"
        vpec["pending_flags"]["signature_pending"] = True

    # DigiCert RFC 3161 timestamping
    vpec["timestamp_anchor"] = await get_timestamp_anchor(
        vpec_json, tsa_url=region_config.tsa_url
    )

    vpec_state = "provisional" if is_provisional else "signed"

    # Atomic: close run + store VPEC
    async with transaction(region) as conn:
        await conn.execute(
            "UPDATE process_runs SET state = 'closed', closed_at = $1 WHERE run_id = $2",
            now,
            run_id,
        )

        await conn.execute(
            """INSERT INTO vpecs
               (vpec_id, org_id, run_id, workflow_id, schema_version,
                process_context_hash, partial, proof_level, state, test_mode,
                issued_at, payload)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)""",
            vpec_id,
            auth.org_id,
            run_id,
            run["workflow_id"],
            "4.0.0",
            run["process_context_hash"],
            body.partial,
            weakest_link,
            vpec_state,
            auth.test_mode,
            now,
            json.dumps(vpec),
        )

    # Background retry: attempt to sign provisional VPECs
    if is_provisional:
        asyncio.create_task(
            _retry_kms_sign(vpec_id, vpec_json, region_config.kms_key, region)
        )

    # SIEM webhook dispatch — fire-and-forget, never blocks VPEC issuance
    await dispatch_vpec_issued(region, auth.org_id, vpec, auth.test_mode)

    # Dispatch gap_created for critical/high gaps
    for g in gap_entries:
        if g["severity"] in ("Critical", "High"):
            await dispatch_gap_created(
                region, auth.org_id, vpec, auth.test_mode,
                gap_id=g["gap_id"],
                gap_severity=g["severity"],
                gap_type=g["gap_type"],
            )

    return vpec


async def _retry_kms_sign(
    vpec_id: str,
    vpec_json: str,
    kms_key: str,
    region: str,
    max_retries: int = 10,
) -> None:
    """Background task: retry KMS signing with exponential backoff (up to ~1h)."""
    delay = 1.0
    for attempt in range(max_retries):
        await asyncio.sleep(delay)
        try:
            sig = await kms_sign(vpec_json, kms_key)
            if sig.get("algorithm") != "UNSIGNED_PENDING":
                # KMS succeeded — update VPEC in DB
                import json as _json
                row = await fetch_one(region, "SELECT payload FROM vpecs WHERE vpec_id = $1", vpec_id)
                if row:
                    payload = _json.loads(row["payload"]) if isinstance(row["payload"], str) else row["payload"]
                    payload["signature"] = sig
                    payload["state"] = "signed"
                    payload["pending_flags"]["signature_pending"] = False
                    await execute(
                        region,
                        "UPDATE vpecs SET state = 'signed', payload = $1 WHERE vpec_id = $2",
                        _json.dumps(payload),
                        vpec_id,
                    )
                logger.info("Provisional VPEC %s signed successfully on retry %d", vpec_id, attempt + 1)
                return
        except Exception:
            logger.warning(
                "KMS retry %d/%d failed for VPEC %s",
                attempt + 1, max_retries, vpec_id,
                exc_info=True,
            )
        delay = min(delay * 2, 600)  # cap at 10 minutes per retry

    # All retries exhausted — insert gap
    logger.error("KMS signing failed after %d retries for VPEC %s", max_retries, vpec_id)
    row = await fetch_one(region, "SELECT run_id FROM vpecs WHERE vpec_id = $1", vpec_id)
    if row:
        gap_id = f"gap_kms_unavailable_{row['run_id']}_{uuid.uuid4().hex[:8]}"
        await execute(
            region,
            """INSERT INTO gaps (gap_id, run_id, gap_type, severity, state, details, detected_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7)""",
            gap_id,
            row["run_id"],
            "kms_unavailable",
            "High",
            "open",
            json.dumps({"vpec_id": vpec_id, "retries_exhausted": max_retries}),
            datetime.now(timezone.utc),
        )
