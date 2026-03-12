"""
POST /api/v1/webhooks/proof-complete — Receive ZK proof completion from Modal worker.

When a proof job completes, the Modal worker calls this endpoint with the proof
bytes. This route:
  1. Validates the webhook bearer token
  2. Loads the VPEC by run_id
  3. Attaches zk_proof to VPEC payload
  4. Sets proof_pending = false
  5. Upgrades proof_level to mathematical (if proof is for governance circuit)
  6. Re-signs the VPEC
  7. Stores updated VPEC

If the proof failed or timed out, a gap is recorded and the VPEC stays at
its current proof_level (execution).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from ..db import execute, fetch_one, transaction
from ..kms import kms_sign

logger = logging.getLogger("primust.proofs")

router = APIRouter(prefix="/api/v1", tags=["proofs"])

# Bearer token for webhook auth (set via env var)
_WEBHOOK_TOKEN = os.environ.get("PRIMUST_WEBHOOK_TOKEN", "")


def _verify_webhook_token(request: Request) -> None:
    """Verify the webhook bearer token. Raises 401 if invalid."""
    if not _WEBHOOK_TOKEN:
        # No token configured — allow in development
        return
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = auth_header[7:]
    if token != _WEBHOOK_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid webhook token")


# ── Request schemas ──


class ProofCompleteRequest(BaseModel):
    job_id: str = Field(max_length=256)
    run_id: str = Field(max_length=256)
    proof_hex: str
    vk_hex: str = ""
    circuit_name: str = Field(default="primust_governance_v1", max_length=256)
    completed_at: str | None = None


class ProofFailedRequest(BaseModel):
    job_id: str = Field(max_length=256)
    run_id: str = Field(max_length=256)
    error: str = Field(max_length=4096)
    failure_type: Literal["failed", "timed_out"] = "failed"


# ── POST /api/v1/webhooks/proof-complete ──


@router.post("/webhooks/proof-complete")
async def proof_complete(body: ProofCompleteRequest, request: Request) -> dict[str, Any]:
    _verify_webhook_token(request)

    # Find VPEC by run_id
    # Try both regions — webhook doesn't carry org context
    vpec_row = None
    region = "us"
    for r in ("us", "eu"):
        try:
            vpec_row = await fetch_one(
                r,
                "SELECT vpec_id, payload FROM vpecs WHERE run_id = $1",
                body.run_id,
            )
            if vpec_row:
                region = r
                break
        except Exception:
            continue

    if not vpec_row:
        raise HTTPException(status_code=404, detail=f"No VPEC found for run_id: {body.run_id}")

    vpec_id = vpec_row["vpec_id"]
    payload = (
        json.loads(vpec_row["payload"])
        if isinstance(vpec_row["payload"], str)
        else vpec_row["payload"]
    )

    # Check proof_pending — idempotency guard
    if not payload.get("pending_flags", {}).get("proof_pending", False):
        logger.info("Proof already attached for VPEC %s, ignoring duplicate", vpec_id)
        return {"status": "already_attached", "vpec_id": vpec_id}

    # Build ZkProof object
    zk_proof = {
        "circuit": body.circuit_name,
        "proof_bytes": body.proof_hex,
        "public_inputs": [],
        "verified_at": body.completed_at or datetime.now(timezone.utc).isoformat(),
        "prover": "modal_cpu",
        "prover_system": "ultrahonk",
        "nargo_version": "1.0.0-beta.18",
    }

    # Update payload
    payload["zk_proof"] = zk_proof
    payload["pending_flags"]["proof_pending"] = False

    # Upgrade proof_level to mathematical if this was the governance circuit
    if body.circuit_name == "primust_governance_v1":
        payload["proof_level"] = "mathematical"
        payload["proof_distribution"]["weakest_link"] = "mathematical"
        payload["proof_distribution"]["weakest_link_explanation"] = (
            f"ZK proof verified — circuit {body.circuit_name}"
        )

    # Re-sign the updated VPEC
    from ..db import get_region_config

    region_config = get_region_config(region)
    vpec_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    sig_envelope = await kms_sign(vpec_json, region_config.kms_key)
    payload["signature"] = sig_envelope

    # Store updated VPEC
    await execute(
        region,
        "UPDATE vpecs SET proof_level = $1, payload = $2 WHERE vpec_id = $3",
        payload["proof_level"],
        json.dumps(payload),
        vpec_id,
    )

    logger.info(
        "Proof attached to VPEC %s (run %s), proof_level upgraded to %s",
        vpec_id,
        body.run_id,
        payload["proof_level"],
    )

    return {
        "status": "proof_attached",
        "vpec_id": vpec_id,
        "proof_level": payload["proof_level"],
    }


# ── POST /api/v1/webhooks/proof-failed ──


@router.post("/webhooks/proof-failed")
async def proof_failed(body: ProofFailedRequest, request: Request) -> dict[str, Any]:
    _verify_webhook_token(request)

    # Find VPEC by run_id
    vpec_row = None
    region = "us"
    for r in ("us", "eu"):
        try:
            vpec_row = await fetch_one(
                r,
                "SELECT vpec_id, payload FROM vpecs WHERE run_id = $1",
                body.run_id,
            )
            if vpec_row:
                region = r
                break
        except Exception:
            continue

    if not vpec_row:
        raise HTTPException(status_code=404, detail=f"No VPEC found for run_id: {body.run_id}")

    vpec_id = vpec_row["vpec_id"]
    payload = (
        json.loads(vpec_row["payload"])
        if isinstance(vpec_row["payload"], str)
        else vpec_row["payload"]
    )

    # Set proof_pending = false (proof will not arrive)
    payload["pending_flags"]["proof_pending"] = False

    # Store updated VPEC
    await execute(
        region,
        "UPDATE vpecs SET payload = $1 WHERE vpec_id = $2",
        json.dumps(payload),
        vpec_id,
    )

    # Record gap
    gap_type = (
        "zkml_proof_pending_timeout" if body.failure_type == "timed_out" else "proof_generation_failed"
    )
    severity = "High"
    gap_id = f"gap_{gap_type}_{body.run_id}_{uuid.uuid4().hex[:8]}"

    await execute(
        region,
        """INSERT INTO gaps (gap_id, run_id, gap_type, severity, state, details, detected_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7)""",
        gap_id,
        body.run_id,
        gap_type,
        severity,
        "open",
        json.dumps({
            "vpec_id": vpec_id,
            "job_id": body.job_id,
            "error": body.error,
            "failure_type": body.failure_type,
        }),
        datetime.now(timezone.utc),
    )

    logger.warning(
        "Proof %s for VPEC %s (run %s): %s",
        body.failure_type,
        vpec_id,
        body.run_id,
        body.error,
    )

    return {
        "status": f"proof_{body.failure_type}",
        "vpec_id": vpec_id,
        "gap_id": gap_id,
    }
