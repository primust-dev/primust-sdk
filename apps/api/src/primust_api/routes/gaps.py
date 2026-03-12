"""
GET  /api/v1/gaps — List gaps (filtered by run_id, state, severity).
POST /api/v1/gaps/{gap_id}/waive — Create waiver for a gap.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from ..auth import AuthContext, require_jwt
from ..banned import reject_banned_fields
from ..db import execute, fetch_all, fetch_one, get_region_config
from ..kms import kms_sign

router = APIRouter(prefix="/api/v1", tags=["gaps"])


class WaiveRequest(BaseModel):
    reason: str = Field(max_length=2000)
    approver_user_id: str = Field(max_length=256)
    compensating_control: str | None = Field(default=None, max_length=2000)
    expires_at: str | None = Field(default=None, max_length=64)


@router.get("/gaps")
async def list_gaps(
    auth: AuthContext = Depends(require_jwt),
    run_id: str | None = Query(default=None),
    state: str | None = Query(default=None),
    severity: str | None = Query(default=None),
) -> list[dict[str, Any]]:
    region = auth.org_region
    conditions = ["g.run_id = pr.run_id", "pr.org_id = $1"]
    params: list[Any] = [auth.org_id]
    idx = 2

    if run_id:
        conditions.append(f"g.run_id = ${idx}")
        params.append(run_id)
        idx += 1
    if state:
        conditions.append(f"g.state = ${idx}")
        params.append(state)
        idx += 1
    if severity:
        conditions.append(f"g.severity = ${idx}")
        params.append(severity)
        idx += 1

    where = " AND ".join(conditions)
    rows = await fetch_all(
        region,
        f"""SELECT g.* FROM gaps g
            JOIN process_runs pr ON {where}
            ORDER BY g.detected_at DESC""",
        *params,
    )
    return rows


@router.post("/gaps/{gap_id}/waive")
async def waive_gap(
    gap_id: str,
    body: WaiveRequest,
    auth: AuthContext = Depends(require_jwt),
) -> dict[str, Any]:
    reject_banned_fields(body.model_dump())

    region = auth.org_region

    # Validate gap exists
    gap = await fetch_one(
        region,
        "SELECT * FROM gaps WHERE gap_id = $1",
        gap_id,
    )
    if not gap:
        raise HTTPException(status_code=404, detail="Gap not found")

    # Verify gap belongs to org via process_run
    run = await fetch_one(
        region,
        "SELECT org_id FROM process_runs WHERE run_id = $1",
        gap["run_id"],
    )
    if not run or run["org_id"] != auth.org_id:
        raise HTTPException(status_code=404, detail="Gap not found")

    # Enforce: expires_at REQUIRED — no permanent waivers
    if not body.expires_at:
        raise HTTPException(
            status_code=422,
            detail="expires_at required — no permanent waivers allowed",
        )

    # Enforce: max 90 days
    try:
        expires = datetime.fromisoformat(body.expires_at.replace("Z", "+00:00"))
    except ValueError as e:
        raise HTTPException(status_code=422, detail=f"Invalid expires_at: {e}") from e

    now = datetime.now(timezone.utc)
    max_expiry = now + timedelta(days=90)
    if expires > max_expiry:
        raise HTTPException(
            status_code=422,
            detail="expires_at cannot be more than 90 days from now",
        )

    # Separation of duties: requestor and approver must be different users
    requestor_id = auth.user_id or "system"
    if requestor_id == body.approver_user_id:
        raise HTTPException(
            status_code=422,
            detail="Waiver requestor and approver must be different users",
        )

    waiver_id = f"waiver_{uuid.uuid4().hex[:16]}"

    # KMS-sign the waiver
    region_config = get_region_config(region)
    waiver_content = json.dumps({
        "waiver_id": waiver_id, "gap_id": gap_id,
        "reason": body.reason, "expires_at": body.expires_at,
    }, sort_keys=True, separators=(",", ":"))
    waiver_sig = await kms_sign(waiver_content, region_config.kms_key)

    await execute(
        region,
        """INSERT INTO waivers
           (waiver_id, gap_id, org_id, requestor_user_id, approver_user_id,
            reason, compensating_control, expires_at, signature, approved_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)""",
        waiver_id,
        gap_id,
        auth.org_id,
        requestor_id,
        body.approver_user_id,
        body.reason,
        body.compensating_control,
        body.expires_at,
        json.dumps(waiver_sig),
        now,
    )

    # Update gap state
    await execute(
        region,
        "UPDATE gaps SET state = 'waived' WHERE gap_id = $1",
        gap_id,
    )

    return {"waiver_id": waiver_id, "gap_id": gap_id, "expires_at": body.expires_at}
