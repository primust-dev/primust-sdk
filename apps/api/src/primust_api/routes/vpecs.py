"""
GET /api/v1/vpecs/{vpec_id} — Retrieve VPEC by ID.
"""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from ..auth import AuthContext, require_jwt
from ..db import fetch_one

router = APIRouter(prefix="/api/v1", tags=["vpecs"])


@router.get("/vpecs/{vpec_id}")
async def get_vpec(
    vpec_id: str,
    auth: AuthContext = Depends(require_jwt),
) -> dict[str, Any]:
    row = await fetch_one(
        auth.org_region,
        "SELECT payload FROM vpecs WHERE vpec_id = $1 AND org_id = $2",
        vpec_id,
        auth.org_id,
    )
    if not row:
        raise HTTPException(status_code=404, detail="VPEC not found")

    payload = row["payload"]
    if isinstance(payload, str):
        payload = json.loads(payload)
    return payload
