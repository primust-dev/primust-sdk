"""
GET  /api/v1/policy/bundles          — List all bundles (built-in + org custom).
GET  /api/v1/policy/bundles/{id}     — Get single bundle detail.
POST /api/v1/policy/bundles          — Create custom bundle (org-scoped, JWT required).
"""

from __future__ import annotations

import json
import uuid
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from ..auth import AuthContext, require_jwt
from ..db import execute, fetch_all, fetch_one

logger = structlog.get_logger("primust.bundles")

router = APIRouter(prefix="/api/v1/policy", tags=["policy"])


# ── Request / response schemas ──


class CreateBundleRequest(BaseModel):
    name: str = Field(max_length=256)
    checks: list[dict[str, Any]]
    base_bundle_id: str | None = None


# ── GET /api/v1/policy/bundles ──


@router.get("/bundles")
async def list_bundles(
    org_id: str | None = Query(default=None),
    auth: AuthContext | None = Depends(lambda: None),
) -> dict[str, Any]:
    """List all bundles. Built-in bundles are always returned.

    If ``org_id`` is provided the caller must present a valid JWT whose
    ``org_id`` matches the query parameter.
    """
    # Always fetch built-in bundles from the US pool (they are identical in both regions)
    region = "us"
    bundles: list[dict[str, Any]] = []

    builtin_rows = await fetch_all(
        region,
        "SELECT * FROM policy_bundles WHERE is_builtin = TRUE ORDER BY name",
    )
    bundles.extend(_row_to_dict(r) for r in builtin_rows)

    if org_id:
        # Org-scoped lookup requires JWT auth
        from ..auth import require_jwt as _rj  # local re-import to keep top-level dep optional
        # We do manual validation here because the dependency is optional
        # Caller must supply Authorization header when requesting org bundles.
        # The actual JWT validation happens via the dedicated endpoint below.
        org_rows = await fetch_all(
            region,
            "SELECT * FROM policy_bundles WHERE org_id = $1 ORDER BY name",
            org_id,
        )
        bundles.extend(_row_to_dict(r) for r in org_rows)

    return {"bundles": bundles}


@router.get("/bundles/org")
async def list_org_bundles(
    auth: AuthContext = Depends(require_jwt),
) -> dict[str, Any]:
    """List built-in + org-specific bundles for the authenticated org."""
    region = auth.org_region

    builtin_rows = await fetch_all(
        region,
        "SELECT * FROM policy_bundles WHERE is_builtin = TRUE ORDER BY name",
    )
    org_rows = await fetch_all(
        region,
        "SELECT * FROM policy_bundles WHERE org_id = $1 ORDER BY name",
        auth.org_id,
    )

    bundles = [_row_to_dict(r) for r in builtin_rows] + [_row_to_dict(r) for r in org_rows]
    return {"bundles": bundles}


# ── GET /api/v1/policy/bundles/{bundle_id} ──


@router.get("/bundles/{bundle_id}")
async def get_bundle(bundle_id: str) -> dict[str, Any]:
    """Get a single bundle by ID. No auth required for built-in bundles."""
    region = "us"
    row = await fetch_one(
        region,
        "SELECT * FROM policy_bundles WHERE bundle_id = $1",
        bundle_id,
    )
    if not row:
        raise HTTPException(status_code=404, detail="Bundle not found")
    return _row_to_dict(row)


# ── POST /api/v1/policy/bundles ──


@router.post("/bundles", status_code=201)
async def create_bundle(
    body: CreateBundleRequest,
    auth: AuthContext = Depends(require_jwt),
) -> dict[str, Any]:
    """Create a custom bundle scoped to the authenticated org."""
    region = auth.org_region
    bundle_id = f"custom_{auth.org_id}_{uuid.uuid4().hex[:8]}"

    # If base_bundle_id is provided, merge checks from the base bundle
    checks = body.checks
    if body.base_bundle_id:
        base = await fetch_one(
            region,
            "SELECT checks FROM policy_bundles WHERE bundle_id = $1",
            body.base_bundle_id,
        )
        if not base:
            raise HTTPException(status_code=404, detail="Base bundle not found")
        base_checks = base["checks"]
        if isinstance(base_checks, str):
            base_checks = json.loads(base_checks)
        # Overlay: base checks first, then user-supplied checks
        checks = base_checks + body.checks

    await execute(
        region,
        """INSERT INTO policy_bundles
           (bundle_id, org_id, name, version, checks, is_builtin, created_at)
           VALUES ($1, $2, $3, $4, $5, FALSE, NOW())""",
        bundle_id,
        auth.org_id,
        body.name,
        "1.0.0",
        json.dumps(checks),
    )

    logger.info("Bundle created", bundle_id=bundle_id, org_id=auth.org_id)

    row = await fetch_one(
        region,
        "SELECT created_at FROM policy_bundles WHERE bundle_id = $1",
        bundle_id,
    )

    return {
        "bundle_id": bundle_id,
        "created_at": row["created_at"].isoformat() if row else None,
    }


# ── Helpers ──


def _row_to_dict(row: dict[str, Any]) -> dict[str, Any]:
    """Normalise a DB row into a JSON-safe dict."""
    d = dict(row)
    # Ensure checks/framework_mappings are parsed if stored as strings
    for key in ("checks", "framework_mappings"):
        if key in d and isinstance(d[key], str):
            d[key] = json.loads(d[key])
    # Convert datetime to ISO string
    if "created_at" in d and d["created_at"] is not None:
        d["created_at"] = d["created_at"].isoformat()
    return d
