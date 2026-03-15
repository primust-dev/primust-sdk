"""
GET  /api/v1/manifests               — List manifests (org-scoped, JWT required).
GET  /api/v1/manifests/{manifest_id} — Get single manifest (public, no auth).
POST /api/v1/manifests               — Register a new manifest (content-addressed, idempotent).
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from ..auth import AuthContext, require_auth, require_jwt
from ..db import execute, fetch_all, fetch_one

logger = structlog.get_logger("primust.manifests")

router = APIRouter(prefix="/api/v1", tags=["manifests"])


# ── Request schemas ──


class RegisterManifestRequest(BaseModel):
    manifest: dict[str, Any]


# ── GET /api/v1/manifests ──


@router.get("/manifests")
async def list_manifests(
    auth: AuthContext = Depends(require_jwt),
) -> dict[str, Any]:
    """List manifests for the authenticated org."""
    region = auth.org_region

    rows = await fetch_all(
        region,
        "SELECT * FROM check_manifests WHERE org_id = $1 ORDER BY registered_at DESC",
        auth.org_id,
    )

    manifests = [_row_to_dict(r) for r in rows]
    return {"manifests": manifests}


# ── GET /api/v1/manifests/{manifest_id} ──


@router.get("/manifests/{manifest_id:path}")
async def get_manifest(manifest_id: str) -> dict[str, Any]:
    """Get a single manifest by ID. No auth required — manifests are public commitments."""
    # Try both regions; manifests are content-addressed so at most one copy exists
    for region in ("us", "eu"):
        row = await fetch_one(
            region,
            "SELECT * FROM check_manifests WHERE manifest_id = $1",
            manifest_id,
        )
        if row:
            return _row_to_dict(row)

    raise HTTPException(status_code=404, detail="Manifest not found")


# ── POST /api/v1/manifests ──


@router.post("/manifests", status_code=201)
async def register_manifest(
    body: RegisterManifestRequest,
    auth: AuthContext = Depends(require_auth),
) -> dict[str, Any]:
    """Register a new manifest. Content-addressed and idempotent.

    The manifest_id is computed as ``sha256:<hex>`` of the canonical JSON
    representation.  If a manifest with the same ID already exists the
    existing record is returned unchanged (INSERT … ON CONFLICT DO NOTHING).
    """
    region = auth.org_region

    # Compute content-addressed ID
    canonical = json.dumps(body.manifest, sort_keys=True, separators=(",", ":"))
    manifest_hash = hashlib.sha256(canonical.encode()).hexdigest()
    manifest_id = f"sha256:{manifest_hash}"

    # Extract metadata from the manifest payload
    check_name = body.manifest.get("check_name", body.manifest.get("name", "unknown"))
    check_version = body.manifest.get("check_version", body.manifest.get("version", "0.0.0"))

    await execute(
        region,
        """INSERT INTO check_manifests
           (manifest_id, manifest_hash, check_name, check_version, org_id,
            manifest_payload, registered_at)
           VALUES ($1, $2, $3, $4, $5, $6, NOW())
           ON CONFLICT (manifest_id) DO NOTHING""",
        manifest_id,
        manifest_hash,
        check_name,
        check_version,
        auth.org_id,
        canonical,
    )

    # Fetch the (possibly pre-existing) record to return registered_at
    row = await fetch_one(
        region,
        "SELECT registered_at FROM check_manifests WHERE manifest_id = $1",
        manifest_id,
    )

    logger.info(
        "Manifest registered",
        manifest_id=manifest_id,
        org_id=auth.org_id,
    )

    return {
        "manifest_id": manifest_id,
        "registered_at": row["registered_at"].isoformat() if row else None,
    }


# ── Helpers ──


def _row_to_dict(row: dict[str, Any]) -> dict[str, Any]:
    """Normalise a DB row into a JSON-safe dict."""
    d = dict(row)
    # Parse JSON fields stored as strings
    for key in ("manifest_payload", "checks"):
        if key in d and isinstance(d[key], str):
            try:
                d[key] = json.loads(d[key])
            except (json.JSONDecodeError, TypeError):
                pass
    # Convert datetimes to ISO strings
    for key in ("registered_at", "created_at"):
        if key in d and d[key] is not None and hasattr(d[key], "isoformat"):
            d[key] = d[key].isoformat()
    return d
