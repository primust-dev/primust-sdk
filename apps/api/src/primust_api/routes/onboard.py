"""
Primust onboarding routes — sandbox key issuance and API key management.

POST /api/v1/onboard  — Create org + issue sandbox key (one-time reveal)
GET  /api/v1/settings/api-keys — List redacted API keys for org
"""

from __future__ import annotations

import hashlib
import logging
import secrets

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from ..auth import AuthContext, require_jwt
from ..db import execute, fetch_all, fetch_one, transaction

logger = logging.getLogger("primust.onboard")

router = APIRouter(prefix="/api/v1", tags=["onboard"])


# ── Response models ──


class OnboardResponse(BaseModel):
    api_key: str | None = None
    org_id: str
    org_region: str
    already_existed: bool


class RedactedKey(BaseModel):
    key_id: str
    key_type: str
    prefix: str
    created_at: str
    status: str


class ApiKeysResponse(BaseModel):
    keys: list[RedactedKey]


# ── POST /api/v1/onboard ──


@router.post("/onboard", response_model=OnboardResponse)
async def onboard(ctx: AuthContext = Depends(require_jwt)) -> OnboardResponse:
    """
    Onboard a new organization and issue a sandbox API key.

    The sandbox key is returned exactly once. If the org already has a sandbox key,
    the response indicates this without revealing the key again.
    """
    org_id = ctx.org_id
    region = ctx.org_region

    # Upsert organization record
    existing_org = await fetch_one(
        region,
        "SELECT org_id FROM organizations WHERE org_id = $1",
        org_id,
    )

    if not existing_org:
        await execute(
            region,
            """
            INSERT INTO organizations (org_id, org_region, created_by)
            VALUES ($1, $2, $3)
            ON CONFLICT (org_id) DO NOTHING
            """,
            org_id,
            region,
            ctx.user_id,
        )
        logger.info("Created organization org_id=%s region=%s", org_id, region)

    # Check for existing sandbox key
    existing_key = await fetch_one(
        region,
        "SELECT key_hash FROM api_keys WHERE org_id = $1 AND key_type = 'sandbox' AND status = 'active'",
        org_id,
    )

    if existing_key:
        return OnboardResponse(
            api_key=None,
            org_id=org_id,
            org_region=region,
            already_existed=True,
        )

    # Generate sandbox key
    raw_secret = secrets.token_hex(16)
    key_string = f"pk_sb_{org_id}_{region}_{raw_secret}"
    key_hash = hashlib.sha256(key_string.encode()).hexdigest()

    # Store hashed key — plaintext is never persisted
    async with transaction(region) as conn:
        await conn.execute(
            """
            INSERT INTO api_keys (key_hash, org_id, status, key_type)
            VALUES ($1, $2, 'active', 'sandbox')
            """,
            key_hash,
            org_id,
        )

    logger.info("Issued sandbox key for org_id=%s region=%s", org_id, region)

    return OnboardResponse(
        api_key=key_string,
        org_id=org_id,
        org_region=region,
        already_existed=False,
    )


# ── GET /api/v1/settings/api-keys ──


def _redact_key_hash(key_hash: str, key_type: str) -> str:
    """
    Build a redacted display prefix from the key type and hash.
    Since we only store the hash, show pk_{type}_...{last4 of hash}.
    """
    suffix = key_hash[-4:]
    type_prefix = "sb" if key_type == "sandbox" else key_type
    return f"pk_{type_prefix}_...{suffix}"


@router.get("/settings/api-keys", response_model=ApiKeysResponse)
async def list_api_keys(ctx: AuthContext = Depends(require_jwt)) -> ApiKeysResponse:
    """List all API keys for the authenticated org (redacted)."""
    rows = await fetch_all(
        ctx.org_region,
        """
        SELECT key_hash, key_type, status, created_at
        FROM api_keys
        WHERE org_id = $1
        ORDER BY created_at DESC
        """,
        ctx.org_id,
    )

    keys = [
        RedactedKey(
            key_id=row["key_hash"][:12],
            key_type=row["key_type"],
            prefix=_redact_key_hash(row["key_hash"], row["key_type"]),
            created_at=row["created_at"].isoformat(),
            status=row["status"],
        )
        for row in rows
    ]

    return ApiKeysResponse(keys=keys)
