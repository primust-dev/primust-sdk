"""
BYOK (Bring Your Own Key) signing key management.

Enterprise orgs can register their own Ed25519 signing keys.
Primust NEVER holds the org's private key.

POST /api/v1/org/signing-keys         — register a new public key
POST /api/v1/org/signing-keys/{id}/verify — challenge-response verification
GET  /api/v1/org/signing-keys         — list org's signing keys
DELETE /api/v1/org/signing-keys/{id}  — revoke a signing key
"""

from __future__ import annotations

import logging
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ..auth import AuthContext, require_jwt
from ..db import execute, fetch_all, fetch_one

logger = logging.getLogger("primust.signing_keys")

router = APIRouter(prefix="/api/v1/org", tags=["signing-keys"])


# ── Request / Response schemas ──


class RegisterKeyRequest(BaseModel):
    public_key_pem: str = Field(min_length=1)
    signing_endpoint_url: str = Field(min_length=1)


class VerifyKeyRequest(BaseModel):
    challenge_signature: str = Field(min_length=1)


# ── Helpers ──


def _validate_ed25519_pem(pem_str: str) -> Ed25519PublicKey:
    """Parse and validate that PEM contains a valid Ed25519 public key."""
    try:
        key = load_pem_public_key(pem_str.encode("utf-8"))
    except Exception as exc:
        raise HTTPException(
            status_code=422, detail=f"Invalid PEM: {exc}"
        ) from exc

    if not isinstance(key, Ed25519PublicKey):
        raise HTTPException(
            status_code=422,
            detail="Key must be Ed25519. Got a different key type.",
        )
    return key


# ── POST /api/v1/org/signing-keys ──


@router.post("/signing-keys")
async def register_signing_key(
    body: RegisterKeyRequest,
    auth: AuthContext = Depends(require_jwt),
) -> dict[str, Any]:
    """Register a new BYOK signing key (admin, JWT required)."""

    # Validate PEM is a real Ed25519 public key
    _validate_ed25519_pem(body.public_key_pem)

    region = auth.org_region
    key_id = f"byok_{uuid.uuid4().hex[:12]}"
    kid = f"kid_org_{auth.org_id}_{uuid.uuid4().hex[:8]}"

    # Generate 32-byte random challenge (hex-encoded)
    challenge = os.urandom(32).hex()
    challenge_expires_at = datetime.now(timezone.utc) + timedelta(hours=1)

    await execute(
        region,
        """INSERT INTO org_signing_keys
           (key_id, org_id, kid, public_key_pem, signing_endpoint_url,
            status, challenge, challenge_expires_at, created_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)""",
        key_id,
        auth.org_id,
        kid,
        body.public_key_pem,
        body.signing_endpoint_url,
        "pending_verification",
        challenge,
        challenge_expires_at,
        datetime.now(timezone.utc),
    )

    logger.info(
        "BYOK key registered: key_id=%s kid=%s org=%s",
        key_id, kid, auth.org_id,
    )

    return {
        "key_id": key_id,
        "kid": kid,
        "challenge": challenge,
        "challenge_expires_at": challenge_expires_at.isoformat(),
    }


# ── POST /api/v1/org/signing-keys/{key_id}/verify ──


@router.post("/signing-keys/{key_id}/verify")
async def verify_signing_key(
    key_id: str,
    body: VerifyKeyRequest,
    auth: AuthContext = Depends(require_jwt),
) -> dict[str, Any]:
    """Verify a BYOK signing key via challenge-response (admin, JWT required)."""

    region = auth.org_region

    record = await fetch_one(
        region,
        "SELECT * FROM org_signing_keys WHERE key_id = $1",
        key_id,
    )
    if not record:
        raise HTTPException(status_code=404, detail="Signing key not found")

    # Enforce org ownership
    if record["org_id"] != auth.org_id:
        raise HTTPException(status_code=404, detail="Signing key not found")

    if record["status"] == "active":
        raise HTTPException(status_code=409, detail="Key already verified")

    if record["status"] == "revoked":
        raise HTTPException(status_code=409, detail="Key has been revoked")

    # Check challenge expiry
    now = datetime.now(timezone.utc)
    if not record["challenge"] or not record["challenge_expires_at"]:
        raise HTTPException(status_code=409, detail="No pending challenge")

    if now > record["challenge_expires_at"]:
        raise HTTPException(
            status_code=410,
            detail="Challenge expired. Register a new key to get a fresh challenge.",
        )

    # Verify Ed25519 signature of the challenge bytes
    pub_key = _validate_ed25519_pem(record["public_key_pem"])
    challenge_bytes = bytes.fromhex(record["challenge"])

    try:
        sig_bytes = bytes.fromhex(body.challenge_signature)
    except ValueError as exc:
        raise HTTPException(
            status_code=422, detail="challenge_signature must be hex-encoded"
        ) from exc

    try:
        pub_key.verify(sig_bytes, challenge_bytes)
    except Exception as exc:
        raise HTTPException(
            status_code=403, detail=f"Signature verification failed: {exc}"
        ) from exc

    # Verification passed — activate key
    await execute(
        region,
        """UPDATE org_signing_keys
           SET status = 'active', verified_at = $1, challenge = NULL, challenge_expires_at = NULL
           WHERE key_id = $2""",
        now,
        key_id,
    )

    logger.info("BYOK key verified: key_id=%s kid=%s org=%s", key_id, record["kid"], auth.org_id)

    return {
        "verified": True,
        "key_id": key_id,
        "kid": record["kid"],
    }


# ── GET /api/v1/org/signing-keys ──


@router.get("/signing-keys")
async def list_signing_keys(
    auth: AuthContext = Depends(require_jwt),
) -> dict[str, Any]:
    """List org's signing keys (admin, JWT required). Never returns challenge."""

    region = auth.org_region

    rows = await fetch_all(
        region,
        """SELECT key_id, kid, status, created_at, verified_at
           FROM org_signing_keys
           WHERE org_id = $1
           ORDER BY created_at DESC""",
        auth.org_id,
    )

    keys = [
        {
            "key_id": r["key_id"],
            "kid": r["kid"],
            "status": r["status"],
            "created_at": r["created_at"].isoformat() if r["created_at"] else None,
            "verified_at": r["verified_at"].isoformat() if r["verified_at"] else None,
        }
        for r in rows
    ]

    return {"keys": keys}


# ── DELETE /api/v1/org/signing-keys/{key_id} ──


@router.delete("/signing-keys/{key_id}")
async def revoke_signing_key(
    key_id: str,
    auth: AuthContext = Depends(require_jwt),
) -> dict[str, Any]:
    """Revoke a BYOK signing key (admin, JWT required)."""

    region = auth.org_region

    record = await fetch_one(
        region,
        "SELECT * FROM org_signing_keys WHERE key_id = $1",
        key_id,
    )
    if not record:
        raise HTTPException(status_code=404, detail="Signing key not found")

    if record["org_id"] != auth.org_id:
        raise HTTPException(status_code=404, detail="Signing key not found")

    if record["status"] == "revoked":
        raise HTTPException(status_code=409, detail="Key already revoked")

    now = datetime.now(timezone.utc)
    await execute(
        region,
        "UPDATE org_signing_keys SET status = 'revoked', revoked_at = $1 WHERE key_id = $2",
        now,
        key_id,
    )

    logger.info("BYOK key revoked: key_id=%s kid=%s org=%s", key_id, record["kid"], auth.org_id)

    return {"revoked": True}
