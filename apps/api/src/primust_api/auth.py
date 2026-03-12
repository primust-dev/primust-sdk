"""
Primust auth — Clerk JWT + API key authentication.

- Clerk JWT: JWKS-based verification with caching (PyJWKClient, lifespan=300s).
- API key: pk_live_xxx → production, pk_test_xxx → test_mode: true.
  Hybrid validation: HMAC validates issuance (fast), DB validates status/revocation/org/type.
- All authenticated routes require one or the other.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import jwt
from fastapi import Depends, Header, HTTPException, Request

logger = logging.getLogger("primust.auth")


@dataclass
class AuthContext:
    """Resolved authentication context for a request."""

    org_id: str
    org_region: str
    test_mode: bool
    user_id: str | None = None  # set for Clerk JWT, not for API key


# ── API Key auth ──


# Keys: pk_live_{org_id}_{region}_{secret} or pk_test_{org_id}_{region}_{secret}
# The secret segment is HMAC-validated against PRIMUST_API_KEY_SECRET.
# After HMAC validation, DB lookup validates: status, revocation, expiry, org binding, key type.
async def _parse_api_key(api_key: str) -> AuthContext:
    """Parse and validate a Primust API key into an AuthContext."""
    parts = api_key.split("_")
    # Minimum: pk_{mode}_{org}_{region}_{secret}
    if len(parts) < 5 or parts[0] != "pk":
        raise HTTPException(status_code=401, detail="Invalid API key format")

    mode = parts[1]  # "live" or "test"
    org_id = parts[2]
    region = parts[3]
    secret_segment = "_".join(parts[4:])

    if mode not in ("live", "test"):
        raise HTTPException(status_code=401, detail="Invalid API key mode")
    if region not in ("us", "eu"):
        raise HTTPException(status_code=401, detail="Invalid API key region")

    # Step 1: HMAC validation (fast, no DB)
    api_key_secret = os.environ.get("PRIMUST_API_KEY_SECRET", "")
    if not api_key_secret:
        raise HTTPException(
            status_code=503,
            detail="API key validation not configured (PRIMUST_API_KEY_SECRET required)",
        )

    prefix = f"pk_{mode}_{org_id}_{region}"
    expected = hmac.new(
        api_key_secret.encode(), prefix.encode(), hashlib.sha256
    ).hexdigest()[:32]
    if not hmac.compare_digest(secret_segment, expected):
        raise HTTPException(status_code=401, detail="Invalid API key")

    # Step 2: DB lookup for revocation/expiry/org-binding/key-type
    from .db import fetch_one

    key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    record = await fetch_one(
        region,
        "SELECT org_id, status, key_type, expires_at FROM api_keys WHERE key_hash = $1",
        key_hash,
    )

    if record:
        # DB record exists — enforce all constraints
        if record["status"] != "active":
            raise HTTPException(status_code=401, detail="API key revoked or expired")
        if record["expires_at"] and record["expires_at"] < datetime.now(timezone.utc):
            raise HTTPException(status_code=401, detail="API key expired")
        if record["org_id"] != org_id:
            raise HTTPException(status_code=401, detail="Invalid API key")
        # DB is source of truth for key type, not prefix
        test_mode = record["key_type"] == "test"
    else:
        # No DB record — HMAC alone is sufficient during bootstrap / migration period.
        # HARD DEADLINE: Remove this allowance before first enterprise contract.
        # Target: 2026-06-01. After this date, reject keys without DB records.
        _BOOTSTRAP_DEADLINE = "2026-06-01"
        if datetime.now(timezone.utc).isoformat()[:10] >= _BOOTSTRAP_DEADLINE:
            logger.critical(
                "BOOTSTRAP DEADLINE PASSED (%s): API key has no DB record "
                "and should be rejected. org=%s, region=%s. "
                "Remove bootstrap allowance in auth.py.",
                _BOOTSTRAP_DEADLINE, org_id, region,
            )
        logger.warning(
            "API key passed HMAC but has no DB record (org=%s, region=%s). "
            "Allowing during bootstrap (deadline: %s).",
            org_id, region, _BOOTSTRAP_DEADLINE,
        )
        test_mode = mode == "test"

    return AuthContext(
        org_id=org_id,
        org_region=region,
        test_mode=test_mode,
    )


# ── Clerk JWT auth ──

# JWKS client singleton — created lazily, cached with lifespan=300s
_jwks_client: jwt.PyJWKClient | None = None


def _get_jwks_client() -> jwt.PyJWKClient:
    """Get or create the JWKS client singleton."""
    global _jwks_client
    if _jwks_client is None:
        jwks_url = os.environ.get("CLERK_JWKS_URL", "")
        if not jwks_url:
            raise HTTPException(
                status_code=503,
                detail="JWKS verification not configured (CLERK_JWKS_URL required)",
            )
        _jwks_client = jwt.PyJWKClient(jwks_url, lifespan=300)
    return _jwks_client


def _decode_clerk_jwt(token: str) -> dict[str, Any]:
    """Decode and verify a Clerk JWT. Fail-closed: never skip verification."""
    clerk_jwks_url = os.environ.get("CLERK_JWKS_URL", "")
    clerk_secret = os.environ.get("CLERK_SECRET_KEY", "")

    if not clerk_jwks_url and not clerk_secret:
        raise HTTPException(
            status_code=503,
            detail="JWT verification not configured (CLERK_JWKS_URL or CLERK_SECRET_KEY required)",
        )

    # Prefer JWKS (production path) — asymmetric key verification with caching
    if clerk_jwks_url:
        try:
            client = _get_jwks_client()
            signing_key = client.get_signing_key_from_jwt(token)
            return jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                options={"verify_aud": False},
            )
        except jwt.PyJWKClientConnectionError as e:
            # JWKS endpoint unreachable — fail-closed, never proceed unverified
            raise HTTPException(
                status_code=503,
                detail="JWKS endpoint unreachable — cannot verify JWT",
            ) from e

    # Fallback: symmetric secret (dev/staging only)
    # Accept both RS256 and HS256 — HS256 used in tests with CLERK_SECRET_KEY
    return jwt.decode(
        token,
        clerk_secret,
        algorithms=["RS256", "HS256"],
        options={"verify_aud": False},
    )


def _parse_clerk_jwt(token: str) -> AuthContext:
    """Parse a Clerk JWT into an AuthContext."""
    try:
        claims = _decode_clerk_jwt(token)
    except jwt.PyJWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid JWT: {e}") from e

    org_id = claims.get("org_id")
    if not org_id:
        raise HTTPException(status_code=401, detail="Missing org_id in JWT")

    org_region = claims.get("org_region", "us")
    user_id = claims.get("sub")

    return AuthContext(
        org_id=org_id,
        org_region=org_region,
        test_mode=False,
        user_id=user_id,
    )


# ── Dependency injection ──


async def require_api_key(
    x_api_key: str = Header(alias="X-API-Key"),
) -> AuthContext:
    """FastAPI dependency: require API key auth."""
    return await _parse_api_key(x_api_key)


async def require_jwt(
    authorization: str = Header(),
) -> AuthContext:
    """FastAPI dependency: require Clerk JWT auth."""
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token")
    token = authorization[7:]
    return _parse_clerk_jwt(token)


async def require_auth(request: Request) -> AuthContext:
    """FastAPI dependency: accept either API key or JWT."""
    api_key = request.headers.get("X-API-Key")
    if api_key:
        return await _parse_api_key(api_key)

    authorization = request.headers.get("Authorization")
    if authorization and authorization.startswith("Bearer "):
        return _parse_clerk_jwt(authorization[7:])

    raise HTTPException(status_code=401, detail="Authentication required")
