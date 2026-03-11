"""
Primust auth — Clerk JWT + API key authentication.

- Clerk JWT: org_id extracted from session claims.
- API key: pk_live_xxx → production, pk_test_xxx → test_mode: true.
- All authenticated routes require one or the other.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

import jwt
from fastapi import Depends, Header, HTTPException, Request


@dataclass
class AuthContext:
    """Resolved authentication context for a request."""

    org_id: str
    org_region: str
    test_mode: bool
    user_id: str | None = None  # set for Clerk JWT, not for API key


# ── API Key auth ──


# In production, API keys are stored in the database.
# For now, resolve org_id + region from the key prefix.
# Keys: pk_live_{org_id}_{region}_xxx or pk_test_{org_id}_{region}_xxx
def _parse_api_key(api_key: str) -> AuthContext:
    """Parse a Primust API key into an AuthContext."""
    parts = api_key.split("_")
    # Minimum: pk_{mode}_{org}_{region}_{secret}
    if len(parts) < 5 or parts[0] != "pk":
        raise HTTPException(status_code=401, detail="Invalid API key format")

    mode = parts[1]  # "live" or "test"
    org_id = parts[2]
    region = parts[3]

    if mode not in ("live", "test"):
        raise HTTPException(status_code=401, detail="Invalid API key mode")
    if region not in ("us", "eu"):
        raise HTTPException(status_code=401, detail="Invalid API key region")

    return AuthContext(
        org_id=org_id,
        org_region=region,
        test_mode=(mode == "test"),
    )


# ── Clerk JWT auth ──


def _decode_clerk_jwt(token: str) -> dict[str, Any]:
    """Decode and verify a Clerk JWT."""
    clerk_secret = os.environ.get("CLERK_SECRET_KEY", "")
    clerk_jwks_url = os.environ.get("CLERK_JWKS_URL", "")

    if not clerk_secret and not clerk_jwks_url:
        # Development mode: decode without verification
        return jwt.decode(token, options={"verify_signature": False})

    # Production: verify with Clerk's public keys
    return jwt.decode(
        token,
        clerk_secret,
        algorithms=["RS256"],
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
    return _parse_api_key(x_api_key)


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
        return _parse_api_key(api_key)

    authorization = request.headers.get("Authorization")
    if authorization and authorization.startswith("Bearer "):
        return _parse_clerk_jwt(authorization[7:])

    raise HTTPException(status_code=401, detail="Authentication required")
