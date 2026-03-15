"""
BYOK (Bring Your Own Key) signing service.

When an Enterprise org has an active BYOK key with a signing_endpoint_url,
this service calls the org's external KMS to sign the VPEC payload hash.

CRITICAL INVARIANT:
  Primust NEVER holds the org's private key.
  The signing_endpoint_url receives only the SHA-256 hash of the canonical VPEC —
  never the VPEC itself. The org's KMS signs the hash and returns the signature.

Protocol:
  POST {signing_endpoint_url}
  Body: {"payload_hex": "<sha256 hex>", "key_id": "<kid>"}
  Response: {"signature_hex": "<hex-encoded Ed25519 signature>"}

Timeout: 5 seconds per attempt
Retries: 3 attempts with exponential backoff
On failure after retries: returns None (caller falls back to Primust KMS)
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any

import httpx

from ..db import fetch_one

logger = logging.getLogger("primust.byok_signer")

# HTTP client settings
_TIMEOUT = 5.0  # seconds per request
_MAX_RETRIES = 3
_BACKOFF_BASE = 0.5  # seconds — 0.5, 1.0, 2.0


async def get_active_org_key(org_id: str, region: str) -> dict[str, Any] | None:
    """
    Look up an active BYOK key for the given org.
    Returns the key record dict or None if no active BYOK key exists.
    """
    row = await fetch_one(
        region,
        """SELECT key_id, org_id, kid, public_key_pem, signing_endpoint_url, status
           FROM org_signing_keys
           WHERE org_id = $1 AND status = 'active'
           ORDER BY verified_at DESC
           LIMIT 1""",
        org_id,
    )
    return dict(row) if row else None


async def sign_with_org_key(
    org_id: str, payload_hex: str, region: str
) -> dict[str, str] | None:
    """
    If org has an active BYOK key with signing_endpoint_url, call it to sign.

    Args:
        org_id: The organization ID.
        payload_hex: Hex-encoded SHA-256 hash of the canonical VPEC JSON.
        region: The org's region ('us' or 'eu').

    Returns:
        {"signature_hex": str, "kid": str} on success, or None on failure / no key.
    """
    org_key = await get_active_org_key(org_id, region)
    if not org_key:
        return None

    endpoint = org_key.get("signing_endpoint_url")
    if not endpoint:
        return None

    kid = org_key["kid"]

    import asyncio

    last_error: Exception | None = None
    for attempt in range(_MAX_RETRIES):
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                response = await client.post(
                    endpoint,
                    json={"payload_hex": payload_hex, "key_id": kid},
                    headers={
                        "Content-Type": "application/json",
                        "User-Agent": "Primust-BYOK/1.0",
                    },
                )

            if response.status_code != 200:
                logger.warning(
                    "BYOK signing endpoint returned %d for org=%s kid=%s (attempt %d/%d)",
                    response.status_code, org_id, kid, attempt + 1, _MAX_RETRIES,
                )
                last_error = RuntimeError(f"HTTP {response.status_code}")
            else:
                body = response.json()
                sig_hex = body.get("signature_hex")
                if not sig_hex:
                    logger.warning(
                        "BYOK signing endpoint returned no signature_hex for org=%s kid=%s",
                        org_id, kid,
                    )
                    last_error = RuntimeError("Missing signature_hex in response")
                else:
                    # Validate it looks like hex
                    try:
                        bytes.fromhex(sig_hex)
                    except ValueError:
                        logger.warning(
                            "BYOK signing endpoint returned invalid hex for org=%s kid=%s",
                            org_id, kid,
                        )
                        last_error = RuntimeError("Invalid hex in signature_hex")
                    else:
                        logger.info(
                            "BYOK signing succeeded for org=%s kid=%s (attempt %d)",
                            org_id, kid, attempt + 1,
                        )
                        return {"signature_hex": sig_hex, "kid": kid}

        except Exception as exc:
            logger.warning(
                "BYOK signing request failed for org=%s kid=%s (attempt %d/%d): %s",
                org_id, kid, attempt + 1, _MAX_RETRIES, exc,
            )
            last_error = exc

        # Exponential backoff before next retry
        if attempt < _MAX_RETRIES - 1:
            delay = _BACKOFF_BASE * (2 ** attempt)
            await asyncio.sleep(delay)

    logger.error(
        "BYOK signing failed after %d attempts for org=%s kid=%s — falling back to Primust KMS. "
        "Last error: %s",
        _MAX_RETRIES, org_id, kid, last_error,
    )
    return None
