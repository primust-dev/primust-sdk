"""
.well-known/primust-pubkeys/ endpoint

Serves public keys for VPEC signature verification.
Keys are immutable once published — old kids must remain accessible forever.

Deployed at: https://primust.com/.well-known/primust-pubkeys/{kid}.pem
"""

from __future__ import annotations

import base64
import logging
from typing import Any

from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse

logger = logging.getLogger("primust.well_known")

router = APIRouter(prefix="/.well-known/primust-pubkeys", tags=["well-known"])


# ── In-memory key registry ──
# In production, keys are exported from GCP KMS and cached here on startup.
# kid → PEM-encoded public key (ECDSA P-256)
_KEY_REGISTRY: dict[str, str] = {}


async def load_keys_from_kms() -> None:
    """
    Export public keys from GCP KMS and populate the registry.
    Called once at application startup.
    """
    import os

    kms_keys = {
        "kid_api": os.environ.get("PRIMUST_KMS_KEY_US"),
    }

    for kid, key_name in kms_keys.items():
        if not key_name:
            logger.warning("No KMS key configured for kid=%s, skipping", kid)
            continue

        if key_name.startswith("local-key-"):
            logger.info("Skipping local dev key for kid=%s", kid)
            continue

        try:
            pem = await _export_kms_public_key(key_name)
            _KEY_REGISTRY[kid] = pem
            logger.info("Loaded public key for kid=%s (%d bytes)", kid, len(pem))
        except Exception:
            logger.error("Failed to export public key for kid=%s", kid, exc_info=True)


async def _export_kms_public_key(key_name: str) -> str:
    """Export the public key from a GCP KMS asymmetric signing key as PEM."""
    from google.cloud import kms

    client = kms.KeyManagementServiceClient()
    public_key = client.get_public_key(request={"name": key_name})
    return public_key.pem


def register_key(kid: str, pem: str) -> None:
    """Register a public key directly (used in tests and local dev)."""
    _KEY_REGISTRY[kid] = pem


@router.get("/{kid}.pem", response_class=PlainTextResponse)
async def get_public_key(kid: str) -> PlainTextResponse:
    """
    Serve a public key by kid.

    Returns PEM-encoded public key (ECDSA P-256 for Primust keys, Ed25519 for BYOK keys).
    Cache-Control: immutable — keys never change once published.

    For BYOK keys (kid starts with 'kid_org_'), the PEM is fetched from org_signing_keys.
    """
    pem = _KEY_REGISTRY.get(kid)

    # BYOK org keys: look up from org_signing_keys table
    if pem is None and kid.startswith("kid_org_"):
        pem = await _lookup_org_key_pem(kid)

    if pem is None:
        raise HTTPException(status_code=404, detail=f"Unknown key ID: {kid}")

    return PlainTextResponse(
        content=pem,
        media_type="application/x-pem-file",
        headers={
            "Cache-Control": "public, max-age=31536000, immutable",
            "Access-Control-Allow-Origin": "*",
        },
    )


async def _lookup_org_key_pem(kid: str) -> str | None:
    """
    Fetch the PEM for an active or revoked BYOK org key from the database.
    Revoked keys are still served — verifiers need them to validate historical VPECs.
    Only pending_verification keys are excluded.
    """
    from ..db import fetch_one

    # Try both regions — org keys are region-specific but we serve pubkeys globally
    for region in ("us", "eu"):
        try:
            row = await fetch_one(
                region,
                """SELECT public_key_pem FROM org_signing_keys
                   WHERE kid = $1 AND status IN ('active', 'revoked')""",
                kid,
            )
            if row:
                return row["public_key_pem"]
        except Exception:
            logger.warning(
                "Failed to look up BYOK key kid=%s in region=%s",
                kid, region, exc_info=True,
            )
    return None
