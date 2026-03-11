"""
RFC 3161 timestamping via DigiCert's free TSA endpoint.

Endpoint: http://timestamp.digicert.com
Content-Type: application/timestamp-query
Response: application/timestamp-reply (DER-encoded TimeStampResp)

No account, no API key — public endpoint.
"""

from __future__ import annotations

import base64
import hashlib
import logging
from typing import Any

import httpx

logger = logging.getLogger("primust.tsa")

DIGICERT_TSA_URL = "http://timestamp.digicert.com"


# ── DER encoding helpers ──


def _der_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    elif length < 0x100:
        return bytes([0x81, length])
    else:
        return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])


def _der_sequence(content: bytes) -> bytes:
    return b"\x30" + _der_length(len(content)) + content


def _der_integer(value: int) -> bytes:
    return bytes([0x02, 0x01, value])


def _der_octet_string(data: bytes) -> bytes:
    return b"\x04" + _der_length(len(data)) + data


def _der_boolean(value: bool) -> bytes:
    return bytes([0x01, 0x01, 0xFF if value else 0x00])


def _der_null() -> bytes:
    return bytes([0x05, 0x00])


# SHA-256 OID: 2.16.840.1.101.3.4.2.1
_SHA256_OID = bytes([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01])


def build_tsa_request(data: bytes) -> bytes:
    """Build an RFC 3161 TimeStampReq (DER) for SHA-256 digest of data."""
    digest = hashlib.sha256(data).digest()

    algo_id = _der_sequence(_SHA256_OID + _der_null())
    msg_imprint = _der_sequence(algo_id + _der_octet_string(digest))
    content = _der_integer(1) + msg_imprint + _der_boolean(True)
    return _der_sequence(content)


# ── TSA client ──


async def get_rfc3161_timestamp(
    document_bytes: bytes,
    tsa_url: str = DIGICERT_TSA_URL,
) -> dict[str, Any]:
    """
    Request an RFC 3161 timestamp from DigiCert.

    Returns timestamp_anchor dict ready for VPEC:
        {
            "type": "rfc3161",
            "tsa": "digicert_us" | "digicert_eu",
            "value": "<base64-encoded TimeStampResp>"
        }
    """
    tsa_request = build_tsa_request(document_bytes)

    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(
            tsa_url,
            content=tsa_request,
            headers={"Content-Type": "application/timestamp-query"},
        )

    if resp.status_code != 200:
        logger.error("TSA request failed: %d %s", resp.status_code, resp.text[:200])
        return {"type": "none", "tsa": "none", "value": None}

    # Determine TSA provider from URL
    tsa_provider = "digicert_us"
    if "eu" in tsa_url.lower():
        tsa_provider = "digicert_eu"

    # Base64-encode the DER response
    token_b64 = base64.b64encode(resp.content).decode("ascii")

    return {
        "type": "rfc3161",
        "tsa": tsa_provider,
        "value": token_b64,
    }


async def get_timestamp_anchor(
    document_json: str,
    tsa_url: str | None = None,
) -> dict[str, Any]:
    """
    Get timestamp anchor for a VPEC document.

    If tsa_url is "none" or not configured, returns stub anchor.
    """
    if not tsa_url or tsa_url == "none":
        return {"type": "none", "tsa": "none", "value": None}

    try:
        return await get_rfc3161_timestamp(
            document_json.encode("utf-8"),
            tsa_url=tsa_url,
        )
    except Exception:
        logger.exception("TSA timestamping failed — falling back to stub")
        return {"type": "none", "tsa": "none", "value": None}
