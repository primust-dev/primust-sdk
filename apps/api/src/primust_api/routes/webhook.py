"""
SIEM Webhook configuration routes (Clerk JWT auth — dashboard users).

GET    /api/v1/webhook                      → current config (auth_header redacted)
POST   /api/v1/webhook                      → create or update config
DELETE /api/v1/webhook                      → delete config
POST   /api/v1/webhook/test                 → send test event (test_mode: true)
GET    /api/v1/webhook/failures             → last 50 dead letter entries
POST   /api/v1/webhook/retry/{delivery_id}  → replay specific failed delivery
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ..auth import AuthContext, require_jwt
from ..db import execute, fetch_all, fetch_one
from ..services.webhook_dispatcher import retry_delivery, send_test_event

router = APIRouter(prefix="/api/v1", tags=["webhook"])

# SIEM auth header examples — returned in GET response
_SIEM_EXAMPLES = [
    {"siem": "Splunk HEC", "format": "Authorization: Splunk <HEC_TOKEN>"},
    {"siem": "Microsoft Sentinel", "format": "Authorization: Bearer <DCR_TOKEN>"},
    {"siem": "IBM QRadar", "format": "SEC: <SEC_TOKEN>"},
    {"siem": "Google Chronicle", "format": "Authorization: Bearer <API_KEY>"},
    {"siem": "Datadog", "format": "DD-API-KEY: <API_KEY>"},
    {"siem": "Elastic", "format": "Authorization: ApiKey <ENCODED>"},
    {"siem": "Exabeam", "format": "Authorization: Bearer <TOKEN>"},
    {"siem": "SentinelOne", "format": "Authorization: ApiToken <TOKEN>"},
    {"siem": "Rapid7 InsightIDR", "format": "X-Api-Key: <TOKEN>"},
    {"siem": "Securonix", "format": "token: <TOKEN>"},
    {"siem": "LogRhythm", "format": "Authorization: Bearer <TOKEN>"},
    {"siem": "Devo", "format": "Authorization: Bearer <TOKEN>"},
]


class WebhookConfigRequest(BaseModel):
    endpoint_url: str = Field(max_length=2048)
    auth_header: str = Field(max_length=2048)
    coverage_threshold_floor: float = Field(default=0.80, ge=0.0, le=1.0)


@router.get("/webhook")
async def get_webhook_config(
    auth: AuthContext = Depends(require_jwt),
) -> dict[str, Any]:
    region = auth.org_region
    config = await fetch_one(
        region,
        "SELECT * FROM webhook_configs WHERE org_id = $1",
        auth.org_id,
    )

    if not config:
        return {
            "configured": False,
            "siem_examples": _SIEM_EXAMPLES,
        }

    return {
        "configured": True,
        "id": config["id"],
        "endpoint_url": config["endpoint_url"],
        "auth_header": "••••••••",  # NEVER expose
        "enabled": config.get("enabled", True),
        "coverage_threshold_floor": config.get("coverage_threshold_floor", 0.80),
        "last_delivery": config.get("last_delivery"),
        "last_status": config.get("last_status"),
        "siem_examples": _SIEM_EXAMPLES,
    }


@router.post("/webhook")
async def create_or_update_webhook(
    body: WebhookConfigRequest,
    auth: AuthContext = Depends(require_jwt),
) -> dict[str, Any]:
    region = auth.org_region
    existing = await fetch_one(
        region,
        "SELECT id FROM webhook_configs WHERE org_id = $1",
        auth.org_id,
    )

    if existing:
        # Update
        await execute(
            region,
            """UPDATE webhook_configs
               SET endpoint_url = $1, auth_header = $2, coverage_threshold_floor = $3
               WHERE org_id = $4""",
            body.endpoint_url,
            body.auth_header,
            body.coverage_threshold_floor,
            auth.org_id,
        )
        return {"id": existing["id"], "status": "updated"}

    # Create
    config_id = f"whcfg_{uuid.uuid4().hex}"
    await execute(
        region,
        """INSERT INTO webhook_configs
           (id, org_id, endpoint_url, auth_header, coverage_threshold_floor)
           VALUES ($1, $2, $3, $4, $5)""",
        config_id,
        auth.org_id,
        body.endpoint_url,
        body.auth_header,
        body.coverage_threshold_floor,
    )
    return {"id": config_id, "status": "created"}


@router.delete("/webhook")
async def delete_webhook(
    auth: AuthContext = Depends(require_jwt),
) -> dict[str, str]:
    region = auth.org_region
    await execute(
        region,
        "DELETE FROM webhook_configs WHERE org_id = $1",
        auth.org_id,
    )
    return {"status": "deleted"}


@router.post("/webhook/test")
async def test_webhook(
    auth: AuthContext = Depends(require_jwt),
) -> dict[str, Any]:
    region = auth.org_region
    try:
        result = await send_test_event(region, auth.org_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    return result


@router.get("/webhook/failures")
async def list_failures(
    auth: AuthContext = Depends(require_jwt),
) -> list[dict[str, Any]]:
    region = auth.org_region
    rows = await fetch_all(
        region,
        """SELECT id, delivery_id, vpec_id, event_type, attempted_at, http_status, error_msg
           FROM webhook_delivery_failures
           WHERE org_id = $1
           ORDER BY attempted_at DESC
           LIMIT 50""",
        auth.org_id,
    )
    return rows


@router.post("/webhook/retry/{delivery_id}")
async def retry_failed_delivery(
    delivery_id: str,
    auth: AuthContext = Depends(require_jwt),
) -> dict[str, Any]:
    region = auth.org_region
    try:
        result = await retry_delivery(region, auth.org_id, delivery_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    return result
