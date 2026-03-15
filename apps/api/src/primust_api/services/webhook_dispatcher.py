"""
Primust SIEM webhook dispatcher — fire-and-forget async delivery.

Pushes governance events to customer-configured SIEM endpoints.
Customer never pushes content to Primust.

Event types:
  vpec_issued              — every VPEC issuance
  gap_created              — critical/high severity only
  coverage_threshold_breach — provable_surface drops below org threshold
  manifest_drift           — manifest_hash changed between runs

INVARIANT: No content fields. No raw input. No check explanation. No PII.
Only governance metadata Primust already holds.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime, timezone
from typing import Any

import httpx
import structlog

from ..db import execute, fetch_one
from ..kms import decrypt_secret

logger = structlog.get_logger("primust.webhook")

# Fields allowed in base payload — allowlist for content-free guarantee
_BASE_PAYLOAD_FIELDS = frozenset({
    "source",
    "event_type",
    "delivery_id",
    "vpec_id",
    "org_id",
    "workflow_id",
    "run_id",
    "commitment_hash",
    "proof_level_floor",
    "provable_surface",
    "provable_surface_breakdown",
    "provable_surface_basis",
    "provable_surface_pending",
    "provable_surface_ungoverned",
    "provable_surface_suppressed",
    "gaps_emitted",
    "critical_gaps",
    "high_gaps",
    "recorded_at",
    "timestamp_source",
    "test_mode",
})

# Additional fields allowed per event type
_EVENT_EXTRA_FIELDS: dict[str, frozenset[str]] = {
    "vpec_issued": frozenset(),
    "gap_created": frozenset({"gap_id", "gap_severity", "gap_type", "manifest_id"}),
    "coverage_threshold_breach": frozenset({
        "previous_provable_surface", "current_provable_surface", "threshold",
    }),
    "manifest_drift": frozenset({"manifest_id", "prior_hash", "current_hash"}),
}

# Retry config
_MAX_RETRIES = 3
_RETRY_DELAYS = [1, 4, 16]  # exponential backoff in seconds


def _validate_payload_fields(payload: dict[str, Any]) -> None:
    """Ensure payload contains only allowlisted fields — no content leaks."""
    event_type = payload.get("event_type", "")
    allowed = _BASE_PAYLOAD_FIELDS | _EVENT_EXTRA_FIELDS.get(event_type, frozenset())
    extra = set(payload.keys()) - allowed
    if extra:
        raise ValueError(
            f"Webhook payload contains non-allowlisted fields: {extra}. "
            "This may indicate a content leak."
        )


def build_base_payload(
    *,
    event_type: str,
    vpec: dict[str, Any],
    org_id: str,
    test_mode: bool,
) -> dict[str, Any]:
    """Build the base webhook payload from a VPEC. No content fields."""
    delivery_id = f"del_{uuid.uuid4().hex}"

    # Extract provable_surface fields from VPEC
    # The VPEC stores proof_distribution and coverage — map to canonical fields
    proof_dist = vpec.get("proof_distribution", {})
    coverage = vpec.get("coverage", {})

    total = coverage.get("records_total", 0)
    pass_count = coverage.get("records_pass", 0)

    # Compute provable_surface from proof distribution
    # provable_surface = fraction of records that have any proof level
    provable_surface = round(pass_count / total, 4) if total > 0 else 0.0

    # Build breakdown from proof_distribution counts
    breakdown = {}
    for level in ("mathematical", "verifiable_inference", "execution", "witnessed", "attestation"):
        count = proof_dist.get(level, 0)
        breakdown[level] = round(count / total, 4) if total > 0 else 0.0

    # Validate breakdown sums to provable_surface (rounding tolerance)
    breakdown_sum = sum(breakdown.values())
    if total > 0 and abs(breakdown_sum - provable_surface) > 0.01:
        logger.warning(
            "provable_surface_breakdown sum mismatch",
            breakdown_sum=breakdown_sum,
            provable_surface=provable_surface,
        )

    # Count gaps
    gaps = vpec.get("gaps", [])
    critical_gaps = sum(1 for g in gaps if g.get("severity") == "Critical")
    high_gaps = sum(1 for g in gaps if g.get("severity") == "High")

    # Get commitment_hash from first record's chain (use commitment_root if available)
    commitment_hash = vpec.get("commitment_root") or ""

    payload = {
        "source": "primust",
        "event_type": event_type,
        "delivery_id": delivery_id,
        "vpec_id": vpec.get("vpec_id", ""),
        "org_id": org_id,
        "workflow_id": vpec.get("workflow_id", ""),
        "run_id": vpec.get("run_id", ""),
        "commitment_hash": commitment_hash,
        "proof_level_floor": vpec.get("proof_level", "attestation"),
        "provable_surface": provable_surface,
        "provable_surface_breakdown": breakdown,
        "provable_surface_basis": "executed_records",
        "provable_surface_pending": 0.0,
        "provable_surface_ungoverned": 0.0,
        "provable_surface_suppressed": False,
        "gaps_emitted": len(gaps),
        "critical_gaps": critical_gaps,
        "high_gaps": high_gaps,
        "recorded_at": vpec.get("issued_at", datetime.now(timezone.utc).isoformat()),
        "timestamp_source": "digicert_tsa",
        "test_mode": test_mode,
    }

    _validate_payload_fields(payload)
    return payload


async def _deliver(
    endpoint_url: str,
    auth_header: str,
    payload: dict[str, Any],
) -> tuple[int, str | None]:
    """POST payload to endpoint. Returns (status_code, error_msg)."""
    # Parse auth header into name: value
    header_parts = auth_header.split(":", 1)
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if len(header_parts) == 2:
        headers[header_parts[0].strip()] = header_parts[1].strip()

    headers["X-Primust-Event"] = payload.get("event_type", "")
    headers["X-Primust-Delivery"] = payload.get("delivery_id", "")

    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            resp = await client.post(
                endpoint_url,
                content=json.dumps(payload),
                headers=headers,
            )
            return resp.status_code, None
        except httpx.TimeoutException:
            return 0, "timeout"
        except httpx.RequestError as e:
            return 0, str(e)


async def _dispatch_with_retry(
    region: str,
    config: dict[str, Any],
    payload: dict[str, Any],
) -> None:
    """Dispatch webhook with retry. Write to dead letter on exhaustion."""
    org_id = config["org_id"]
    config_id = config["id"]
    delivery_id = payload["delivery_id"]
    vpec_id = payload.get("vpec_id", "")
    event_type = payload.get("event_type", "")
    auth_header = decrypt_secret(config["auth_header"])

    last_status = 0
    last_error: str | None = None

    for attempt in range(_MAX_RETRIES):
        if attempt > 0:
            await asyncio.sleep(_RETRY_DELAYS[attempt])

        status, err = await _deliver(
            config["endpoint_url"],
            auth_header,
            payload,
        )
        last_status = status
        last_error = err

        if 200 <= status < 300:
            # Success — update last_delivery
            now = datetime.now(timezone.utc)
            await execute(
                region,
                "UPDATE webhook_configs SET last_delivery = $1, last_status = $2 WHERE id = $3",
                now, status, config_id,
            )
            logger.info(
                "webhook_delivered",
                delivery_id=delivery_id,
                event_type=event_type,
                org_id=org_id,
                status=status,
                attempt=attempt + 1,
            )
            return

        logger.warning(
            "webhook_delivery_failed",
            delivery_id=delivery_id,
            event_type=event_type,
            org_id=org_id,
            status=status,
            error=err,
            attempt=attempt + 1,
        )

    # All retries exhausted — update last_status and write dead letter
    await execute(
        region,
        "UPDATE webhook_configs SET last_status = $1 WHERE id = $2",
        last_status, config_id,
    )

    failure_id = f"whf_{uuid.uuid4().hex}"
    await execute(
        region,
        """INSERT INTO webhook_delivery_failures
           (id, org_id, delivery_id, vpec_id, event_type, payload, attempted_at, http_status, error_msg)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)""",
        failure_id,
        org_id,
        delivery_id,
        vpec_id,
        event_type,
        json.dumps(payload),
        datetime.now(timezone.utc),
        last_status,
        last_error,
    )

    logger.error(
        "webhook_dead_letter",
        delivery_id=delivery_id,
        event_type=event_type,
        org_id=org_id,
        last_status=last_status,
    )


async def dispatch_event(
    region: str,
    org_id: str,
    payload: dict[str, Any],
) -> None:
    """
    Look up webhook config for org and dispatch asynchronously.
    Fire-and-forget — NEVER blocks caller.
    """
    config = await fetch_one(
        region,
        "SELECT * FROM webhook_configs WHERE org_id = $1",
        org_id,
    )

    if not config or not config.get("enabled", True):
        return

    # Validate no content fields before dispatch
    _validate_payload_fields(payload)

    # Fire-and-forget
    asyncio.create_task(_dispatch_with_retry(region, config, payload))


async def dispatch_vpec_issued(
    region: str,
    org_id: str,
    vpec: dict[str, Any],
    test_mode: bool,
) -> None:
    """Dispatch vpec_issued event after VPEC issuance."""
    payload = build_base_payload(
        event_type="vpec_issued",
        vpec=vpec,
        org_id=org_id,
        test_mode=test_mode,
    )
    await dispatch_event(region, org_id, payload)


async def dispatch_gap_created(
    region: str,
    org_id: str,
    vpec: dict[str, Any],
    test_mode: bool,
    *,
    gap_id: str,
    gap_severity: str,
    gap_type: str,
    manifest_id: str = "",
) -> None:
    """Dispatch gap_created event. Only fires for critical/high severity."""
    if gap_severity not in ("Critical", "High"):
        return

    payload = build_base_payload(
        event_type="gap_created",
        vpec=vpec,
        org_id=org_id,
        test_mode=test_mode,
    )
    payload["gap_id"] = gap_id
    payload["gap_severity"] = gap_severity.lower()
    payload["gap_type"] = gap_type
    payload["manifest_id"] = manifest_id

    _validate_payload_fields(payload)
    await dispatch_event(region, org_id, payload)


async def dispatch_coverage_threshold_breach(
    region: str,
    org_id: str,
    vpec: dict[str, Any],
    test_mode: bool,
    *,
    previous_provable_surface: float,
    current_provable_surface: float,
    threshold: float,
) -> None:
    """Dispatch coverage_threshold_breach when provable_surface drops below org threshold."""
    payload = build_base_payload(
        event_type="coverage_threshold_breach",
        vpec=vpec,
        org_id=org_id,
        test_mode=test_mode,
    )
    payload["previous_provable_surface"] = previous_provable_surface
    payload["current_provable_surface"] = current_provable_surface
    payload["threshold"] = threshold

    _validate_payload_fields(payload)
    await dispatch_event(region, org_id, payload)


async def dispatch_manifest_drift(
    region: str,
    org_id: str,
    vpec: dict[str, Any],
    test_mode: bool,
    *,
    manifest_id: str,
    prior_hash: str,
    current_hash: str,
) -> None:
    """Dispatch manifest_drift when manifest_hash changes between runs."""
    payload = build_base_payload(
        event_type="manifest_drift",
        vpec=vpec,
        org_id=org_id,
        test_mode=test_mode,
    )
    payload["manifest_id"] = manifest_id
    payload["prior_hash"] = prior_hash
    payload["current_hash"] = current_hash

    _validate_payload_fields(payload)
    await dispatch_event(region, org_id, payload)


async def send_test_event(
    region: str,
    org_id: str,
) -> dict[str, Any]:
    """Send a test webhook event. Returns delivery result synchronously."""
    config = await fetch_one(
        region,
        "SELECT * FROM webhook_configs WHERE org_id = $1",
        org_id,
    )
    if not config:
        raise ValueError("No webhook configured for this org")

    delivery_id = f"del_{uuid.uuid4().hex}"
    payload = {
        "source": "primust",
        "event_type": "vpec_issued",
        "delivery_id": delivery_id,
        "vpec_id": "vpec_test_00000000",
        "org_id": org_id,
        "workflow_id": "wf_test",
        "run_id": "run_test",
        "commitment_hash": "poseidon2:a1b2c3d4e5f6",
        "proof_level_floor": "execution",
        "provable_surface": 0.85,
        "provable_surface_breakdown": {
            "mathematical": 0.50,
            "verifiable_inference": 0.0,
            "execution": 0.35,
            "witnessed": 0.0,
            "attestation": 0.0,
        },
        "provable_surface_basis": "executed_records",
        "provable_surface_pending": 0.0,
        "provable_surface_ungoverned": 0.0,
        "provable_surface_suppressed": False,
        "gaps_emitted": 0,
        "critical_gaps": 0,
        "high_gaps": 0,
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "timestamp_source": "digicert_tsa",
        "test_mode": True,
    }

    import time
    start = time.monotonic()
    test_auth = decrypt_secret(config["auth_header"])
    status, err = await _deliver(config["endpoint_url"], test_auth, payload)
    latency_ms = round((time.monotonic() - start) * 1000, 1)

    # Update config status
    now = datetime.now(timezone.utc)
    if 200 <= status < 300:
        await execute(
            region,
            "UPDATE webhook_configs SET last_delivery = $1, last_status = $2 WHERE id = $3",
            now, status, config["id"],
        )

    return {
        "delivery_id": delivery_id,
        "status": status,
        "latency_ms": latency_ms,
        "error": err,
    }


async def retry_delivery(
    region: str,
    org_id: str,
    delivery_id: str,
) -> dict[str, Any]:
    """Retry a specific failed delivery from the dead letter table."""
    failure = await fetch_one(
        region,
        "SELECT * FROM webhook_delivery_failures WHERE delivery_id = $1 AND org_id = $2",
        delivery_id,
        org_id,
    )
    if not failure:
        raise ValueError("Delivery not found")

    config = await fetch_one(
        region,
        "SELECT * FROM webhook_configs WHERE org_id = $1",
        org_id,
    )
    if not config:
        raise ValueError("No webhook configured for this org")

    payload = failure.get("payload", {})
    if isinstance(payload, str):
        payload = json.loads(payload)

    import time
    start = time.monotonic()
    retry_auth = decrypt_secret(config["auth_header"])
    status, err = await _deliver(config["endpoint_url"], retry_auth, payload)
    latency_ms = round((time.monotonic() - start) * 1000, 1)

    if 200 <= status < 300:
        now = datetime.now(timezone.utc)
        await execute(
            region,
            "UPDATE webhook_configs SET last_delivery = $1, last_status = $2 WHERE id = $3",
            now, status, config["id"],
        )

    return {
        "delivery_id": delivery_id,
        "status": status,
        "latency_ms": latency_ms,
        "error": err,
    }
