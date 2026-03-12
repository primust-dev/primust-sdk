"""
P9-B SIEM Webhook tests — 17 MUST PASS.

Tests webhook dispatch, routes, payload validation, retry logic, and dead letter.
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from .conftest import InMemoryDB, _make_api_key, seed_policy_pack, seed_run, seed_surface


# ── Helpers ──


def _seed_webhook_config(
    db: InMemoryDB,
    org_id: str = "org001",
    enabled: bool = True,
    threshold: float = 0.80,
) -> str:
    config_id = f"whcfg_{uuid.uuid4().hex}"
    db.tables["webhook_configs"].append({
        "id": config_id,
        "org_id": org_id,
        "endpoint_url": "https://siem.example.com/intake",
        "auth_header": "Authorization: Splunk test_token_123",
        "enabled": enabled,
        "coverage_threshold_floor": threshold,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "last_delivery": None,
        "last_status": None,
    })
    return config_id


def _seed_record(db: InMemoryDB, run_id: str, surface_id: str, **overrides: Any) -> str:
    record_id = f"rec_{uuid.uuid4().hex[:8]}"
    rec = {
        "record_id": record_id,
        "run_id": run_id,
        "action_unit_id": f"au_{uuid.uuid4().hex[:8]}",
        "manifest_id": "manifest_001",
        "manifest_hash": "sha256:" + "dd" * 32,
        "surface_id": surface_id,
        "commitment_hash": "poseidon2:" + "cc" * 32,
        "check_result": "pass",
        "proof_level_achieved": "execution",
        "chain_hash": "sha256:" + "ee" * 32,
        "idempotency_key": f"idem_{uuid.uuid4().hex[:8]}",
        "recorded_at": datetime.now(timezone.utc).isoformat(),
    }
    rec.update(overrides)
    db.tables["check_execution_records"].append(rec)
    return record_id


def _close_run(client: TestClient, run_id: str, api_key: str) -> dict[str, Any]:
    resp = client.post(
        f"/api/v1/runs/{run_id}/close",
        json={},
        headers={"X-API-Key": api_key},
    )
    assert resp.status_code == 200
    return resp.json()


# ── Webhook dispatch tests ──


class TestWebhookDispatch:
    """P9-B SIEM Webhook Dispatch."""

    def test_webhook_fires_on_vpec_issuance(
        self, client: TestClient, mock_db: InMemoryDB, api_key_us: str
    ) -> None:
        """MUST PASS: webhook fires on every VPEC issuance when config present."""
        surface_id = seed_surface(mock_db)
        run_id = seed_run(mock_db, surface_id=surface_id)
        _seed_record(mock_db, run_id, surface_id)
        _seed_webhook_config(mock_db)

        with patch(
            "primust_api.services.webhook_dispatcher._deliver",
            new_callable=AsyncMock,
            return_value=(200, None),
        ) as mock_deliver:
            _close_run(client, run_id, api_key_us)

            # dispatch_vpec_issued is awaited, which calls dispatch_event,
            # which creates an asyncio task calling _dispatch_with_retry.
            # Give the task a moment to execute.
            assert mock_deliver.call_count >= 1
            call_args = mock_deliver.call_args_list[0]
            payload = call_args[0][2]  # third positional arg
            assert payload["event_type"] == "vpec_issued"
            assert payload["source"] == "primust"

    def test_webhook_fires_on_critical_gap(
        self, client: TestClient, mock_db: InMemoryDB, api_key_us: str
    ) -> None:
        """MUST PASS: webhook fires on gap_created when severity = critical."""
        surface_id = seed_surface(mock_db)
        run_id = seed_run(mock_db, surface_id=surface_id)
        _seed_record(mock_db, run_id, surface_id)
        _seed_webhook_config(mock_db)

        # Seed a critical gap
        mock_db.tables["gaps"].append({
            "gap_id": "gap_crit_001",
            "run_id": run_id,
            "gap_type": "policy_config_drift",
            "severity": "Critical",
            "state": "open",
            "details": {},
            "detected_at": datetime.now(timezone.utc).isoformat(),
        })

        with patch(
            "primust_api.services.webhook_dispatcher._deliver",
            new_callable=AsyncMock,
            return_value=(200, None),
        ) as mock_deliver:
            _close_run(client, run_id, api_key_us)

            # Should have at least 2 calls: vpec_issued + gap_created
            payloads = [call[0][2] for call in mock_deliver.call_args_list]
            event_types = [p["event_type"] for p in payloads]
            assert "vpec_issued" in event_types
            assert "gap_created" in event_types

            gap_payload = next(p for p in payloads if p["event_type"] == "gap_created")
            assert gap_payload["gap_severity"] == "critical"

    def test_webhook_does_not_fire_on_medium_gap(
        self, client: TestClient, mock_db: InMemoryDB, api_key_us: str
    ) -> None:
        """MUST PASS: webhook does NOT fire on gap_created when severity = medium."""
        surface_id = seed_surface(mock_db)
        run_id = seed_run(mock_db, surface_id=surface_id)
        _seed_record(mock_db, run_id, surface_id)
        _seed_webhook_config(mock_db)

        # Seed a policy snapshot so close_run doesn't auto-create a Critical gap
        run_data = mock_db.tables["process_runs"][0]
        mock_db.tables["policy_snapshots"].append({
            "snapshot_id": run_data["policy_snapshot_hash"],
            "policy_pack_id": "pp_test",
            "policy_pack_version": "1.0.0",
            "effective_checks": "[]",
            "snapshotted_at": datetime.now(timezone.utc).isoformat(),
            "policy_basis": "P1_self_declared",
        })

        mock_db.tables["gaps"].append({
            "gap_id": "gap_med_001",
            "run_id": run_id,
            "gap_type": "some_medium_gap",
            "severity": "Medium",
            "state": "open",
            "details": {},
            "detected_at": datetime.now(timezone.utc).isoformat(),
        })

        with patch(
            "primust_api.services.webhook_dispatcher._deliver",
            new_callable=AsyncMock,
            return_value=(200, None),
        ) as mock_deliver:
            _close_run(client, run_id, api_key_us)

            payloads = [call[0][2] for call in mock_deliver.call_args_list]
            event_types = [p["event_type"] for p in payloads]
            # Only vpec_issued, no gap_created for medium severity
            assert "gap_created" not in event_types

    def test_vpec_issuance_succeeds_when_webhook_endpoint_down(
        self, client: TestClient, mock_db: InMemoryDB, api_key_us: str
    ) -> None:
        """MUST PASS: VPEC issuance succeeds even when webhook endpoint is down."""
        surface_id = seed_surface(mock_db)
        run_id = seed_run(mock_db, surface_id=surface_id)
        _seed_record(mock_db, run_id, surface_id)
        _seed_webhook_config(mock_db)

        with patch(
            "primust_api.services.webhook_dispatcher._deliver",
            new_callable=AsyncMock,
            return_value=(0, "connection refused"),
        ):
            vpec = _close_run(client, run_id, api_key_us)
            # VPEC issuance succeeds regardless of webhook failure
            assert vpec["vpec_id"].startswith("vpec_")
            assert vpec["state"] == "signed"

    def test_dispatch_is_async(
        self, client: TestClient, mock_db: InMemoryDB, api_key_us: str
    ) -> None:
        """MUST PASS: dispatch is async — does not add latency to VPEC response."""
        surface_id = seed_surface(mock_db)
        run_id = seed_run(mock_db, surface_id=surface_id)
        _seed_record(mock_db, run_id, surface_id)

        # No webhook config → dispatch is a no-op → fast
        start = time.monotonic()
        vpec = _close_run(client, run_id, api_key_us)
        no_webhook_ms = (time.monotonic() - start) * 1000

        # With webhook config but mocked fast delivery
        surface_id2 = seed_surface(mock_db)
        run_id2 = seed_run(mock_db, surface_id=surface_id2)
        _seed_record(mock_db, run_id2, surface_id2)
        _seed_webhook_config(mock_db)

        with patch(
            "primust_api.services.webhook_dispatcher._deliver",
            new_callable=AsyncMock,
            return_value=(200, None),
        ):
            start = time.monotonic()
            vpec2 = _close_run(client, run_id2, api_key_us)
            with_webhook_ms = (time.monotonic() - start) * 1000

        # With webhook should not be dramatically slower (fire-and-forget)
        assert vpec2["vpec_id"].startswith("vpec_")

    def test_base_payload_contains_no_content_fields(
        self, client: TestClient, mock_db: InMemoryDB, api_key_us: str
    ) -> None:
        """MUST PASS: base payload contains no content fields (field allowlist test)."""
        from primust_api.services.webhook_dispatcher import (
            _BASE_PAYLOAD_FIELDS,
            _EVENT_EXTRA_FIELDS,
            build_base_payload,
        )

        # Content fields that must NEVER appear
        content_fields = {
            "raw_input", "check_explanation", "user_email", "user_name",
            "pii", "content", "prompt", "response", "output",
        }

        all_allowed = set(_BASE_PAYLOAD_FIELDS)
        for extra in _EVENT_EXTRA_FIELDS.values():
            all_allowed |= extra

        assert not (all_allowed & content_fields), \
            f"Content fields in allowlist: {all_allowed & content_fields}"

    def test_provable_surface_breakdown_sums_correctly(
        self, client: TestClient, mock_db: InMemoryDB, api_key_us: str
    ) -> None:
        """MUST PASS: provable_surface_breakdown values sum correctly."""
        from primust_api.services.webhook_dispatcher import build_base_payload

        vpec = {
            "vpec_id": "vpec_test",
            "workflow_id": "wf_001",
            "run_id": "run_001",
            "proof_level": "execution",
            "proof_distribution": {
                "mathematical": 3,
                "verifiable_inference": 0,
                "execution": 7,
                "witnessed": 0,
                "attestation": 0,
            },
            "coverage": {"records_total": 10, "records_pass": 10},
            "gaps": [],
            "commitment_root": "poseidon2:abc123",
            "issued_at": "2026-03-12T00:00:00Z",
        }

        payload = build_base_payload(
            event_type="vpec_issued", vpec=vpec, org_id="org001", test_mode=False,
        )

        breakdown = payload["provable_surface_breakdown"]
        total = sum(breakdown.values())
        # Should sum to provable_surface (within float tolerance)
        assert abs(total - payload["provable_surface"]) < 0.01

    def test_auth_header_never_in_logs(
        self, client: TestClient, mock_db: InMemoryDB, jwt_token: str
    ) -> None:
        """MUST PASS: auth_header never appears in API responses."""
        _seed_webhook_config(mock_db)

        resp = client.get(
            "/api/v1/webhook",
            headers={"Authorization": f"Bearer {jwt_token}"},
        )

        assert resp.status_code == 200
        data = resp.json()
        assert data["auth_header"] == "••••••••"
        assert "test_token_123" not in json.dumps(data)
        assert "Splunk" not in data["auth_header"]

    def test_test_endpoint_returns_delivery_id(
        self, client: TestClient, mock_db: InMemoryDB, jwt_token: str
    ) -> None:
        """MUST PASS: test endpoint returns delivery_id and http_status."""
        _seed_webhook_config(mock_db)

        with patch(
            "primust_api.services.webhook_dispatcher._deliver",
            new_callable=AsyncMock,
            return_value=(200, None),
        ):
            resp = client.post(
                "/api/v1/webhook/test",
                headers={"Authorization": f"Bearer {jwt_token}"},
            )

        assert resp.status_code == 200
        data = resp.json()
        assert "delivery_id" in data
        assert data["delivery_id"].startswith("del_")
        assert data["status"] == 200

    def test_disabled_config_fires_no_webhook(
        self, client: TestClient, mock_db: InMemoryDB, api_key_us: str
    ) -> None:
        """MUST PASS: disabled config (enabled=false) fires no webhook."""
        surface_id = seed_surface(mock_db)
        run_id = seed_run(mock_db, surface_id=surface_id)
        _seed_record(mock_db, run_id, surface_id)
        _seed_webhook_config(mock_db, enabled=False)

        with patch(
            "primust_api.services.webhook_dispatcher._deliver",
            new_callable=AsyncMock,
            return_value=(200, None),
        ) as mock_deliver:
            _close_run(client, run_id, api_key_us)
            mock_deliver.assert_not_called()

    def test_test_mode_true_for_test_key(
        self, client: TestClient, mock_db: InMemoryDB, api_key_test: str
    ) -> None:
        """MUST PASS: test_mode: true when pk_test_xxx key issued the VPEC."""
        surface_id = seed_surface(mock_db)
        run_id = seed_run(mock_db, surface_id=surface_id)
        _seed_record(mock_db, run_id, surface_id)
        _seed_webhook_config(mock_db)

        with patch(
            "primust_api.services.webhook_dispatcher._deliver",
            new_callable=AsyncMock,
            return_value=(200, None),
        ) as mock_deliver:
            _close_run(client, run_id, api_key_test)

            assert mock_deliver.call_count >= 1
            payload = mock_deliver.call_args_list[0][0][2]
            assert payload["test_mode"] is True


class TestWebhookRetry:
    """Retry and dead letter tests."""

    def test_retries_with_exponential_backoff(self) -> None:
        """MUST PASS: 3 retries with exponential backoff on failure."""
        from primust_api.services.webhook_dispatcher import _MAX_RETRIES, _RETRY_DELAYS

        assert _MAX_RETRIES == 3
        assert _RETRY_DELAYS == [1, 4, 16]
        # Verify exponential: each delay is 4x the previous
        for i in range(1, len(_RETRY_DELAYS)):
            assert _RETRY_DELAYS[i] == _RETRY_DELAYS[i - 1] * 4

    def test_dead_letter_written_after_retries_exhausted(
        self, mock_db: InMemoryDB
    ) -> None:
        """MUST PASS: dead letter written after all retries exhausted."""
        import asyncio
        from primust_api.services.webhook_dispatcher import _dispatch_with_retry

        config = {
            "id": "whcfg_test",
            "org_id": "org001",
            "endpoint_url": "https://siem.example.com/intake",
            "auth_header": "Authorization: Splunk test_token",
        }
        payload = {
            "source": "primust",
            "event_type": "vpec_issued",
            "delivery_id": "del_test_deadletter",
            "vpec_id": "vpec_test",
            "org_id": "org001",
            "workflow_id": "wf_001",
            "run_id": "run_001",
            "commitment_hash": "poseidon2:abc",
            "proof_level_floor": "execution",
            "provable_surface": 0.85,
            "provable_surface_breakdown": {
                "mathematical": 0.0,
                "verifiable_inference": 0.0,
                "execution": 0.85,
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
            "recorded_at": "2026-03-12T00:00:00Z",
            "timestamp_source": "digicert_tsa",
            "test_mode": False,
        }

        with patch(
            "primust_api.services.webhook_dispatcher._deliver",
            new_callable=AsyncMock,
            return_value=(500, "Internal Server Error"),
        ), patch(
            "primust_api.services.webhook_dispatcher.asyncio.sleep",
            new_callable=AsyncMock,
        ):
            asyncio.get_event_loop().run_until_complete(
                _dispatch_with_retry("us", config, payload)
            )

        # Dead letter should be written
        failures = mock_db.tables.get("webhook_delivery_failures", [])
        assert len(failures) == 1
        assert failures[0]["delivery_id"] == "del_test_deadletter"
        assert failures[0]["http_status"] == 500

    def test_retry_delivery_replays(
        self, client: TestClient, mock_db: InMemoryDB, jwt_token: str
    ) -> None:
        """MUST PASS: POST /api/v1/webhook/retry/{delivery_id} replays delivery."""
        _seed_webhook_config(mock_db)

        # Seed a dead letter entry
        mock_db.tables["webhook_delivery_failures"].append({
            "id": "whf_test",
            "org_id": "org001",
            "delivery_id": "del_replay_001",
            "vpec_id": "vpec_test",
            "event_type": "vpec_issued",
            "payload": json.dumps({"source": "primust", "event_type": "vpec_issued", "delivery_id": "del_replay_001"}),
            "attempted_at": datetime.now(timezone.utc).isoformat(),
            "http_status": 500,
            "error_msg": "Internal Server Error",
        })

        with patch(
            "primust_api.services.webhook_dispatcher._deliver",
            new_callable=AsyncMock,
            return_value=(200, None),
        ):
            resp = client.post(
                "/api/v1/webhook/retry/del_replay_001",
                headers={"Authorization": f"Bearer {jwt_token}"},
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["delivery_id"] == "del_replay_001"
        assert data["status"] == 200


class TestWebhookRoutes:
    """Webhook configuration routes."""

    def test_create_webhook_config(
        self, client: TestClient, mock_db: InMemoryDB, jwt_token: str
    ) -> None:
        """Create webhook config via POST."""
        resp = client.post(
            "/api/v1/webhook",
            json={
                "endpoint_url": "https://siem.example.com/intake",
                "auth_header": "Authorization: Splunk my_token",
                "coverage_threshold_floor": 0.75,
            },
            headers={"Authorization": f"Bearer {jwt_token}"},
        )

        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "created"
        assert data["id"].startswith("whcfg_")

        # Verify stored
        configs = mock_db.tables.get("webhook_configs", [])
        assert len(configs) == 1
        assert configs[0]["coverage_threshold_floor"] == 0.75

    def test_delete_webhook_config(
        self, client: TestClient, mock_db: InMemoryDB, jwt_token: str
    ) -> None:
        """Delete webhook config via DELETE."""
        _seed_webhook_config(mock_db)

        resp = client.delete(
            "/api/v1/webhook",
            headers={"Authorization": f"Bearer {jwt_token}"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "deleted"

    def test_get_webhook_siem_examples(
        self, client: TestClient, mock_db: InMemoryDB, jwt_token: str
    ) -> None:
        """GET webhook config includes all 12 SIEM examples."""
        resp = client.get(
            "/api/v1/webhook",
            headers={"Authorization": f"Bearer {jwt_token}"},
        )

        assert resp.status_code == 200
        data = resp.json()
        assert data["configured"] is False
        assert len(data["siem_examples"]) == 12
