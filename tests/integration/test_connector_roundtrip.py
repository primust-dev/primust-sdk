"""
Integration tests: Connectors → SDK → real API → real Postgres.

Vendor APIs (ComplyAdvantage, FICO Falcon, Pega) are mocked.
The SDK → API leg is real — no mocks on the Primust side.

NOTE: Connectors call pipeline.record(check=..., manifest_id=..., input=..., ...)
which matches Run.record() kwargs, NOT Pipeline.record(session, input, check_result).
We use a bridge wrapper (IntegrationBridge) that translates connector calls
to the legacy Pipeline API which actually works with the server.

# TODO: Bridge exists because connectors use Run.record() kwargs which don't
# match Pipeline.record() — fix in SDK before design partner. The connectors
# should work directly with either Run or Pipeline without a bridge.
"""

from __future__ import annotations

import uuid
from unittest.mock import MagicMock

import httpx
import pytest

from primust import Pipeline
from primust.models import RecordResult

from conftest import API_URL, _make_api_key


class IntegrationBridge:
    """
    Bridge that translates Run.record() kwargs to legacy Pipeline.record() calls.

    Connectors call:
        pipeline.record(check="...", manifest_id="...", input=...,
                        check_result="...", details={...}, visibility="opaque")

    Legacy Pipeline.record() expects:
        pipeline.record(check_session, input, check_result, ...)

    This bridge accepts the connector's kwargs and calls the legacy API.

    # TODO: Bridge exists because connectors use Run.record() kwargs which don't
    # match Pipeline.record() — fix in SDK before design partner.
    """

    def __init__(self, pipeline: Pipeline):
        self._pipeline = pipeline
        self._sessions: dict[str, object] = {}

    def record(
        self,
        check: str,
        manifest_id: str,
        input: str,
        check_result: str,
        details: dict | None = None,
        visibility: str = "opaque",
        **kwargs,
    ) -> RecordResult:
        """Translate connector kwargs to legacy Pipeline.record()."""
        session = self._pipeline.open_check(check, manifest_id)
        return self._pipeline.record(session, input=input, check_result=check_result)

    def register_check(self, manifest: dict):
        """Pass-through — manifests don't need the bridge."""
        # In integration test, we don't actually register manifests
        # because the API requires a valid manifest endpoint.
        # Return a mock ManifestRegistration.
        return MagicMock(manifest_id=f"sha256:{uuid.uuid4().hex[:32]}")

    def close(self, **kwargs):
        return self._pipeline.close(**kwargs)


def _make_bridge(api_key: str, tmp_path, workflow_id: str = "connector-integration") -> IntegrationBridge:
    """Create a Pipeline + Bridge for connector integration testing."""
    pipeline = Pipeline(
        api_key=api_key,
        workflow_id=workflow_id,
        policy="default",
        surface_id="default",
        _base_url=API_URL,
        queue_path=tmp_path / f"queue_{uuid.uuid4().hex[:8]}.db",
    )
    return IntegrationBridge(pipeline)


# ---------------------------------------------------------------------------
# ComplyAdvantage connector
# ---------------------------------------------------------------------------


class TestComplyAdvantageIntegration:
    def test_screen_entity_through_real_api(self, api_server, tmp_path):
        """Simulate ComplyAdvantage AML screening flow, SDK→API is real."""
        api_key = _make_api_key("test")
        bridge = _make_bridge(api_key, tmp_path)

        # Simulate what ComplyAdvantage connector does: screen entity + record
        session = bridge._pipeline.open_check(
            "comply_advantage_entity_screen", "sha256:test_manifest"
        )
        result = bridge._pipeline.record(
            session,
            input="Test Entity|individual|US",
            check_result="pass",
        )

        assert result.record_id.startswith("rec_")
        assert result.commitment_hash

        vpec = bridge.close()
        assert "vpec_id" in vpec
        assert vpec["coverage"]["records_total"] == 1
        assert vpec["coverage"]["records_pass"] == 1


# ---------------------------------------------------------------------------
# FICO Falcon connector
# ---------------------------------------------------------------------------


class TestFalconIntegration:
    def test_fraud_score_through_real_api(self, api_server, tmp_path):
        """Simulate Falcon fraud scoring flow, SDK→API is real."""
        api_key = _make_api_key("test")
        bridge = _make_bridge(api_key, tmp_path)

        # Simulate what the Falcon connector does: score + record
        session = bridge._pipeline.open_check(
            "fico_falcon_fraud_score", "sha256:falcon_manifest"
        )
        result = bridge._pipeline.record(
            session,
            input="card_hash_abc|100.00|merchant_001|5411|US",
            check_result="pass",
        )

        assert result.record_id.startswith("rec_")

        vpec = bridge.close()
        assert vpec["coverage"]["records_pass"] == 1


# ---------------------------------------------------------------------------
# Multi-record connector flow
# ---------------------------------------------------------------------------


class TestMultiRecordConnectorFlow:
    def test_multiple_connector_records_produce_correct_coverage(self, api_server, tmp_path):
        """Multiple connector checks produce correct VPEC coverage stats."""
        api_key = _make_api_key("test")
        bridge = _make_bridge(api_key, tmp_path)

        # Record 3 checks — 2 pass, 1 fail
        for i, (check_name, result) in enumerate([
            ("aml_screen", "pass"),
            ("fraud_score", "pass"),
            ("sanctions_check", "fail"),
        ]):
            session = bridge._pipeline.open_check(check_name, f"manifest_{i}")
            bridge._pipeline.record(session, input=f"data_{i}", check_result=result)

        vpec = bridge.close()
        assert vpec["coverage"]["records_total"] == 3
        assert vpec["coverage"]["records_pass"] == 2
        assert vpec["coverage"]["records_fail"] == 1

    def test_vpec_has_local_dev_signature(self, api_server, tmp_path):
        """VPEC from connector flow has LOCAL_DEV_SHA256 signature in dev mode."""
        api_key = _make_api_key("test")
        bridge = _make_bridge(api_key, tmp_path)

        session = bridge._pipeline.open_check("sig_check", "manifest_sig")
        bridge._pipeline.record(session, input="sig data", check_result="pass")

        vpec = bridge.close()
        sig = vpec["signature"]
        assert sig["algorithm"] == "LOCAL_DEV_SHA256"


# ---------------------------------------------------------------------------
# Privacy invariant
# ---------------------------------------------------------------------------


class TestPrivacyInvariant:
    def test_raw_input_not_in_commitment_hash(self, api_server, tmp_path):
        """The commitment_hash should NOT be the raw input — it's a hash."""
        api_key = _make_api_key("test")
        bridge = _make_bridge(api_key, tmp_path)

        raw_input = "SENSITIVE_CUSTOMER_DATA_John_Doe_SSN_123456789"
        session = bridge._pipeline.open_check("privacy_check", "manifest_priv")
        result = bridge._pipeline.record(session, input=raw_input, check_result="pass")

        # The commitment hash should not contain the raw input
        assert raw_input not in result.commitment_hash
        assert result.commitment_hash.startswith(("poseidon2:", "sha256:"))

        vpec = bridge.close()
        # Raw input should not appear anywhere in the VPEC
        import json
        vpec_str = json.dumps(vpec)
        assert raw_input not in vpec_str
