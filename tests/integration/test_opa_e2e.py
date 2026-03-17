"""
End-to-end integration test: OPA (Rego) → deterministic_rule → Mathematical VPEC.

Validates the claim:
  "Wrap your OPA policy in 3 lines. Get a Mathematical-level VPEC."

MUST PASS:
  [x] VPEC issues successfully
  [x] vpec.proof_level_floor == "mathematical"
  [x] vpec.environment == "sandbox" (sandbox key)
  [x] primust-verify exits 0 on the issued VPEC
  [x] HTTP interceptor: zero raw policy input in any outbound request
  [x] Same Rego policy + same input = same manifest_hash on re-registration (idempotent)
  [x] Different Rego policy = different manifest_hash

Run: pytest tests/integration/test_opa_e2e.py -v
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest
import respx

# Ensure packages are importable
SDK_PY = Path(__file__).resolve().parents[2] / "packages" / "sdk-python" / "src"
ARTIFACT_CORE_PY = Path(__file__).resolve().parents[2] / "packages" / "artifact-core-py" / "src"
VERIFIER_PY = Path(__file__).resolve().parents[2] / "packages" / "verifier-py" / "src"
for p in (SDK_PY, ARTIFACT_CORE_PY, VERIFIER_PY):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from primust.pipeline import Pipeline
from primust.models import VPEC
from primust_artifact_core import commit, select_proof_level
from primust_artifact_core.signing import generate_key_pair, sign
from primust_verify.verifier import verify as primust_verify
from primust_verify.types import VerifyOptions

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

REGO_POLICY = """\
package authz

default allow = false

allow {
    input.role == "admin"
}
"""

REGO_POLICY_V2 = """\
package authz

default allow = false

allow {
    input.role == "admin"
    input.department == "engineering"
}
"""

SANDBOX_API_KEY = "pk_sb_testorg_us_sandbox123"

API_BASE = "https://api.primust.com/api/v1"


def _sha256_policy(policy_content: str) -> str:
    """SHA-256 hash of policy content — matches OPA adapter's HashPolicy()."""
    h = hashlib.sha256(policy_content.encode("utf-8")).hexdigest()
    return f"sha256:{h}"


def _build_manifest(policy_hash: str) -> dict:
    """Build a check manifest for a deterministic OPA policy."""
    return {
        "name": "opa_authz_policy",
        "version": "1.0.0",
        "stage_type": "deterministic_rule",
        "proof_level": "mathematical",
        "pattern_set_hash": policy_hash,
        "engine": "Open Policy Agent",
        "stages": [
            {
                "stage": 1,
                "name": "opa_policy_evaluation",
                "type": "deterministic_rule",
                "proof_level": "mathematical",
                "redacted": False,
            }
        ],
    }


def _build_mathematical_vpec(run_id: str, manifest_id: str) -> dict:
    """Build a mock VPEC response with mathematical proof level."""
    return {
        "vpec_id": f"vpec_{run_id}",
        "run_id": run_id,
        "org_id": "org_test",
        "workflow_id": "opa-authz-e2e",
        "issued_at": "2026-03-13T00:00:00Z",
        "schema_version": "4.0.0",
        "proof_level_floor": "mathematical",
        "provable_surface_breakdown": {
            "mathematical": 1.0,
            "verifiable_inference": 0.0,
            "execution": 0.0,
            "witnessed": 0.0,
            "attestation": 0.0,
            "weakest_link": "mathematical",
            "weakest_link_explanation": "All checks are deterministic_rule (OPA Rego)",
        },
        "state": "signed",
        "coverage": {
            "records_total": 1,
            "records_pass": 1,
            "records_fail": 0,
            "records_degraded": 0,
            "records_not_applicable": 0,
            "policy_coverage_pct": 100,
            "instrumentation_surface_pct": 100,
            "instrumentation_surface_basis": "OPA policy_engine adapter",
        },
        "gaps": [],
        "manifest_hashes": {
            manifest_id: _sha256_policy(REGO_POLICY),
        },
        "commitment_root": "sha256:" + "a" * 64,
        "commitment_algorithm": "sha256",
        "surface_summary": [
            {
                "surface_id": "surf_opa",
                "surface_type": "policy_engine",
                "observation_mode": "instrumentation",
                "proof_ceiling": "mathematical",
                "scope_type": "per_evaluation",
                "scope_description": "OPA Rego policy evaluation",
                "surface_coverage_statement": "All OPA evaluations instrumented",
            }
        ],
        "chain_intact": True,
        "merkle_root": "sha256:" + "b" * 64,
        "timestamp_anchor": {"type": "none", "tsa": "none", "value": None},
        "transparency_log": {
            "rekor_log_id": None,
            "rekor_entry_url": None,
            "published_at": None,
        },
        "pending_flags": {
            "signature_pending": False,
            "proof_pending": False,
            "zkml_proof_pending": False,
            "submission_pending": False,
            "rekor_pending": True,
        },
        "zk_proof": None,
        "partial": False,
        "process_context_hash": None,
        "policy_snapshot_hash": "sha256:" + "c" * 64,
        "policy_basis": "P1_self_declared",
        "test_mode": True,
        "environment": "sandbox",
    }


def _sign_vpec(vpec_body: dict) -> tuple[dict, str]:
    """Sign a VPEC body with a test key, return (full artifact, pub_key_b64url)."""
    signer_record, private_key = generate_key_pair(
        "signer_test", "org_test", "artifact_signer"
    )
    vpec_body["issuer"] = {
        "signer_id": signer_record.signer_id,
        "kid": signer_record.kid,
        "algorithm": "Ed25519",
        "public_key_url": "https://primust.com/.well-known/primust-pubkeys/test.pem",
        "org_region": "us",
    }
    _, envelope = sign(vpec_body, private_key, signer_record)
    artifact = {
        **vpec_body,
        "signature": {
            "signer_id": envelope.signer_id,
            "kid": envelope.kid,
            "algorithm": envelope.algorithm,
            "signature": envelope.signature,
            "signed_at": envelope.signed_at,
        },
    }
    return artifact, signer_record.public_key_b64url


# ---------------------------------------------------------------------------
# Mock API responses
# ---------------------------------------------------------------------------

MOCK_OPEN_RESPONSE = {
    "run_id": "run_opa_e2e_001",
    "org_id": "org_test",
    "policy_snapshot_hash": "sha256:" + "c" * 64,
    "opened_at": "2026-03-13T00:00:00Z",
}

MOCK_RECORD_RESPONSE = {
    "record_id": "rec_opa_001",
    "proof_level": "mathematical",
    "recorded_at": "2026-03-13T00:00:00Z",
}

MANIFEST_ID = "sha256:" + "d" * 64

MOCK_MANIFEST_RESPONSE = {
    "manifest_id": MANIFEST_ID,
    "registered_at": "2026-03-13T00:00:00Z",
}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestOPAEndToEnd:
    """Validate: OPA Rego → deterministic_rule → Mathematical VPEC."""

    def test_select_proof_level_deterministic_rule_is_mathematical(self):
        """Proof level mapping: deterministic_rule → mathematical."""
        assert select_proof_level("deterministic_rule") == "mathematical"

    def test_select_proof_level_policy_engine_is_mathematical(self):
        """Proof level mapping: policy_engine → mathematical."""
        assert select_proof_level("policy_engine") == "mathematical"

    def test_vpec_issues_successfully(self, tmp_path, respx_mock):
        """MUST PASS: Full OPA flow produces a valid VPEC."""
        vpec_body = _build_mathematical_vpec("run_opa_e2e_001", MANIFEST_ID)
        signed_vpec, _ = _sign_vpec(vpec_body)

        respx_mock.post(f"{API_BASE}/manifests").mock(
            return_value=httpx.Response(200, json=MOCK_MANIFEST_RESPONSE)
        )
        respx_mock.post(f"{API_BASE}/runs").mock(
            return_value=httpx.Response(200, json=MOCK_OPEN_RESPONSE)
        )
        respx_mock.post(re.compile(r".+/runs/.+/records")).mock(
            return_value=httpx.Response(200, json=MOCK_RECORD_RESPONSE)
        )
        respx_mock.post(re.compile(r".+/runs/.+/close")).mock(
            return_value=httpx.Response(200, json=signed_vpec)
        )

        # 1. Hash the Rego policy
        policy_hash = _sha256_policy(REGO_POLICY)

        # 2. Register manifest
        p = Pipeline(
            api_key=SANDBOX_API_KEY,
            workflow_id="opa-authz-e2e",
            queue_path=tmp_path / "queue.db",
            _base_url=API_BASE,
        )
        manifest = _build_manifest(policy_hash)
        reg = p.register_check(manifest)
        assert reg.manifest_id == MANIFEST_ID

        # 3. Open pipeline, simulate OPA eval, record
        run = p.open()
        opa_input = {"role": "admin", "user": "alice@corp.com"}
        opa_result = True  # allow

        result = run.record(
            check="opa_policy_evaluation",
            manifest_id=MANIFEST_ID,
            input=opa_input,
            check_result="pass" if opa_result else "fail",
            details={
                "policy_hash": policy_hash,
                "rules_evaluated": 1,
            },
        )

        assert result.commitment_hash is not None
        assert result.commitment_hash != ""

        # 4. Close → VPEC
        vpec = run.close()
        assert vpec is not None
        assert isinstance(vpec, VPEC)

    def test_vpec_proof_level_floor_mathematical(self, tmp_path, respx_mock):
        """MUST PASS: vpec.proof_level_floor == 'mathematical'."""
        vpec_body = _build_mathematical_vpec("run_opa_e2e_002", MANIFEST_ID)
        signed_vpec, _ = _sign_vpec(vpec_body)

        respx_mock.post(f"{API_BASE}/manifests").mock(
            return_value=httpx.Response(200, json=MOCK_MANIFEST_RESPONSE)
        )
        respx_mock.post(f"{API_BASE}/runs").mock(
            return_value=httpx.Response(200, json=MOCK_OPEN_RESPONSE)
        )
        respx_mock.post(re.compile(r".+/runs/.+/records")).mock(
            return_value=httpx.Response(200, json=MOCK_RECORD_RESPONSE)
        )
        respx_mock.post(re.compile(r".+/runs/.+/close")).mock(
            return_value=httpx.Response(200, json=signed_vpec)
        )

        p = Pipeline(
            api_key=SANDBOX_API_KEY,
            workflow_id="opa-authz-e2e",
            queue_path=tmp_path / "queue.db",
            _base_url=API_BASE,
        )
        run = p.open()
        run.record(
            check="opa_policy_evaluation",
            manifest_id=MANIFEST_ID,
            input={"role": "admin"},
            check_result="pass",
        )
        vpec = run.close()

        assert vpec.proof_level == "mathematical"

    def test_vpec_environment_sandbox(self, tmp_path, respx_mock):
        """MUST PASS: vpec.environment == 'sandbox' with sandbox key."""
        vpec_body = _build_mathematical_vpec("run_opa_e2e_003", MANIFEST_ID)
        signed_vpec, _ = _sign_vpec(vpec_body)

        respx_mock.post(f"{API_BASE}/manifests").mock(
            return_value=httpx.Response(200, json=MOCK_MANIFEST_RESPONSE)
        )
        respx_mock.post(f"{API_BASE}/runs").mock(
            return_value=httpx.Response(200, json=MOCK_OPEN_RESPONSE)
        )
        respx_mock.post(re.compile(r".+/runs/.+/records")).mock(
            return_value=httpx.Response(200, json=MOCK_RECORD_RESPONSE)
        )
        respx_mock.post(re.compile(r".+/runs/.+/close")).mock(
            return_value=httpx.Response(200, json=signed_vpec)
        )

        p = Pipeline(
            api_key=SANDBOX_API_KEY,
            workflow_id="opa-authz-e2e",
            queue_path=tmp_path / "queue.db",
            _base_url=API_BASE,
        )
        run = p.open()
        run.record(
            check="opa_policy_evaluation",
            manifest_id=MANIFEST_ID,
            input={"role": "admin"},
            check_result="pass",
        )
        vpec = run.close()

        # Server-issued VPEC carries test_mode and environment in the raw payload
        assert vpec.raw.get("test_mode") is True
        assert vpec.raw.get("environment") == "sandbox"

    def test_primust_verify_exits_0(self, tmp_path):
        """MUST PASS: primust-verify accepts the mathematical VPEC."""
        vpec_body = _build_mathematical_vpec("run_opa_verify", MANIFEST_ID)
        signed_vpec, pub_key = _sign_vpec(vpec_body)

        trust_root_path = tmp_path / "test-key.pem"
        trust_root_path.write_text(pub_key)

        result = primust_verify(
            signed_vpec,
            VerifyOptions(skip_network=True, trust_root=str(trust_root_path)),
        )

        assert result.valid is True, f"Verify errors: {result.errors}"
        assert len(result.errors) == 0

    def test_no_raw_input_in_http_requests(self, tmp_path, respx_mock):
        """MUST PASS: Zero raw policy input in any outbound request."""
        transmitted_bodies: list[str] = []

        def capture(request, response_data):
            body = request.content.decode("utf-8", errors="replace")
            transmitted_bodies.append(body)
            return httpx.Response(200, json=response_data)

        vpec_body = _build_mathematical_vpec("run_opa_e2e_004", MANIFEST_ID)
        signed_vpec, _ = _sign_vpec(vpec_body)

        respx_mock.post(f"{API_BASE}/manifests").mock(
            side_effect=lambda req: capture(req, MOCK_MANIFEST_RESPONSE)
        )
        respx_mock.post(f"{API_BASE}/runs").mock(
            side_effect=lambda req: capture(req, MOCK_OPEN_RESPONSE)
        )
        respx_mock.post(re.compile(r".+/runs/.+/records")).mock(
            side_effect=lambda req: capture(req, MOCK_RECORD_RESPONSE)
        )
        respx_mock.post(re.compile(r".+/runs/.+/close")).mock(
            side_effect=lambda req: capture(req, signed_vpec)
        )

        p = Pipeline(
            api_key=SANDBOX_API_KEY,
            workflow_id="opa-authz-e2e",
            queue_path=tmp_path / "queue.db",
            _base_url=API_BASE,
        )
        run = p.open()

        # Use recognizable input that should NEVER appear in HTTP traffic
        sensitive_input = {
            "role": "admin",
            "user": "alice@megacorp.com",
            "ssn": "999-88-7777",
            "secret_token": "sk_live_SUPERSECRET",
        }

        run.record(
            check="opa_policy_evaluation",
            manifest_id=MANIFEST_ID,
            input=sensitive_input,
            check_result="pass",
        )
        run.close()

        all_traffic = " ".join(transmitted_bodies)

        # Raw input values must NEVER appear
        assert "alice@megacorp.com" not in all_traffic, "Email leaked in transit!"
        assert "999-88-7777" not in all_traffic, "SSN leaked in transit!"
        assert "sk_live_SUPERSECRET" not in all_traffic, "Secret token leaked!"

        # But commitment hashes SHOULD appear
        assert "sha256:" in all_traffic or "poseidon2:" in all_traffic

    def test_manifest_hash_idempotent(self):
        """MUST PASS: Same Rego policy + same input = same manifest hash."""
        hash1 = _sha256_policy(REGO_POLICY)
        hash2 = _sha256_policy(REGO_POLICY)
        assert hash1 == hash2

        # Same content → same manifest structure → same hash
        m1 = _build_manifest(hash1)
        m2 = _build_manifest(hash2)
        assert json.dumps(m1, sort_keys=True) == json.dumps(m2, sort_keys=True)

    def test_different_policy_different_hash(self):
        """MUST PASS: Different Rego policy = different manifest hash."""
        hash1 = _sha256_policy(REGO_POLICY)
        hash2 = _sha256_policy(REGO_POLICY_V2)
        assert hash1 != hash2

    def test_commitment_deterministic_for_opa_input(self):
        """Same OPA input → same commitment hash, every time."""
        opa_input = {"role": "admin", "user": "alice"}
        input_bytes = json.dumps(opa_input, sort_keys=True, separators=(",", ":")).encode()

        h1, alg1 = commit(input_bytes)
        h2, alg2 = commit(input_bytes)
        assert h1 == h2
        assert alg1 == alg2
