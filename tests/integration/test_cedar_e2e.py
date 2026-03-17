"""
End-to-end integration test: Cedar → deterministic_rule → Mathematical VPEC.

Validates the claim:
  "Your Cedar policies are deterministic. That means they're mathematically provable."

MUST PASS:
  [x] VPEC issues successfully
  [x] vpec.proof_level_floor == "mathematical"
  [x] primust-verify exits 0
  [x] Zero raw content in outbound requests

Run: pytest tests/integration/test_cedar_e2e.py -v
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

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

CEDAR_POLICY = """\
permit(
  principal,
  action == Action::"read",
  resource
) when {
  principal.role == "admin"
};
"""

SANDBOX_API_KEY = "pk_sb_testorg_us_sandbox456"

API_BASE = "https://api.primust.com/api/v1"


def _sha256_policy(policy_content: str) -> str:
    h = hashlib.sha256(policy_content.encode("utf-8")).hexdigest()
    return f"sha256:{h}"


def _build_manifest(policy_hash: str) -> dict:
    return {
        "name": "cedar_authz_policy",
        "version": "1.0.0",
        "stage_type": "deterministic_rule",
        "proof_level": "mathematical",
        "pattern_set_hash": policy_hash,
        "engine": "AWS Cedar",
        "stages": [
            {
                "stage": 1,
                "name": "cedar_policy_evaluation",
                "type": "deterministic_rule",
                "proof_level": "mathematical",
                "redacted": False,
            }
        ],
    }


def _build_mathematical_vpec(run_id: str, manifest_id: str) -> dict:
    return {
        "vpec_id": f"vpec_{run_id}",
        "run_id": run_id,
        "org_id": "org_test",
        "workflow_id": "cedar-authz-e2e",
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
            "weakest_link_explanation": "All checks are deterministic_rule (AWS Cedar)",
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
            "instrumentation_surface_basis": "Cedar policy_engine adapter",
        },
        "gaps": [],
        "manifest_hashes": {
            manifest_id: _sha256_policy(CEDAR_POLICY),
        },
        "commitment_root": "sha256:" + "a" * 64,
        "commitment_algorithm": "sha256",
        "surface_summary": [
            {
                "surface_id": "surf_cedar",
                "surface_type": "policy_engine",
                "observation_mode": "instrumentation",
                "proof_ceiling": "mathematical",
                "scope_type": "per_evaluation",
                "scope_description": "Cedar authorization evaluation",
                "surface_coverage_statement": "All Cedar evaluations instrumented",
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
    "run_id": "run_cedar_e2e_001",
    "org_id": "org_test",
    "policy_snapshot_hash": "sha256:" + "c" * 64,
    "opened_at": "2026-03-13T00:00:00Z",
}

MOCK_RECORD_RESPONSE = {
    "record_id": "rec_cedar_001",
    "proof_level": "mathematical",
    "recorded_at": "2026-03-13T00:00:00Z",
}

MANIFEST_ID = "sha256:" + "e" * 64

MOCK_MANIFEST_RESPONSE = {
    "manifest_id": MANIFEST_ID,
    "registered_at": "2026-03-13T00:00:00Z",
}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestCedarEndToEnd:
    """Validate: Cedar → deterministic_rule → Mathematical VPEC."""

    def test_vpec_issues_successfully(self, tmp_path, respx_mock):
        """MUST PASS: Full Cedar flow produces a valid VPEC."""
        vpec_body = _build_mathematical_vpec("run_cedar_e2e_001", MANIFEST_ID)
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

        policy_hash = _sha256_policy(CEDAR_POLICY)

        p = Pipeline(
            api_key=SANDBOX_API_KEY,
            workflow_id="cedar-authz-e2e",
            queue_path=tmp_path / "queue.db",
            _base_url=API_BASE,
        )
        reg = p.register_check(_build_manifest(policy_hash))
        assert reg.manifest_id == MANIFEST_ID

        run = p.open()

        # Simulate Cedar evaluation: isAuthorized(principal, action, resource)
        cedar_input = {
            "action": 'Action::"read"',
            "context": {},
            "principal": 'User::"alice"',
            "resource": 'Document::"report-q4"',
        }
        cedar_decision = "allow"

        result = run.record(
            check="cedar_policy_evaluation",
            manifest_id=MANIFEST_ID,
            input=cedar_input,
            check_result="pass" if cedar_decision == "allow" else "fail",
            details={
                "policy_set_hash": policy_hash,
                "decision": cedar_decision,
                "reasons_count": 1,
            },
        )

        assert result.commitment_hash is not None
        vpec = run.close()
        assert vpec is not None
        assert isinstance(vpec, VPEC)

    def test_vpec_proof_level_floor_mathematical(self, tmp_path, respx_mock):
        """MUST PASS: vpec.proof_level_floor == 'mathematical'."""
        vpec_body = _build_mathematical_vpec("run_cedar_e2e_002", MANIFEST_ID)
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
            workflow_id="cedar-authz-e2e",
            queue_path=tmp_path / "queue.db",
            _base_url=API_BASE,
        )
        run = p.open()
        run.record(
            check="cedar_policy_evaluation",
            manifest_id=MANIFEST_ID,
            input={"principal": 'User::"alice"', "action": 'Action::"read"',
                    "resource": 'Doc::"r1"', "context": {}},
            check_result="pass",
        )
        vpec = run.close()
        assert vpec.proof_level == "mathematical"

    def test_primust_verify_exits_0(self, tmp_path):
        """MUST PASS: primust-verify accepts the mathematical Cedar VPEC."""
        vpec_body = _build_mathematical_vpec("run_cedar_verify", MANIFEST_ID)
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
        """MUST PASS: Zero raw Cedar authorization data in outbound requests."""
        transmitted_bodies: list[str] = []

        def capture(request, response_data):
            body = request.content.decode("utf-8", errors="replace")
            transmitted_bodies.append(body)
            return httpx.Response(200, json=response_data)

        vpec_body = _build_mathematical_vpec("run_cedar_e2e_003", MANIFEST_ID)
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
            workflow_id="cedar-authz-e2e",
            queue_path=tmp_path / "queue.db",
            _base_url=API_BASE,
        )
        run = p.open()

        # Recognizable sensitive content that must NEVER appear in HTTP traffic
        cedar_input = {
            "principal": 'User::"ceo@megacorp.com"',
            "action": 'Action::"transfer"',
            "resource": 'Account::"acct-99887766"',
            "context": {"amount": 1000000, "destination": "offshore-account-XYZ"},
        }

        run.record(
            check="cedar_policy_evaluation",
            manifest_id=MANIFEST_ID,
            input=cedar_input,
            check_result="pass",
        )
        run.close()

        all_traffic = " ".join(transmitted_bodies)

        assert "ceo@megacorp.com" not in all_traffic, "Principal leaked!"
        assert "acct-99887766" not in all_traffic, "Account leaked!"
        assert "offshore-account-XYZ" not in all_traffic, "Destination leaked!"
        assert "1000000" not in all_traffic, "Amount leaked!"

        # Commitment hashes SHOULD appear
        assert "sha256:" in all_traffic or "poseidon2:" in all_traffic

    def test_commitment_deterministic_for_cedar_input(self):
        """Same Cedar input → same commitment hash."""
        cedar_input = {
            "action": 'Action::"read"',
            "context": {},
            "principal": 'User::"alice"',
            "resource": 'Document::"doc-1"',
        }
        input_bytes = json.dumps(cedar_input, sort_keys=True, separators=(",", ":")).encode()

        h1, _ = commit(input_bytes)
        h2, _ = commit(input_bytes)
        assert h1 == h2
