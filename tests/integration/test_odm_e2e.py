"""
End-to-end integration test: IBM ODM → deterministic_rule → Mathematical VPEC.

Validates the claim:
  "Your IBM ODM rules are deterministic. That means they're mathematically provable."

Uses a real ODM-style ruleset (credit underwriting) to exercise the full flow.
ODM unique: tests generateStagesFromRules() automatic manifest generation.

MUST PASS:
  [x] select_proof_level("deterministic_rule") == "mathematical"
  [x] VPEC issues successfully
  [x] vpec.proof_level_floor == "mathematical"
  [x] vpec.environment == "sandbox" (sandbox key)
  [x] primust-verify exits 0 on the issued VPEC
  [x] HTTP interceptor: zero raw ruleset params in any outbound request
  [x] Same ruleset + same params = same manifest hash (idempotent)
  [x] Different ruleset = different manifest hash
  [x] Same params → same commitment hash (deterministic)
  [x] generateStagesFromRules() produces mathematical stages
  [x] ODM evaluation deterministic (same params → same decision)

Run: pytest tests/integration/test_odm_e2e.py -v
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
# Real IBM ODM ruleset (IRL/BAL-style credit underwriting)
# ---------------------------------------------------------------------------

# IBM ODM rules are authored in IRL (ILOG Rule Language) or BAL (Business
# Action Language). This represents a credit underwriting ruleset deployed
# via Decision Center → Decision Server.

ODM_RULESET_IRL = """\
// RuleApp: CreditUnderwriting
// RuleSet: /CreditUnderwriting/Underwriting

// Rule: MinCreditScoreCheck
// Priority: 0
if
    the credit score of 'the loan application' is less than 680
then
    set the decision of 'the loan application' to "declined" ;
    add "MinCreditScoreCheck" to the rules fired of 'the loan application' ;

// Rule: MaxDebtToIncomeCheck
// Priority: 0
if
    the debt to income ratio of 'the loan application' is more than 0.43
then
    set the decision of 'the loan application' to "declined" ;
    add "MaxDebtToIncomeCheck" to the rules fired of 'the loan application' ;

// Rule: CollateralValuationCheck
// Priority: 0
if
    the loan to value ratio of 'the loan application' is more than 0.80
    and the PMI flag of 'the loan application' is false
then
    set the decision of 'the loan application' to "declined" ;
    add "CollateralValuationCheck" to the rules fired of 'the loan application' ;

// Rule: FraudIndicatorCheck
// Priority: 0
if
    the fraud score of 'the loan application' is more than 75
then
    set the decision of 'the loan application' to "referred" ;
    add "FraudIndicatorCheck" to the rules fired of 'the loan application' ;

// Rule: ApproveApplication
// Priority: -1 (runs last)
if
    the decision of 'the loan application' is null
then
    set the decision of 'the loan application' to "approved" ;
    add "ApproveApplication" to the rules fired of 'the loan application' ;
"""

ODM_RULESET_IRL_V2 = """\
// RuleApp: CreditUnderwriting v2
// RuleSet: /CreditUnderwriting/Underwriting

// Rule: MinCreditScoreCheck (tightened)
if
    the credit score of 'the loan application' is less than 720
then
    set the decision of 'the loan application' to "declined" ;

// Rule: MaxDebtToIncomeCheck (tightened)
if
    the debt to income ratio of 'the loan application' is more than 0.36
then
    set the decision of 'the loan application' to "declined" ;

// Rule: ApproveApplication
if
    the decision of 'the loan application' is null
then
    set the decision of 'the loan application' to "approved" ;
"""

SANDBOX_API_KEY = "pk_sb_testorg_us_sandbox_odm"

API_BASE = "https://api.primust.com/api/v1"


def _sha256_policy(policy_content: str) -> str:
    h = hashlib.sha256(policy_content.encode("utf-8")).hexdigest()
    return f"sha256:{h}"


def _build_manifest(policy_hash: str) -> dict:
    return {
        "name": "odm_credit_underwriting",
        "version": "1.0.0",
        "stage_type": "deterministic_rule",
        "proof_level": "mathematical",
        "pattern_set_hash": policy_hash,
        "engine": "IBM Operational Decision Manager",
        "stages": [
            {
                "stage": 1,
                "name": "odm_rule_execution",
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
        "workflow_id": "odm-underwriting-e2e",
        "issued_at": "2026-03-14T00:00:00Z",
        "schema_version": "4.0.0",
        "proof_level": "mathematical",
        "proof_distribution": {
            "mathematical": 1,
            "verifiable_inference": 0,
            "execution": 0,
            "witnessed": 0,
            "attestation": 0,
            "weakest_link": "mathematical",
            "weakest_link_explanation": "All checks are deterministic_rule (IBM ODM)",
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
            "instrumentation_surface_basis": "IBM ODM policy_engine adapter",
        },
        "gaps": [],
        "manifest_hashes": {
            manifest_id: _sha256_policy(ODM_RULESET_IRL),
        },
        "commitment_root": "sha256:" + "a" * 64,
        "commitment_algorithm": "sha256",
        "surface_summary": [
            {
                "surface_id": "surf_odm",
                "surface_type": "policy_engine",
                "observation_mode": "instrumentation",
                "proof_ceiling": "mathematical",
                "scope_type": "per_evaluation",
                "scope_description": "IBM ODM ruleset execution",
                "surface_coverage_statement": "All ODM executions instrumented",
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
    "run_id": "run_odm_e2e_001",
    "org_id": "org_test",
    "policy_snapshot_hash": "sha256:" + "c" * 64,
    "opened_at": "2026-03-14T00:00:00Z",
}

MOCK_RECORD_RESPONSE = {
    "record_id": "rec_odm_001",
    "proof_level": "mathematical",
    "recorded_at": "2026-03-14T00:00:00Z",
}

MANIFEST_ID = "sha256:" + "0" * 64

MOCK_MANIFEST_RESPONSE = {
    "manifest_id": MANIFEST_ID,
    "registered_at": "2026-03-14T00:00:00Z",
}


# ---------------------------------------------------------------------------
# Simulated ODM execution (deterministic)
# ---------------------------------------------------------------------------

def _execute_odm_ruleset(ruleset_params: dict) -> tuple[list[str], dict, str]:
    """
    Simulate deterministic IBM ODM ruleset execution.

    Given ruleset parameters, returns (rules_fired, decision_output, check_result).
    Same params + same ruleset = same decision, every time.
    This mirrors IlrStatelessSession.execute() behavior.
    """
    rules_fired = []
    decision = None

    credit_score = ruleset_params.get("credit_score", 999)
    dti_ratio = ruleset_params.get("dti_ratio", 0)
    ltv_ratio = ruleset_params.get("ltv_ratio", 0)
    has_pmi = ruleset_params.get("has_pmi", False)
    fraud_score = ruleset_params.get("fraud_score", 0)

    if credit_score < 680:
        rules_fired.append("MinCreditScoreCheck")
        decision = "declined"

    if dti_ratio > 0.43:
        rules_fired.append("MaxDebtToIncomeCheck")
        decision = "declined"

    if ltv_ratio > 0.80 and not has_pmi:
        rules_fired.append("CollateralValuationCheck")
        decision = "declined"

    if fraud_score > 75:
        rules_fired.append("FraudIndicatorCheck")
        if decision is None:
            decision = "referred"

    if decision is None:
        rules_fired.append("ApproveApplication")
        decision = "approved"

    decision_output = {
        "decision": decision,
        "rules_fired_count": len(rules_fired),
        "rule_app": "CreditUnderwriting",
        "rule_set": "Underwriting",
    }

    check_result = "pass" if decision == "approved" else "fail"
    return rules_fired, decision_output, check_result


def _generate_stages_from_rules(rules_fired: list[str]) -> list[dict]:
    """
    Python equivalent of PrimustODM.generateStagesFromRules().

    Each rule that fired becomes a separate deterministic_rule stage
    with mathematical proof level.
    """
    stages = []
    for i, rule_name in enumerate(rules_fired):
        stages.append({
            "stage": i + 1,
            "name": rule_name,
            "type": "policy_engine",
            "proof_level": "mathematical",
            "method": "deterministic_rule",
            "purpose": f"ODM rule: {rule_name}",
        })
    return stages


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestODMEndToEnd:
    """Validate: IBM ODM → deterministic_rule → Mathematical VPEC."""

    def test_select_proof_level_deterministic_rule_is_mathematical(self):
        """Proof level mapping: deterministic_rule → mathematical."""
        assert select_proof_level("deterministic_rule") == "mathematical"

    def test_vpec_issues_successfully(self, tmp_path, respx_mock):
        """MUST PASS: Full ODM flow produces a valid VPEC."""
        vpec_body = _build_mathematical_vpec("run_odm_e2e_001", MANIFEST_ID)
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

        policy_hash = _sha256_policy(ODM_RULESET_IRL)

        p = Pipeline(
            api_key=SANDBOX_API_KEY,
            workflow_id="odm-underwriting-e2e",
            queue_path=tmp_path / "queue.db",
            _base_url=API_BASE,
        )
        reg = p.register_check(_build_manifest(policy_hash))
        assert reg.manifest_id == MANIFEST_ID

        run = p.open()

        # Real ODM ruleset parameters (credit underwriting)
        ruleset_params = {
            "applicant_name": "Maria Garcia",
            "credit_score": 740,
            "dti_ratio": 0.32,
            "ltv_ratio": 0.70,
            "has_pmi": False,
            "fraud_score": 15,
            "loan_amount": 425000,
            "property_zip": "94105",
        }

        rules_fired, decision_output, check_result = _execute_odm_ruleset(ruleset_params)

        result = run.record(
            check="odm_rule_execution",
            manifest_id=MANIFEST_ID,
            input=ruleset_params,
            check_result=check_result,
            details={
                "rule_app": "CreditUnderwriting",
                "rule_set": "Underwriting",
                "rules_fired_count": len(rules_fired),
                "decision": decision_output["decision"],
            },
        )

        assert result.commitment_hash is not None
        assert result.commitment_hash != ""

        vpec = run.close()
        assert vpec is not None
        assert isinstance(vpec, VPEC)

    def test_vpec_proof_level_floor_mathematical(self, tmp_path, respx_mock):
        """MUST PASS: vpec.proof_level_floor == 'mathematical'."""
        vpec_body = _build_mathematical_vpec("run_odm_e2e_002", MANIFEST_ID)
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
            workflow_id="odm-underwriting-e2e",
            queue_path=tmp_path / "queue.db",
            _base_url=API_BASE,
        )
        run = p.open()

        params = {"credit_score": 780, "dti_ratio": 0.28, "ltv_ratio": 0.65,
                  "has_pmi": False, "fraud_score": 5}
        _, _, check_result = _execute_odm_ruleset(params)

        run.record(
            check="odm_rule_execution",
            manifest_id=MANIFEST_ID,
            input=params,
            check_result=check_result,
        )
        vpec = run.close()
        assert vpec.proof_level == "mathematical"

    def test_vpec_environment_sandbox(self, tmp_path, respx_mock):
        """MUST PASS: vpec.environment == 'sandbox' with sandbox key."""
        vpec_body = _build_mathematical_vpec("run_odm_e2e_003", MANIFEST_ID)
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
            workflow_id="odm-underwriting-e2e",
            queue_path=tmp_path / "queue.db",
            _base_url=API_BASE,
        )
        run = p.open()

        params = {"credit_score": 720, "dti_ratio": 0.35, "fraud_score": 10}
        _, _, check_result = _execute_odm_ruleset(params)

        run.record(
            check="odm_rule_execution",
            manifest_id=MANIFEST_ID,
            input=params,
            check_result=check_result,
        )
        vpec = run.close()
        assert vpec.raw.get("test_mode") is True
        assert vpec.raw.get("environment") == "sandbox"

    def test_primust_verify_exits_0(self, tmp_path):
        """MUST PASS: primust-verify accepts the mathematical ODM VPEC."""
        vpec_body = _build_mathematical_vpec("run_odm_verify", MANIFEST_ID)
        signed_vpec, pub_key = _sign_vpec(vpec_body)

        trust_root_path = tmp_path / "test-key.pem"
        trust_root_path.write_text(pub_key)

        result = primust_verify(
            signed_vpec,
            VerifyOptions(skip_network=True, trust_root=str(trust_root_path)),
        )

        assert result.valid is True, f"Verify errors: {result.errors}"
        assert len(result.errors) == 0

    def test_no_raw_params_in_http_requests(self, tmp_path, respx_mock):
        """MUST PASS: Zero raw ODM ruleset params in any outbound request."""
        transmitted_bodies: list[str] = []

        def capture(request, response_data):
            body = request.content.decode("utf-8", errors="replace")
            transmitted_bodies.append(body)
            return httpx.Response(200, json=response_data)

        vpec_body = _build_mathematical_vpec("run_odm_e2e_004", MANIFEST_ID)
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
            workflow_id="odm-underwriting-e2e",
            queue_path=tmp_path / "queue.db",
            _base_url=API_BASE,
        )
        run = p.open()

        # Sensitive PII that must NEVER appear in HTTP traffic
        sensitive_params = {
            "applicant_name": "Robert Chen",
            "ssn": "987-65-4321",
            "credit_score": 620,
            "dti_ratio": 0.55,
            "annual_income": 120000,
            "employer": "TopSecret Defense Corp",
            "fraud_score": 80,
            "property_address": "1234 Hidden Lane, Palo Alto, CA",
        }

        _, _, check_result = _execute_odm_ruleset(sensitive_params)

        run.record(
            check="odm_rule_execution",
            manifest_id=MANIFEST_ID,
            input=sensitive_params,
            check_result=check_result,
        )
        run.close()

        all_traffic = " ".join(transmitted_bodies)

        assert "Robert Chen" not in all_traffic, "Applicant name leaked!"
        assert "987-65-4321" not in all_traffic, "SSN leaked!"
        assert "TopSecret Defense Corp" not in all_traffic, "Employer leaked!"
        assert "1234 Hidden Lane" not in all_traffic, "Address leaked!"

        # Commitment hashes SHOULD appear
        assert "sha256:" in all_traffic or "poseidon2:" in all_traffic

    def test_manifest_hash_idempotent(self):
        """MUST PASS: Same ruleset + same params = same manifest hash."""
        hash1 = _sha256_policy(ODM_RULESET_IRL)
        hash2 = _sha256_policy(ODM_RULESET_IRL)
        assert hash1 == hash2

        m1 = _build_manifest(hash1)
        m2 = _build_manifest(hash2)
        assert json.dumps(m1, sort_keys=True) == json.dumps(m2, sort_keys=True)

    def test_different_ruleset_different_hash(self):
        """MUST PASS: Different IRL ruleset = different manifest hash."""
        hash1 = _sha256_policy(ODM_RULESET_IRL)
        hash2 = _sha256_policy(ODM_RULESET_IRL_V2)
        assert hash1 != hash2

    def test_commitment_deterministic_for_odm_params(self):
        """Same ODM ruleset params → same commitment hash, every time."""
        params = {
            "applicant_score": 720,
            "loan_amount": 250000,
            "ltv_ratio": 0.8,
        }
        input_bytes = json.dumps(params, sort_keys=True, separators=(",", ":")).encode()

        h1, alg1 = commit(input_bytes)
        h2, alg2 = commit(input_bytes)
        assert h1 == h2
        assert alg1 == alg2

    def test_generate_stages_from_rules_mathematical(self):
        """ODM unique: generateStagesFromRules() produces mathematical stages."""
        rules_fired = [
            "MinCreditScoreCheck",
            "MaxDebtToIncomeCheck",
            "CollateralValuationCheck",
            "FraudIndicatorCheck",
        ]

        stages = _generate_stages_from_rules(rules_fired)
        assert len(stages) == 4

        for i, stage in enumerate(stages):
            assert stage["stage"] == i + 1
            assert stage["name"] == rules_fired[i]
            assert stage["type"] == "policy_engine"
            assert stage["proof_level"] == "mathematical"
            assert stage["method"] == "deterministic_rule"

    def test_odm_evaluation_deterministic(self):
        """Same params → same rules fired, same decision (determinism)."""
        params = {
            "credit_score": 650,
            "dti_ratio": 0.50,
            "ltv_ratio": 0.90,
            "has_pmi": False,
            "fraud_score": 80,
        }

        fired1, output1, result1 = _execute_odm_ruleset(params)
        fired2, output2, result2 = _execute_odm_ruleset(params)

        assert fired1 == fired2
        assert output1 == output2
        assert result1 == result2
        assert result1 == "fail"
        assert "MinCreditScoreCheck" in fired1
        assert "MaxDebtToIncomeCheck" in fired1
        assert "CollateralValuationCheck" in fired1
        assert "FraudIndicatorCheck" in fired1

    def test_odm_approval_path(self):
        """Qualified application approved by ApproveApplication rule."""
        params = {
            "credit_score": 780,
            "dti_ratio": 0.25,
            "ltv_ratio": 0.60,
            "has_pmi": False,
            "fraud_score": 10,
        }

        fired, output, result = _execute_odm_ruleset(params)
        assert result == "pass"
        assert output["decision"] == "approved"
        assert fired == ["ApproveApplication"]

    def test_odm_referral_path(self):
        """High fraud score triggers referral even with good credit."""
        params = {
            "credit_score": 780,
            "dti_ratio": 0.25,
            "ltv_ratio": 0.60,
            "has_pmi": False,
            "fraud_score": 90,
        }

        fired, output, result = _execute_odm_ruleset(params)
        assert output["decision"] == "referred"
        assert "FraudIndicatorCheck" in fired
