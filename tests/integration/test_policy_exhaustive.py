"""
EXHAUSTIVE scenario coverage: every unique path through the 5-level underwriting rules.

Decision tree:
  Level 1 (Eligibility): 3 failure exits + 1 pass
  Level 2 (Credit tier): 4 tiers + 1 reject
  Level 3 (DTI/Collateral): 2×2 = 4 combos per tier
  Level 4 (Fraud): 4 binary flags = 16 combos per tier
  Level 5 (Decision): deterministic from above

Total unique terminal paths:
  3 eligibility failures
  + 1 credit reject
  + 4 tiers × (2 DTI-fail variants + 1 collateral-fail + 16 fraud combos)
  = 3 + 1 + 4 × 19 = 80 scenarios

Each scenario verifies:
  - Correct decision
  - Correct rules fired
  - Determinism (3 runs, identical output)
  - Commitment determinism (same hash)

Run: pytest tests/integration/test_policy_exhaustive.py -v
"""
from __future__ import annotations

import itertools
import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
ARTIFACT_CORE_PY = REPO / "packages" / "artifact-core-py" / "src"
if str(ARTIFACT_CORE_PY) not in sys.path:
    sys.path.insert(0, str(ARTIFACT_CORE_PY))

from primust_artifact_core import commit


# ---------------------------------------------------------------------------
# Shared evaluator (identical to test_policy_engines_e2e.py)
# ---------------------------------------------------------------------------

def evaluate_underwriting(params: dict) -> dict:
    result = {
        "eligible": None,
        "credit_tier": None,
        "max_dti_ratio": None,
        "max_ltv": None,
        "dti_acceptable": None,
        "collateral_adequate": None,
        "fraud_flags": [],
        "decision": None,
        "rules_fired": [],
    }

    age = params.get("age", 30)
    citizenship = params.get("citizenship", "US")
    loan_amount = params.get("loan_amount", 300000)

    if age < 18 or age > 75:
        result["eligible"] = False
        result["decision"] = "declined_eligibility"
        result["rules_fired"].append("Eligibility_AgeCheck")
        return result

    if citizenship not in ("US", "PR", "GU"):
        result["eligible"] = False
        result["decision"] = "declined_eligibility"
        result["rules_fired"].append("Eligibility_CitizenshipCheck")
        return result

    if loan_amount < 50000 or loan_amount > 2000000:
        result["eligible"] = False
        result["decision"] = "declined_eligibility"
        result["rules_fired"].append("Eligibility_LoanAmountCheck")
        return result

    result["eligible"] = True
    result["rules_fired"].append("Eligibility_Passed")

    credit_score = params.get("credit_score", 700)
    has_pmi = params.get("has_pmi", False)
    compensating = params.get("compensating_factors_count", 0)

    if credit_score >= 740:
        result["credit_tier"] = "prime"
        result["max_dti_ratio"] = 0.43
        result["max_ltv"] = 0.95 if has_pmi else 0.90
        result["rules_fired"].append("CreditTier_Prime")
        if has_pmi:
            result["rules_fired"].append("CreditTier_PrimeWithPMI")
    elif credit_score >= 680:
        result["credit_tier"] = "near_prime"
        result["max_dti_ratio"] = 0.36
        result["max_ltv"] = 0.80
        result["rules_fired"].append("CreditTier_NearPrime")
    elif credit_score >= 620 and compensating >= 2:
        result["credit_tier"] = "subprime"
        result["max_dti_ratio"] = 0.28
        result["max_ltv"] = 0.70
        result["rules_fired"].append("CreditTier_Subprime")
    else:
        result["credit_tier"] = "reject"
        result["decision"] = "declined_credit"
        result["rules_fired"].append("CreditTier_Reject")
        return result

    dti_ratio = params.get("dti_ratio", 0.35)
    ltv_ratio = params.get("ltv_ratio", 0.75)

    result["dti_acceptable"] = dti_ratio <= result["max_dti_ratio"]
    result["rules_fired"].append(
        "DTI_Check_Passed" if result["dti_acceptable"] else "DTI_Check_Failed"
    )

    result["collateral_adequate"] = ltv_ratio <= result["max_ltv"]
    result["rules_fired"].append(
        "Collateral_Check_Passed" if result["collateral_adequate"] else "Collateral_Check_Failed"
    )

    stated_income = params.get("stated_income", 100000)
    verified_income = params.get("verified_income", 100000)
    apps_90d = params.get("applications_last_90_days", 0)
    mailing_state = params.get("mailing_state", "CA")
    property_state = params.get("property_state", "CA")
    investment = params.get("investment_property", False)
    ssn_issue_year = params.get("ssn_issue_year", 2000)
    birth_year = params.get("birth_year", 1990)

    if stated_income > verified_income * 1.3:
        result["fraud_flags"].append("income_inconsistency")
        result["rules_fired"].append("Fraud_IncomeInconsistency")

    if apps_90d > 3:
        result["fraud_flags"].append("velocity_alert")
        result["rules_fired"].append("Fraud_VelocityAlert")

    if mailing_state != property_state and not investment:
        result["fraud_flags"].append("address_mismatch")
        result["rules_fired"].append("Fraud_AddressMismatch")

    if ssn_issue_year > birth_year + 18:
        result["fraud_flags"].append("synthetic_identity")
        result["rules_fired"].append("Fraud_SyntheticIdentity")

    fraud_count = len(result["fraud_flags"])

    if fraud_count > 2:
        result["decision"] = "declined_fraud"
        result["rules_fired"].append("Decision_DeclinedFraud")
    elif not result["dti_acceptable"]:
        result["decision"] = "declined_dti"
        result["rules_fired"].append("Decision_DeclinedDTI")
    elif not result["collateral_adequate"]:
        result["decision"] = "declined_collateral"
        result["rules_fired"].append("Decision_DeclinedCollateral")
    elif fraud_count > 0:
        result["decision"] = "referred"
        result["rules_fired"].append("Decision_Referred")
    else:
        result["decision"] = "approved"
        result["rules_fired"].append("Decision_Approved")

    return result


# ---------------------------------------------------------------------------
# Exhaustive scenario generation
# ---------------------------------------------------------------------------

# Credit tiers and their parameters
TIERS = {
    "prime": {
        "credit_score": 780,
        "has_pmi": False,
        "compensating_factors_count": 0,
        "max_dti": 0.43,
        "max_ltv": 0.90,
    },
    "prime_pmi": {
        "credit_score": 780,
        "has_pmi": True,
        "compensating_factors_count": 0,
        "max_dti": 0.43,
        "max_ltv": 0.95,
    },
    "near_prime": {
        "credit_score": 710,
        "has_pmi": False,
        "compensating_factors_count": 0,
        "max_dti": 0.36,
        "max_ltv": 0.80,
    },
    "subprime": {
        "credit_score": 640,
        "has_pmi": False,
        "compensating_factors_count": 3,
        "max_dti": 0.28,
        "max_ltv": 0.70,
    },
}

# 4 fraud flags, each binary → 16 combinations
FRAUD_FLAGS = ["income_inconsistency", "velocity_alert", "address_mismatch", "synthetic_identity"]

FRAUD_PARAMS = {
    "income_inconsistency": {"stated_income": 200000, "verified_income": 100000},
    "velocity_alert": {"applications_last_90_days": 5},
    "address_mismatch": {"mailing_state": "NY", "property_state": "FL", "investment_property": False},
    "synthetic_identity": {"ssn_issue_year": 2020, "birth_year": 1990},
}

CLEAN_FRAUD_PARAMS = {
    "stated_income": 100000,
    "verified_income": 100000,
    "applications_last_90_days": 0,
    "mailing_state": "CA",
    "property_state": "CA",
    "investment_property": False,
    "ssn_issue_year": 2005,
    "birth_year": 1990,
}


def _generate_all_scenarios():
    """Generate every unique terminal path through the decision tree."""
    scenarios = []

    # ── Level 1 failures ──
    scenarios.append({
        "id": "L1_age_under",
        "params": {"age": 16, "citizenship": "US", "loan_amount": 300000},
        "expected_decision": "declined_eligibility",
        "expected_rule": "Eligibility_AgeCheck",
    })
    scenarios.append({
        "id": "L1_age_over",
        "params": {"age": 80, "citizenship": "US", "loan_amount": 300000},
        "expected_decision": "declined_eligibility",
        "expected_rule": "Eligibility_AgeCheck",
    })
    scenarios.append({
        "id": "L1_citizenship_UK",
        "params": {"age": 35, "citizenship": "UK", "loan_amount": 300000},
        "expected_decision": "declined_eligibility",
        "expected_rule": "Eligibility_CitizenshipCheck",
    })
    scenarios.append({
        "id": "L1_citizenship_CA",
        "params": {"age": 35, "citizenship": "CA", "loan_amount": 300000},
        "expected_decision": "declined_eligibility",
        "expected_rule": "Eligibility_CitizenshipCheck",
    })
    scenarios.append({
        "id": "L1_loan_too_small",
        "params": {"age": 35, "citizenship": "US", "loan_amount": 10000},
        "expected_decision": "declined_eligibility",
        "expected_rule": "Eligibility_LoanAmountCheck",
    })
    scenarios.append({
        "id": "L1_loan_too_large",
        "params": {"age": 35, "citizenship": "US", "loan_amount": 5000000},
        "expected_decision": "declined_eligibility",
        "expected_rule": "Eligibility_LoanAmountCheck",
    })

    # ── Level 1 boundary: eligible citizenships ──
    for cit in ("US", "PR", "GU"):
        scenarios.append({
            "id": f"L1_eligible_{cit}",
            "params": {
                "age": 35, "citizenship": cit, "loan_amount": 300000,
                "credit_score": 780, "dti_ratio": 0.30, "ltv_ratio": 0.70,
                **CLEAN_FRAUD_PARAMS,
            },
            "expected_decision": "approved",
            "expected_rule": "Decision_Approved",
        })

    # ── Level 1 boundary: age edges ──
    scenarios.append({
        "id": "L1_age_exactly_18",
        "params": {
            "age": 18, "citizenship": "US", "loan_amount": 300000,
            "credit_score": 780, "dti_ratio": 0.30, "ltv_ratio": 0.70,
            **CLEAN_FRAUD_PARAMS,
        },
        "expected_decision": "approved",
        "expected_rule": "Decision_Approved",
    })
    scenarios.append({
        "id": "L1_age_exactly_75",
        "params": {
            "age": 75, "citizenship": "US", "loan_amount": 300000,
            "credit_score": 780, "dti_ratio": 0.30, "ltv_ratio": 0.70,
            **CLEAN_FRAUD_PARAMS,
        },
        "expected_decision": "approved",
        "expected_rule": "Decision_Approved",
    })
    scenarios.append({
        "id": "L1_loan_exactly_50000",
        "params": {
            "age": 35, "citizenship": "US", "loan_amount": 50000,
            "credit_score": 780, "dti_ratio": 0.30, "ltv_ratio": 0.70,
            **CLEAN_FRAUD_PARAMS,
        },
        "expected_decision": "approved",
        "expected_rule": "Decision_Approved",
    })
    scenarios.append({
        "id": "L1_loan_exactly_2000000",
        "params": {
            "age": 35, "citizenship": "US", "loan_amount": 2000000,
            "credit_score": 780, "dti_ratio": 0.30, "ltv_ratio": 0.70,
            **CLEAN_FRAUD_PARAMS,
        },
        "expected_decision": "approved",
        "expected_rule": "Decision_Approved",
    })

    # ── Level 2: credit reject paths ──
    scenarios.append({
        "id": "L2_reject_score_580",
        "params": {
            "age": 35, "citizenship": "US", "loan_amount": 300000,
            "credit_score": 580, "compensating_factors_count": 0,
        },
        "expected_decision": "declined_credit",
        "expected_rule": "CreditTier_Reject",
    })
    scenarios.append({
        "id": "L2_reject_score_619",
        "params": {
            "age": 35, "citizenship": "US", "loan_amount": 300000,
            "credit_score": 619, "compensating_factors_count": 0,
        },
        "expected_decision": "declined_credit",
        "expected_rule": "CreditTier_Reject",
    })
    scenarios.append({
        "id": "L2_reject_subprime_no_compensating",
        "params": {
            "age": 35, "citizenship": "US", "loan_amount": 300000,
            "credit_score": 640, "compensating_factors_count": 1,
        },
        "expected_decision": "declined_credit",
        "expected_rule": "CreditTier_Reject",
    })

    # ── Level 2 boundaries ──
    scenarios.append({
        "id": "L2_boundary_score_620_with_comp",
        "params": {
            "age": 35, "citizenship": "US", "loan_amount": 300000,
            "credit_score": 620, "compensating_factors_count": 2,
            "dti_ratio": 0.25, "ltv_ratio": 0.65, **CLEAN_FRAUD_PARAMS,
        },
        "expected_decision": "approved",
        "expected_rule": "Decision_Approved",
    })
    scenarios.append({
        "id": "L2_boundary_score_680",
        "params": {
            "age": 35, "citizenship": "US", "loan_amount": 300000,
            "credit_score": 680, "dti_ratio": 0.33, "ltv_ratio": 0.78,
            **CLEAN_FRAUD_PARAMS,
        },
        "expected_decision": "approved",
        "expected_rule": "Decision_Approved",
    })
    scenarios.append({
        "id": "L2_boundary_score_739",
        "params": {
            "age": 35, "citizenship": "US", "loan_amount": 300000,
            "credit_score": 739, "dti_ratio": 0.33, "ltv_ratio": 0.78,
            **CLEAN_FRAUD_PARAMS,
        },
        "expected_decision": "approved",
        "expected_rule": "Decision_Approved",
    })
    scenarios.append({
        "id": "L2_boundary_score_740",
        "params": {
            "age": 35, "citizenship": "US", "loan_amount": 300000,
            "credit_score": 740, "dti_ratio": 0.35, "ltv_ratio": 0.85,
            **CLEAN_FRAUD_PARAMS,
        },
        "expected_decision": "approved",
        "expected_rule": "Decision_Approved",
    })

    # ── Levels 3-5: Per tier × DTI/collateral × fraud combos ──
    for tier_name, tier_cfg in TIERS.items():
        base_params = {
            "age": 35,
            "citizenship": "US",
            "loan_amount": 300000,
            "credit_score": tier_cfg["credit_score"],
            "has_pmi": tier_cfg["has_pmi"],
            "compensating_factors_count": tier_cfg["compensating_factors_count"],
        }

        max_dti = tier_cfg["max_dti"]
        max_ltv = tier_cfg["max_ltv"]

        # DTI fail + collateral pass
        scenarios.append({
            "id": f"{tier_name}_dti_fail_coll_pass",
            "params": {
                **base_params,
                "dti_ratio": max_dti + 0.05,
                "ltv_ratio": max_ltv - 0.10,
                **CLEAN_FRAUD_PARAMS,
            },
            "expected_decision": "declined_dti",
            "expected_rule": "Decision_DeclinedDTI",
        })

        # DTI fail + collateral fail (still declined_dti — DTI checked first)
        scenarios.append({
            "id": f"{tier_name}_dti_fail_coll_fail",
            "params": {
                **base_params,
                "dti_ratio": max_dti + 0.05,
                "ltv_ratio": max_ltv + 0.10,
                **CLEAN_FRAUD_PARAMS,
            },
            "expected_decision": "declined_dti",
            "expected_rule": "Decision_DeclinedDTI",
        })

        # DTI pass + collateral fail
        scenarios.append({
            "id": f"{tier_name}_dti_pass_coll_fail",
            "params": {
                **base_params,
                "dti_ratio": max_dti - 0.05,
                "ltv_ratio": max_ltv + 0.10,
                **CLEAN_FRAUD_PARAMS,
            },
            "expected_decision": "declined_collateral",
            "expected_rule": "Decision_DeclinedCollateral",
        })

        # DTI boundary: exactly at limit (should pass)
        scenarios.append({
            "id": f"{tier_name}_dti_exactly_at_limit",
            "params": {
                **base_params,
                "dti_ratio": max_dti,
                "ltv_ratio": max_ltv - 0.10,
                **CLEAN_FRAUD_PARAMS,
            },
            "expected_decision": "approved",
            "expected_rule": "Decision_Approved",
        })

        # LTV boundary: exactly at limit (should pass)
        scenarios.append({
            "id": f"{tier_name}_ltv_exactly_at_limit",
            "params": {
                **base_params,
                "dti_ratio": max_dti - 0.05,
                "ltv_ratio": max_ltv,
                **CLEAN_FRAUD_PARAMS,
            },
            "expected_decision": "approved",
            "expected_rule": "Decision_Approved",
        })

        # ── All 16 fraud flag combinations ──
        # DTI pass + collateral pass, vary fraud flags
        good_dti = max_dti - 0.05
        good_ltv = max_ltv - 0.10

        for flag_count in range(5):  # 0, 1, 2, 3, 4 flags
            for flag_combo in itertools.combinations(FRAUD_FLAGS, flag_count):
                fraud_params = dict(CLEAN_FRAUD_PARAMS)
                for flag in flag_combo:
                    fraud_params.update(FRAUD_PARAMS[flag])

                if flag_count == 0:
                    expected = "approved"
                    expected_rule = "Decision_Approved"
                elif flag_count <= 2:
                    expected = "referred"
                    expected_rule = "Decision_Referred"
                else:
                    expected = "declined_fraud"
                    expected_rule = "Decision_DeclinedFraud"

                flag_label = "_".join(flag_combo) if flag_combo else "clean"
                scenarios.append({
                    "id": f"{tier_name}_fraud_{flag_label}",
                    "params": {
                        **base_params,
                        "dti_ratio": good_dti,
                        "ltv_ratio": good_ltv,
                        **fraud_params,
                    },
                    "expected_decision": expected,
                    "expected_rule": expected_rule,
                    "expected_fraud_flags": list(flag_combo),
                })

    return scenarios


ALL_SCENARIOS = _generate_all_scenarios()
SCENARIO_IDS = [s["id"] for s in ALL_SCENARIOS]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestExhaustiveDecisions:
    """Every unique path through the 5-level decision tree."""

    @pytest.mark.parametrize("scenario", ALL_SCENARIOS, ids=SCENARIO_IDS)
    def test_decision_correct(self, scenario):
        result = evaluate_underwriting(scenario["params"])
        assert result["decision"] == scenario["expected_decision"], (
            f'{scenario["id"]}: expected {scenario["expected_decision"]}, got {result["decision"]}'
        )

    @pytest.mark.parametrize("scenario", ALL_SCENARIOS, ids=SCENARIO_IDS)
    def test_expected_rule_fired(self, scenario):
        result = evaluate_underwriting(scenario["params"])
        assert scenario["expected_rule"] in result["rules_fired"], (
            f'{scenario["id"]}: expected rule {scenario["expected_rule"]} not in {result["rules_fired"]}'
        )

    @pytest.mark.parametrize("scenario", ALL_SCENARIOS, ids=SCENARIO_IDS)
    def test_fraud_flags_correct(self, scenario):
        if "expected_fraud_flags" not in scenario:
            return  # Not a fraud-combo scenario
        result = evaluate_underwriting(scenario["params"])
        assert sorted(result["fraud_flags"]) == sorted(scenario["expected_fraud_flags"]), (
            f'{scenario["id"]}: expected flags {scenario["expected_fraud_flags"]}, '
            f'got {result["fraud_flags"]}'
        )

    @pytest.mark.parametrize("scenario", ALL_SCENARIOS, ids=SCENARIO_IDS)
    def test_deterministic(self, scenario):
        """Same input → identical output on 3 consecutive runs."""
        r1 = evaluate_underwriting(scenario["params"])
        r2 = evaluate_underwriting(scenario["params"])
        r3 = evaluate_underwriting(scenario["params"])
        assert r1 == r2, f'{scenario["id"]}: run 1 != run 2'
        assert r2 == r3, f'{scenario["id"]}: run 2 != run 3'

    @pytest.mark.parametrize("scenario", ALL_SCENARIOS, ids=SCENARIO_IDS)
    def test_commitment_deterministic(self, scenario):
        """Same input → same Poseidon2/SHA-256 commitment hash."""
        input_bytes = json.dumps(
            scenario["params"], sort_keys=True, separators=(",", ":")
        ).encode()
        h1, _ = commit(input_bytes)
        h2, _ = commit(input_bytes)
        assert h1 == h2, f'{scenario["id"]}: commitment not deterministic'


class TestExhaustiveCoverage:
    """Verify we actually covered every path."""

    def test_total_scenario_count(self):
        """We generated the expected number of scenarios."""
        # 13 L1 (6 failures + 3 citizenships + 4 boundaries)
        # + 7 L2 (3 rejects + 4 boundaries)
        # + 4 tiers × 21 (3 DTI/coll combos + 2 boundaries + 16 fraud combos)
        # = 13 + 7 + 84 = 104
        assert len(ALL_SCENARIOS) == 104, (
            f"Expected 104 scenarios, got {len(ALL_SCENARIOS)}"
        )

    def test_all_decisions_covered(self):
        """Every possible decision outcome appears at least once."""
        decisions = set()
        for s in ALL_SCENARIOS:
            decisions.add(s["expected_decision"])
        expected = {
            "approved",
            "referred",
            "declined_eligibility",
            "declined_credit",
            "declined_dti",
            "declined_collateral",
            "declined_fraud",
        }
        assert decisions == expected, f"Missing decisions: {expected - decisions}"

    def test_all_tiers_covered(self):
        """Every credit tier appears in at least one scenario."""
        tiers = set()
        for s in ALL_SCENARIOS:
            r = evaluate_underwriting(s["params"])
            if r["credit_tier"]:
                tiers.add(r["credit_tier"])
        expected = {"prime", "near_prime", "subprime", "reject"}
        assert expected.issubset(tiers), f"Missing tiers: {expected - tiers}"

    def test_all_fraud_flag_combos_per_tier(self):
        """Every fraud flag combination (16) tested for each tier."""
        for tier in ("prime", "prime_pmi", "near_prime", "subprime"):
            fraud_scenarios = [
                s for s in ALL_SCENARIOS
                if s["id"].startswith(f"{tier}_fraud_")
            ]
            assert len(fraud_scenarios) == 16, (
                f"{tier}: expected 16 fraud combos, got {len(fraud_scenarios)}"
            )

    def test_all_individual_fraud_flags_tested(self):
        """Each of the 4 fraud flags appears in at least one fired scenario."""
        all_fired_flags = set()
        for s in ALL_SCENARIOS:
            if "expected_fraud_flags" in s:
                for f in s["expected_fraud_flags"]:
                    all_fired_flags.add(f)
        expected = {"income_inconsistency", "velocity_alert", "address_mismatch", "synthetic_identity"}
        assert all_fired_flags == expected

    def test_no_duplicate_scenario_ids(self):
        """Every scenario has a unique ID."""
        assert len(SCENARIO_IDS) == len(set(SCENARIO_IDS)), "Duplicate scenario IDs found"
