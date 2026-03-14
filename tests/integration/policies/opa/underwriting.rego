package underwriting

import future.keywords.if
import future.keywords.in
import future.keywords.contains

# ── Level 1: Basic eligibility gates ──

default eligible = false

eligible if {
    input.applicant.age >= 18
    input.applicant.age <= 75
    input.applicant.citizenship in {"US", "PR", "GU"}
    input.loan.amount >= 50000
    input.loan.amount <= 2000000
}

# ── Level 2: Credit scoring rules ──

default credit_tier = "reject"

credit_tier = "prime" if {
    input.applicant.credit_score >= 740
}

credit_tier = "near_prime" if {
    input.applicant.credit_score >= 680
    input.applicant.credit_score < 740
}

credit_tier = "subprime" if {
    input.applicant.credit_score >= 620
    input.applicant.credit_score < 680
    input.applicant.compensating_factors_count >= 2
}

# ── Level 3: Debt-to-income analysis ──

default dti_acceptable = false

max_dti_ratio := 0.43 if { credit_tier == "prime" }
max_dti_ratio := 0.36 if { credit_tier == "near_prime" }
max_dti_ratio := 0.28 if { credit_tier == "subprime" }

dti_acceptable if {
    input.applicant.dti_ratio <= max_dti_ratio
}

# ── Level 4: Collateral / LTV rules ──

default collateral_adequate = false

max_ltv := 0.95 if { credit_tier == "prime"; input.loan.has_pmi }
max_ltv := 0.90 if { credit_tier == "prime"; not input.loan.has_pmi }
max_ltv := 0.80 if { credit_tier == "near_prime" }
max_ltv := 0.70 if { credit_tier == "subprime" }

collateral_adequate if {
    input.loan.ltv_ratio <= max_ltv
}

# ── Level 5: Cross-field fraud indicators ──

default fraud_flags = set()

fraud_flags contains "income_inconsistency" if {
    input.applicant.stated_income > input.applicant.verified_income * 1.3
}

fraud_flags contains "velocity_alert" if {
    input.applicant.applications_last_90_days > 3
}

fraud_flags contains "address_mismatch" if {
    input.applicant.mailing_state != input.property.state
    not input.applicant.investment_property
}

fraud_flags contains "synthetic_identity" if {
    input.applicant.ssn_issue_year > input.applicant.birth_year + 18
}

default fraud_acceptable = false

fraud_acceptable if {
    count(fraud_flags) == 0
}

# ── Level 6: Final decision (compound) ──

default decision = "declined"

decision = "approved" if {
    eligible
    credit_tier != "reject"
    dti_acceptable
    collateral_adequate
    fraud_acceptable
}

decision = "referred" if {
    eligible
    credit_tier != "reject"
    dti_acceptable
    collateral_adequate
    not fraud_acceptable
    count(fraud_flags) <= 2
}

decision = "declined_fraud" if {
    count(fraud_flags) > 2
}

# ── Output: structured decision with breakdown ──

result := {
    "decision": decision,
    "eligible": eligible,
    "credit_tier": credit_tier,
    "dti_acceptable": dti_acceptable,
    "dti_limit": max_dti_ratio,
    "collateral_adequate": collateral_adequate,
    "ltv_limit": max_ltv,
    "fraud_flags": fraud_flags,
    "fraud_acceptable": fraud_acceptable,
}
