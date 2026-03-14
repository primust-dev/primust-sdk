// ── Level 1: Basic eligibility gates ──

// Block minors and over-age applicants
forbid(
  principal,
  action == Action::"apply",
  resource == Resource::"loan"
) when {
  principal.age < 18 || principal.age > 75
};

// Block non-eligible citizenships
forbid(
  principal,
  action == Action::"apply",
  resource == Resource::"loan"
) unless {
  principal.citizenship == "US" ||
  principal.citizenship == "PR" ||
  principal.citizenship == "GU"
};

// Block out-of-range loan amounts
forbid(
  principal,
  action == Action::"apply",
  resource == Resource::"loan"
) when {
  resource.amount < 50000 || resource.amount > 2000000
};

// ── Level 2: Credit scoring gates ──

// Prime applicants (740+) — allow with standard terms
permit(
  principal,
  action == Action::"originate",
  resource == Resource::"loan"
) when {
  principal.credit_score >= 740 &&
  principal.dti_ratio <= 0.43 &&
  resource.ltv_ratio <= 0.90
};

// Prime with PMI — allow higher LTV
permit(
  principal,
  action == Action::"originate",
  resource == Resource::"loan"
) when {
  principal.credit_score >= 740 &&
  principal.dti_ratio <= 0.43 &&
  resource.ltv_ratio <= 0.95 &&
  resource.has_pmi == true
};

// Near-prime (680-739) — tighter limits
permit(
  principal,
  action == Action::"originate",
  resource == Resource::"loan"
) when {
  principal.credit_score >= 680 &&
  principal.credit_score < 740 &&
  principal.dti_ratio <= 0.36 &&
  resource.ltv_ratio <= 0.80
};

// Subprime (620-679) — requires compensating factors
permit(
  principal,
  action == Action::"originate",
  resource == Resource::"loan"
) when {
  principal.credit_score >= 620 &&
  principal.credit_score < 680 &&
  principal.compensating_factors_count >= 2 &&
  principal.dti_ratio <= 0.28 &&
  resource.ltv_ratio <= 0.70
};

// ── Level 3: Fraud gates (forbid overrides permit) ──

// Income inconsistency — block origination
forbid(
  principal,
  action == Action::"originate",
  resource == Resource::"loan"
) when {
  principal.stated_income > principal.verified_income * 1.30
};

// Application velocity — block origination
forbid(
  principal,
  action == Action::"originate",
  resource == Resource::"loan"
) when {
  principal.applications_last_90_days > 3
};

// Address mismatch on primary residence
forbid(
  principal,
  action == Action::"originate",
  resource == Resource::"loan"
) when {
  principal.mailing_state != resource.property_state &&
  resource.occupancy_type == "primary_residence"
};

// Synthetic identity indicator
forbid(
  principal,
  action == Action::"originate",
  resource == Resource::"loan"
) when {
  principal.ssn_issue_year > principal.birth_year + 18
};

// ── Level 4: Manual review routing ──

// Route to senior underwriter when close to limits
permit(
  principal,
  action == Action::"refer_to_senior_underwriter",
  resource == Resource::"loan"
) when {
  principal.credit_score >= 620 &&
  principal.dti_ratio > 0.36 &&
  principal.dti_ratio <= 0.50
};

// Route to fraud team
permit(
  principal,
  action == Action::"refer_to_fraud_team",
  resource == Resource::"loan"
) when {
  principal.applications_last_90_days > 2 ||
  principal.stated_income > principal.verified_income * 1.15
};

// ── Level 5: Investor eligibility (secondary market) ──

// Conforming loan eligible for GSE sale
permit(
  principal,
  action == Action::"sell_to_gse",
  resource == Resource::"loan"
) when {
  resource.amount <= 766550 &&
  principal.credit_score >= 680 &&
  principal.dti_ratio <= 0.43 &&
  resource.ltv_ratio <= 0.80 &&
  resource.occupancy_type == "primary_residence"
};

// Jumbo loan — portfolio retention only
forbid(
  principal,
  action == Action::"sell_to_gse",
  resource == Resource::"loan"
) when {
  resource.amount > 766550
};
