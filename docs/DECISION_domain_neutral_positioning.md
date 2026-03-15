# DECISION: Domain-Neutral Governance Primitive
## Primust, Inc. · Proposed Addition to DECISIONS
### March 15, 2026 · For review and merge into DECISIONS_v12

---

## Summary

Primust's core primitive — the GEP (Governed Execution Proof) and its portable artifact, the VPEC — is domain-neutral. AI governance is the entry market, not the defining frame. The core schema, SDK surface, verification path, and proof level hierarchy contain zero AI-specific fields. Domain specificity lives exclusively in check implementations, policy bundles, and domain packs.

---

## System Invariant (Reinforced)

> No `agent_id`, no `tool_name`, no `model_name`, no AI-specific fields in the core schema.

This invariant was established in DECISIONS_v11. This decision reinforces it and extends it to a formal architectural boundary.

**Core schema fields (domain-neutral):**
- `pipeline_id` — not `agent_id`
- `check_name` — not `tool_name`
- `check_type` — `built_in` | `custom` | `witnessed`
- `proof_level_floor` — mathematical | verifiable_inference | execution | witnessed | attestation
- `provable_surface` — 0.0 to 1.0
- `commitment_hash` — SHA-256 of check input/output
- `signature` — Ed25519
- `issued_at` — RFC 3339 timestamp

None of these fields assume AI. None of these fields assume software. They describe: a process ran, checks executed, results were committed, a proof was issued.

**Test:** If a field name would confuse a manufacturing QC engineer or a clinical data manager, it does not belong in core. Domain-specific fields belong in domain pack extensions.

---

## The GEP Proves Any Declared Process Ran on Committed Data

The four-word explanation from DECISIONS_v11 is domain-neutral by design:

**Input -> Checks -> Output -> Verify**

| Step | AI Agent Example | Software Build Example | Financial Pipeline Example | Clinical Trial Example | Manufacturing QC Example |
|---|---|---|---|---|---|
| Input | User prompt, context | Source code, dependencies | Market data feed | Patient data, CRF | Raw material lot, specs |
| Checks | PII regex, cost bounds, command patterns | SAST, dependency hash, SBOM gen | Reconciliation, schema validation, threshold | Audit trail integrity, e-signature, completeness | Dimensional inspection, material cert, traceability |
| Output | Agent response | Build artifact | Processed dataset | Cleaned dataset | Inspected component |
| Verify | `primust verify vpec.json` | `primust verify vpec.json` | `primust verify vpec.json` | `primust verify vpec.json` | `primust verify vpec.json` |

The verification step is identical across all domains. The VPEC schema is identical. The proof levels are identical. Only the checks differ.

---

## Built-In Checks: Domain-Neutral Core

primust-checks (Apache-2.0) ships two categories of built-in checks.

### Domain-Neutral Primitives

These checks apply to any process type. They are the foundation.

| Check | Proof Ceiling | What It Proves |
|---|---|---|
| `schema_validation` | Mathematical | Input/output conforms to declared JSON Schema |
| `reconciliation_check` | Mathematical | Two datasets agree within declared tolerance |
| `dependency_hash_check` | Mathematical | Dependencies match declared hashes (SBOM, lockfile, BOM) |
| `threshold_check` | Mathematical | Numeric value within declared bounds |
| `timestamp_ordering_check` | Mathematical | Events occurred in declared sequence |
| `upstream_vpec_verify` | Mathematical | Upstream org's VPEC is cryptographically valid (see DECISION_crossorg_verification) |

### AI-Focused Checks (Domain Pack: primust-ai)

These checks are relevant primarily to AI/ML workloads. They ship in the AI domain pack, not in core.

| Check | Proof Ceiling | What It Proves |
|---|---|---|
| `secrets_scanner` | Mathematical | No secrets/API keys in input/output |
| `pii_regex` | Mathematical | No PII patterns detected (regex-based) |
| `cost_bounds` | Mathematical | LLM API cost within declared budget |
| `command_patterns` | Mathematical | Agent commands match allowlist patterns |
| `model_hash_binding` | Execution | Output was produced by declared model version |

**Architectural rule:** Core primust-checks contains only domain-neutral primitives. Domain-specific checks live in domain packs. The boundary is enforced at the package level, not by convention.

---

## Policy Bundles: Domain-Neutral and Domain-Specific

### Domain-Neutral Bundles (ship in primust-checks)

| Bundle | Target Regulation/Standard | Checks Included |
|---|---|---|
| `supply_chain_v1` | SLSA, NIST SSDF, SBOM mandates | dependency_hash_check, schema_validation, upstream_vpec_verify, timestamp_ordering_check |
| `data_pipeline_v1` | SOX data quality, MiFID II | reconciliation_check, schema_validation, threshold_check, timestamp_ordering_check |
| `quality_control_v1` | ISO 9001, AS9100, ISO 13485 | schema_validation, threshold_check, reconciliation_check, upstream_vpec_verify |

### AI Bundles (ship in primust-ai)

| Bundle | Target Regulation/Standard | Checks Included |
|---|---|---|
| `eu_ai_act_v1` | EU AI Act | pii_regex, cost_bounds, command_patterns, secrets_scanner, model_hash_binding, schema_validation |
| `hipaa_ai_v1` | HIPAA + AI | pii_regex, secrets_scanner, schema_validation, cost_bounds |
| `soc2_ai_v1` | SOC 2 Type II + AI | secrets_scanner, command_patterns, schema_validation, cost_bounds |
| `general_ai_v1` | Best practice | pii_regex, secrets_scanner, cost_bounds, command_patterns |
| `coding_agent_v1` | Enterprise coding | command_patterns, secrets_scanner, cost_bounds |

**Packaging rule:** An organization using Primust for software supply chain governance installs `primust` and `primust-checks`. It never encounters `primust-ai`, `pii_regex`, or `cost_bounds` unless it chooses to. The AI domain pack is opt-in, not bundled.

---

## Cross-Org Verification Is Domain-Neutral

`upstream_vpec_verify` (see DECISION_crossorg_verification) is the clearest expression of domain neutrality. The check verifies a VPEC. It does not know what process the VPEC attests to. A bank verifying a fintech vendor's data quality VPEC uses the exact same check as a platform verifying an ISV's AI governance VPEC. Same code. Same proof level. Same gap taxonomy.

---

## Non-AI Expansion Markets

AI governance is the entry market because:
1. Regulatory urgency (EU AI Act, state-level AI bills) creates immediate demand
2. AI teams are early adopters of developer tools
3. The AI governance market is greenfield — no entrenched incumbents with cryptographic proof

But the following markets have equal or greater long-term TAM, and Primust's domain-neutral primitive applies without modification:

### Software Supply Chain
- **Regulatory tailwind:** SLSA framework adoption, NIST SSDF (SP 800-218), Executive Order 14028 SBOM mandates, EU Cyber Resilience Act
- **Primust fit:** `dependency_hash_check` + `upstream_vpec_verify` + `schema_validation` = cryptographic proof that a build pipeline ran declared checks on declared dependencies
- **Entry motion:** `supply_chain_v1` bundle + CI integration

### Financial Data Integrity
- **Regulatory tailwind:** SOX Section 404 (internal controls), MiFID II data quality requirements, Basel III/IV operational risk, DORA (EU Digital Operational Resilience Act)
- **Primust fit:** `reconciliation_check` + `threshold_check` + `schema_validation` = cryptographic proof that data pipeline reconciliations passed on committed data
- **Entry motion:** `data_pipeline_v1` bundle + existing enterprise SDK

### Pharmaceutical / Clinical
- **Regulatory tailwind:** FDA 21 CFR Part 11 (electronic records/signatures), EU GMP Annex 11, ICH E6(R3) (GCP modernization), FDA CDER data integrity guidance
- **Primust fit:** `timestamp_ordering_check` + `schema_validation` + `reconciliation_check` + witnessed proof level (human pharmacist approval) = cryptographic proof that clinical data processing met regulatory requirements
- **Entry motion:** `quality_control_v1` bundle + witnessed check type + CRO cross-org verification

### Manufacturing QC
- **Regulatory tailwind:** ISO 9001:2015, AS9100D (aerospace), ISO 13485 (medical devices), IATF 16949 (automotive), FDA 21 CFR Part 820 (medical device QSR)
- **Primust fit:** `threshold_check` + `reconciliation_check` + `upstream_vpec_verify` = cryptographic proof that QC inspections passed on committed measurements
- **Entry motion:** `quality_control_v1` bundle + supplier cross-org verification

---

## Marketing and Documentation Implications

### Lead Message

**Wrong:** "Prove your AI governance ran."
**Right:** "Prove your governance checks ran."

**Wrong:** "Cryptographic AI governance."
**Right:** "Cryptographic governance proofs."

**Wrong:** "The AI governance primitive."
**Right:** "The governance primitive." (AI mentioned as primary use case, not defining frame.)

### Documentation Structure

```
docs.primust.com/
  quickstart/              # Domain-neutral: Input -> Checks -> Output -> Verify
  concepts/
    gep/                   # Domain-neutral explanation
    vpec/                  # Domain-neutral schema
    proof-levels/          # Domain-neutral hierarchy
    cross-org/             # Domain-neutral verification chains
  guides/
    ai-agents/             # AI domain pack guide
    software-supply-chain/ # Supply chain bundle guide
    data-pipelines/        # Data pipeline bundle guide
    manufacturing-qc/      # QC bundle guide
  reference/
    checks/                # All checks, tagged by domain
    bundles/               # All bundles, tagged by domain
```

The quickstart does NOT mention AI until the user selects a domain pack. The concepts section is entirely domain-neutral. Domain specificity enters only in the guides section.

### Website (primust.com)

Hero: "Prove your governance checks ran." Sub-hero references AI as the first use case, not the only one. Use case pages cover AI, software supply chain, financial data, and regulated industries.

---

## Rationale

1. **Domain lock-in is a strategic error.** If Primust is "the AI governance company," it cannot sell to a bank's data quality team, a pharma company's clinical operations, or an aerospace manufacturer's QC department without repositioning. Domain-neutral core + domain-specific packs avoids this trap.

2. **The primitive genuinely is domain-neutral.** This is not marketing aspiration — it is architectural fact. The VPEC schema contains no AI-specific fields. The proof levels apply to any process type. Ed25519 does not care what was signed. The domain-neutral positioning reflects the actual technical design.

3. **Cross-org verification demands domain neutrality.** A verification chain frequently crosses domain boundaries. A bank verifying a fintech vendor's VPEC should not need to understand AI-specific fields. A platform verifying an ISV's VPEC should not need to understand financial data fields. The common schema must be domain-neutral for cross-org to work.

4. **Non-AI markets have larger TAM and stronger regulatory tailwinds.** SOX compliance alone is a larger market than AI governance. Software supply chain mandates (SBOM, SLSA) are already in effect. Pharmaceutical data integrity requirements have existed for decades. These markets are ready now — they just need the right primitive.

5. **AI entry market provides distribution for non-AI expansion.** AI teams adopt early, prove the primitive works, and generate case studies. Enterprise sales then expand to adjacent teams (data engineering, DevOps, compliance) within the same organization. Domain-neutral core makes this expansion zero-friction.

---

*DECISION_domain_neutral_positioning.md · March 15, 2026 · Primust, Inc.*
*Proposed for DECISIONS_v12. Subject to review.*
