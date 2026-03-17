# PRIMUST TECHNICAL SPECIFICATION
## v8.0 · March 16, 2026 · Supersedes TECH_SPEC v7 and all prior versions
## Canonical sources: DECISIONS_v13, ARCHITECTURE_v1, MASTER_v9

> New in v8: VPEC field renames (proof_level_floor, provable_surface, gaps, environment). Gap taxonomy 47 types. primust-connectors: all 7 Python REST connectors built (321 tests), Apache-2.0 license. Guidewire: Python REST / Attestation ceiling built, Java spec only. visibility field restored. pk_sb_ canonical. system_unavailable gap type added. Schema version 5.0.0.

---

## 1. SYSTEM INVARIANTS — NEVER VIOLATE

1. **Raw content does not transit Primust.** Commitment hashes and bounded normalized metadata only. Raw input/output never does. For Witnessed: display_content and rationale committed locally; only hashes transit.

2. **Fail open, fail honest.** Primust failures do not block customer pipelines. All failures become gaps.

3. **Weakest-link proof level.** proof_level_floor = minimum across all records. Cannot be faked upward.

4. **Gaps recorded honestly.** detectable_from_surface: false means "unknown" not "ungoverned."

5. **Domain-neutral core.** No agent_id, tool_name, trace, pipeline_id in core schema.

6. **Promotion gates in code.** P1 → SHAREABLE impossible without override + watermark.

7. **Connector dry-run before production.** --dry-run confirms "Raw content: NONE" before enterprise security approval.

8. **signer_id ≠ kid.** Both required in every signature envelope.

9. **Primust never holds reviewer credentials.** Reviewer's Ed25519 private key never leaves customer environment.

10. **human_review maps to Witnessed, not Attestation.** Protocol distinction, not a label.

11. **Manifest hash captured per record.** Every CheckExecutionRecord stores manifest_hash at time of execution.

12. **Customer private key never leaves customer environment.** BYOK signing: Primust calls customer signing endpoint with payload. Customer never uploads private key.

13. **upstream_vpec_verify proof ceiling is Mathematical.** Ed25519 verification is deterministic. Never downgrade this ceiling.

---

## 2. CONFIRMED PACKAGE INVENTORY (March 15, 2026)

### 2.1 Deployable Apps

| App | Stack | Location | Status |
|---|---|---|---|
| API | Python / FastAPI / asyncpg | Fly.io dual-region | Built. 16 source files, 61 tests. |
| Dashboard | Next.js 15 / React 19 | Vercel — app.primust.com | Built. GREEN. |
| Verify Site | Next.js 15 | Vercel — verify.primust.com | Built. GREEN. |

### 2.2 Core Packages

| Package | Lang | Key Contents | Status |
|---|---|---|---|
| artifact-core | TS | Canonical JSON, Ed25519 signing, Poseidon2 commitments, VPEC artifact types | Built |
| artifact-core-py | Python | Python mirror | Built |
| zk-core | TS | ZK circuits, witness builders, prover routing, Modal client | Built |
| zk-core-py | Python | Minimal stub | Stub |
| runtime-core | TS | CheckManifest, ProcessRun, ActionUnit, Gap, Waiver, EvidencePack, SQLite store, sync queue, lineage tokens, schema validation | Built |
| runtime-core-py | Python | Mirror — 9 source files, 4 tests | Built |
| policy-engine | TS | Policy snapshot binding, manifest validation, proof ceiling calculation, gap detection, VPEC issuance | Built. 7 tsc errors (non-blocking). |
| policy-engine-py | Python | Early mirror | Early |
| registry | TS | Ed25519 key lifecycle (active/rotated/revoked), JWKS endpoint, manifest registry | Built |
| evidence-pack | TS | Merkle pack assembly, verification instructions | Built. 4 tsc errors (non-blocking). |
| evidence-pack-py | Python | Stub | Stub |
| verifier | TS | Offline verification engine + primust-verify CLI, JWKS caching | Built |
| rules-core | Java | Poseidon2 BN254, canonical JSON, commitment primitives | Built |
| rules-core-go | Go | Module defined | Built |
| zk-worker | Python | Serverless ZK prover on Modal | Built |
| db | SQL | 11 migrations applied (US + EU Neon) | Built |

### 2.3 Customer SDKs

| Package | Lang | Publish Target | Status |
|---|---|---|---|
| sdk-python (primust) | Python | PyPI | Live 1.0.0. YELLOW — poseidon2 prefix pre-existing. |
| primust-verify | Python | PyPI (Apache-2.0) | Live 1.0.0. YELLOW — display string fix pending. |
| primust-checks | Python | PyPI (Apache-2.0) | Live 1.0.0. 8 built-in checks, 7 bundles, 86 tests GREEN. |
| sdk-js (@primust/sdk) | TypeScript | npm | Live 1.0.0. GREEN. |
| sdk-java | Java | Maven Central | Published 1.0.0. GREEN. |
| sdk-csharp | C# (.NET 8) | NuGet | Early. 7 files. Not yet published. |

### 2.4 AI Agent Adapters

| Package | Lang | Target | Tests | Status |
|---|---|---|---|---|
| primust-langgraph | Python | LangGraph | 14 | Live 1.0.0. YELLOW — poseidon2 prefix. |
| primust-google-adk | Python | Google ADK | 14 | Live 1.0.0. YELLOW — poseidon2 prefix. |
| primust-openai-agents | Python | OpenAI Agents SDK | 14 | Live 1.0.0. YELLOW — poseidon2 prefix. |
| primust-otel | Python | OpenTelemetry | 14 | Live 1.0.0. YELLOW — proof level map. |
| @primust/otel | TS | OpenTelemetry | — | Live 1.0.0. YELLOW — proof level map. |

### 2.5 Rule Engine Adapters

| Package | Lang | Target | Proof Ceiling | Status |
|---|---|---|---|---|
| primust-cedar | Java | AWS Cedar | Mathematical (eval()) / Execution (recordEvaluation() — deprecated) | Published 1.0.1. GREEN. eval() wraps isAuthorized(), commits input pre-eval + output post-eval. recordEvaluation() deprecated at Execution. |
| primust-drools | Java | Red Hat Drools | Mathematical (eval() + Map facts) / Execution (recordEvaluation() — deprecated; POJO users) | Published 1.0.1. GREEN. eval() owns KieSession lifecycle, AgendaEventListener captures rule names, getObjects() captures output. Requires Map-based facts for canonical serialization. |
| primust-odm | Java | IBM ODM | Mathematical (eval() via IlrSessionFactory) / Execution (recordExecution() — deprecated) | Published 1.1.0. GREEN. eval() wraps IlrStatelessSession.execute() with real ODM runtime verified. JARs extracted from IBM ODM free developer Docker image (icr.io/cpopen/odm-k8s/odm:9.5). 13 tests pass including ODM runtime integration. No IBM Passport Advantage required for development. |
| primust-opa | Go | OPA v1.4.2 | Mathematical (local) / Attestation (remote) | Tagged v1.0.1. GREEN. recordCheck() gap-aware: 6 silent failure paths → governance_recording_failed gaps. EvalResult.Gap + OutputCommitmentHash fields added. |

### 2.6 Regulated Connectors

| Package | Contents | Status |
|---|---|---|
| primust-connectors | 7 Python REST connectors — ComplyAdvantage (48 tests), NICE Actimize (51), FICO Blaze + IBM ODM (41), FICO Falcon (45), Pega CDH (46), Wolters Kluwer UpToDate (46), Guidewire ClaimCenter (38). Total: 321 tests. All Attestation ceiling (REST wrappers). Java/C# in-process specs exist for Mathematical ceiling — require vendor SDK licenses. **License: Apache-2.0.** | Built. |

### 2.7 Schemas (v5.0.0)

11 JSON schemas. Schema version 5.0.0. Migration 012 pending: VPEC field renames, pk_sb_, gap taxonomy 47 types.
Golden test vectors. PROVISIONAL_FREEZE.md. SIGNER_TRUST_POLICY.md.

### 2.8 Known YELLOW Test Failures (Pre-Existing, Non-Blocking)

| Failure | Packages | Count | Fix |
|---|---|---|---|
| poseidon2 prefix (sha256: vs poseidon2:) | sdk-python, langgraph, openai-agents, google-adk | 13 | Wire to Noir output — gated on ZK circuit integration |
| Proof level map values | primust-otel (py + js) | 15 | Update test fixtures to current canonical enum values |
| Verifier display string | primust-verify | 2 | Update "verifiable_inference" display label to "Verifiable Inference" |

---

## 3. DATA FLOW — WHAT TRANSITS PRIMUST

### At VPEC issuance (the ONLY data Primust receives)

```json
{
  "run_id": "...",
  "workflow_id": "...",
  "policy_snapshot_hash": "sha256:...",
  "manifest_hashes": ["sha256:...", "sha256:..."],
  "check_execution_records": [
    {
      "manifest_id": "sha256:...",
      "input_commitment_hash": "poseidon2:...",
      "output_commitment_hash": "poseidon2:...",
      "check_result": "pass",
      "proof_level_achieved": "mathematical",
      "actor_id": "user_uuid | null",
      "explanation_commitment": "poseidon2:hex | null",
      "bias_audit": { ... } | null
    }
  ],
  "activity_chain": {
    "record_count": 47,
    "chain_root": "sha256:...",
    "governance_decision_summary": {"allowed": 45, "blocked": 2, "modified": 0},
    "activity_log_present": true
  },
  "gaps": []
}
```

**`visibility` parameter (all record() calls):**
Default: `"opaque"`. Values: `"opaque"` | `"selective"` | `"transparent"`. Connector records enforce `"opaque"` — not configurable by caller. Regulated data must never be transparent.

**Never transits Primust:**
- Customer agent inputs, outputs, or tool parameters
- Customer source code or check logic or model weights
- Individual AgentActivityRecords
- Reviewer display content or rationale text
- Matched PII patterns, matched secret strings, matched command strings
- Explanation text (only explanation_commitment hash transits)
- Actual bias audit disparity values (only disparity_result_commitment hash transits)

### Commitment hash computation (in-process before any network call)

```python
input_commitment_hash = poseidon2(canonical_json(input))
output_commitment_hash = poseidon2(canonical_json(output))
explanation_commitment = poseidon2(canonical_json(explanation_text))  # if required
disparity_result_commitment = poseidon2(str(disparity_value))
```

---

## 4. POLICY CENTER API SPEC

### 4.1 Endpoints

**GET /api/v1/policy/bundles**
Returns all available policy bundles (built-in + org custom). No auth for built-in bundles.

**POST /api/v1/manifests** (org-scoped, auth required)
Register a manifest. Content-addressed: manifest_id = SHA256(canonical(manifest_json)).
Returns: `{ "manifest_id": "sha256:...", "registered_at": "..." }`

**GET /api/v1/manifests/{manifest_id}**
Returns manifest JSON. No auth required.

**POST /api/v1/policy/generate-code** (org-scoped)
Body: `{ "framework": "langgraph"|"openai_agents"|"google_adk"|"otel"|"custom", "manifest_ids": [...], "policy_id": "..." }`
Returns: `{ "python_code": "...", "typescript_code": "...", "java_code": "..." }`

### 4.2 Built-in Bundles (seed data)

| bundle_id | Required checks | Framework mappings |
|---|---|---|
| ai_agent_general_v1 | secrets_scanner, pii_regex, cost_bounds, enforcement_rate (ZK) | — |
| eu_ai_act_art12_v1 | enforcement_rate (ZK), pii_non_detection (ZK), policy_continuity (ZK) | eu_ai_act_art12, eu_ai_act_art9 |
| hipaa_safeguards_v1 | pii_non_detection (ZK), enforcement_rate (ZK), audit_log_coverage | hipaa_164312 |
| soc2_cc_v1 | cost_bound_zk, enforcement_rate (ZK), policy_config_integrity (ZK) | soc2_cc71, soc2_cc81, soc2_cc61 |
| coding_agent_v1 | command_patterns, secrets_scanner, enforcement_rate (ZK) | — |
| supply_chain_governance_v1 | upstream_vpec_verify, dependency_hash_check | — |
| financial_data_governance_v1 | upstream_vpec_verify, reconciliation_check, schema_validation | — |

---

## 5. PRIMUST.CHECKS HARNESS SPEC

### 5.1 Package
Location: `packages/primust-checks/`
License: Apache-2.0
Publish: PyPI as `primust-checks`
Status: Live 1.0.0. 86/86 tests GREEN.

### 5.2 Interface

```python
from primust_checks import Harness, CheckResult

harness = Harness(policy="eu_ai_act_art12_v1")                         # observability only
harness = Harness(policy="eu_ai_act_art12_v1", api_key="pk_live_xxx")  # proof layer active

@harness.check
def my_existing_check(input, output) -> CheckResult:
    return CheckResult(passed=your_logic(input), evidence="...")

result = harness.run(input=..., output=...)
# result.passed, result.gaps, result.vpec (None if no api_key)
```

### 5.3 Built-in Check Specifications

**secrets_scanner** (Mathematical)
Patterns: AWS_ACCESS_KEY_ID, GCP service account JSON keys, GitHub tokens (ghp_, ghs_), generic API key patterns
Returns: CheckResult(passed=no_secrets_found, evidence=matched_pattern_count)
Invariant: matched string values NEVER in evidence

**pii_regex** (Mathematical)
Patterns: SSN, credit cards (Luhn-validated), email (RFC 5322), US phone
Returns: CheckResult(passed=no_pii_found, evidence=pii_type_counts)
Invariant: matched values NEVER in evidence

**cost_bounds** (Mathematical)
Config: max_tokens_per_run (default: 100000), max_cost_usd (default: 1.00)
Returns: CheckResult(passed=within_bounds, evidence={token_count, cost_usd})

**command_patterns** (Mathematical)
Config: denylist (default: rm -rf, DROP TABLE, chmod 777, curl|bash, wget|bash) or allowlist
Returns: CheckResult(passed=no_blocked_command, evidence=matched_pattern_name)
Invariant: matched command string NEVER in evidence

---

**upstream_vpec_verify** (Mathematical)
Verifies a received VPEC from an upstream organization before processing their output.
Ed25519 verification is deterministic — same inputs always yield same result. Proof ceiling: Mathematical.
Domain-neutral: upstream process can be AI pipeline, software build, financial data delivery, clinical data, any VPEC-bearing process.

Inputs:
```
vpec_artifact: VPEC JSON object
expected_issuer_org_id: string — must match VPEC issuer field
minimum_proof_level_floor: enum (attestation|witnessed|execution|verifiable_inference|mathematical)
trust_root_pem: string (optional) — if provided, zero network calls ever
required_claims: array[string] (optional) — claim_ids that must be present and verified
reject_sandbox: boolean (default: true)
```

Outputs:
```
CheckResult(
  passed=bool,
  evidence={
    exit_code: int,             # 0=valid, 1=invalid, 2=sandbox, 3=key_revoked
    proof_level_floor_met: bool,
    issuer_org_id_match: bool,
    verified_vpec_id: string,
    verified_at: RFC3339,
    claims_verified: list[str],
    failure_reason: str|None
  }
)
```

Gap codes on failure: upstream_vpec_invalid_signature (Critical), upstream_vpec_sandbox (High), upstream_vpec_key_revoked (High), upstream_vpec_insufficient_proof_level (High), upstream_vpec_missing_claim (Medium), upstream_vpec_issuer_mismatch (Critical), upstream_vpec_missing (High).
Network: conditional — not required if trust_root_pem provided.
Invariant: verified_vpec_id recorded in evidence. Failure reason never suppressed.

---

**schema_validation** (Mathematical)
Validates incoming data payload against a declared JSON Schema or Avro schema.
Config: schema_ref (content-addressed schema hash), strict_mode (bool)
Returns: CheckResult(passed=schema_valid, evidence={field_count, violation_count, violation_paths})
Invariant: violation values NEVER in evidence — only field paths and counts.
Domain: Financial data delivery, API acceptance, data pipeline ingestion.

---

**reconciliation_check** (Mathematical)
Verifies numeric reconciliation between a delivered dataset and a declared expected summary.
Config: expected_row_count, expected_checksum, expected_totals{field: value}
Returns: CheckResult(passed=reconciled, evidence={row_count_match, checksum_match, total_deltas})
Invariant: individual row values NEVER in evidence.
Domain: Financial data vendor delivery, reporting pipelines, position data.

---

**dependency_hash_check** (Mathematical)
Verifies that a delivered software artifact or dependency manifest matches declared content hashes.
Config: expected_hashes{artifact_name: sha256_hex}, hash_algorithm (default: sha256)
Returns: CheckResult(passed=all_match, evidence={matched_count, mismatch_count, missing_count})
Invariant: file contents NEVER in evidence — only hash comparison results.
Domain: Software build acceptance, SBOM verification, CI/CD artifact promotion.

---

### 5.4 Without vs With API Key

| Behavior | Without api_key | With api_key |
|---|---|---|
| Checks run | Yes | Yes (identical) |
| Check results computed | Yes | Yes (identical) |
| Gaps identified | Yes | Yes (identical) |
| Dashboard observability | Yes | Yes |
| VPEC issued | No | Yes |
| result.vpec | None | VPEC object |
| result.observability_only | True | False |

### 5.5 BYOC Invariants
- Check logic runs in customer environment
- CheckResult.evidence: metadata only (counts, types, booleans) — never content values
- Commitment hash computed from input/output before check runs

---

## 6. BYOK SIGNING SPEC

### 6.1 Database Schema

```sql
CREATE TABLE org_signing_keys (
  org_id          TEXT NOT NULL,
  key_id          TEXT NOT NULL,
  public_key_pem  TEXT NOT NULL,
  signing_endpoint_url TEXT NOT NULL,
  status          TEXT NOT NULL CHECK (status IN ('pending_verification', 'active', 'revoked')),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  activated_at    TIMESTAMPTZ,
  PRIMARY KEY (org_id, key_id)
);
```

### 6.2 Registration Flow

```
POST /api/v1/org/signing-keys
→ key_id assigned → verification_challenge generated → status: pending_verification

POST /api/v1/org/signing-keys/verify
→ Verify Ed25519(challenge_signature, public_key_pem) → status → active
```

### 6.3–6.6 (Signing flow, VPEC signature field, customer endpoint contract, failure handling)
See TECH_SPEC_v6 §6.3–6.6 — unchanged in v7.

---

## 7. ACTIVITY CHAIN SPEC (CANONICAL — AI DOMAIN PACK)

See TECH_SPEC_v6 §7 — unchanged in v7.

AgentActivityRecord schema, chain construction, three backends (SQLite/PostgreSQL/S3+Object Lock), what transits Primust (chain_root only, zero activity records).

---

## 8. ZK CIRCUIT INVENTORY (CANONICAL)

### Built (Noir, UltraHonk, Modal CPU)

From zk-core: skip_condition, config_epoch_continuity, coverage_check, ordering_proof

From original migration: range_proof, cost_bound, pii_non_detection, enforcement_rate, continuous_compliance, fleet_aggregate, temporal_comparison, tool_whitelist, multi_framework, cross_org_session

Extended circuits: C15: pipeline_coverage (~280K gates), C16: chain_ordering (~160K gates), C17: cross_boundary_session (~100K gates) — supports cross-org verification chain, custom_engine_coverage

### Tier 2 (design partner trigger, Modal GPU)
EZKL/Bionetta for Verifiable Inference level

---

## 9. VERIFICATION SPEC

### 9.0 Four Verification Paths (UPDATED — v7)

**Path 0 — primust-verify embedded (HIGHEST FREQUENCY — relying party)**

The B2B integration pattern. A downstream system embeds primust-verify as a library call before processing upstream output.

```python
from primust_verify import verify

result = verify(vpec_json)                            # network mode
result = verify(vpec_json, trust_root_pem=KEY_PEM)   # zero network, pinned key

if not result.valid:
    raise GovernanceVerificationError(result.failure_reason)
# result.valid, result.proof_level_floor, result.exit_code, result.failure_reason
```

```typescript
import { verify } from '@primust/sdk/verify'
const result = await verify(vpecJson)
if (!result.valid) throw new GovernanceVerificationError(result.failureReason)
```

**Java / C# gap:** No native verifier library. Shell out to `primust verify` CLI.
primust-verify-java: demand-gated — build when first Java relying-party design partner requests embedded verification.

**Path 1 — primust-verify CLI (Apache-2.0)**
```bash
primust verify vpec.json
primust verify vpec.json --trust-root key.pem
primust pack verify pack.json
```

**Path 2 — primust verify CLI (SDK bundled)**
Ships with main SDK. Same library as Path 1.

**Path 3 — verify.primust.com**
Human front door. Convenience only. Not the trust anchor.
MUST display: "You don't need this website. pip install primust-verify — works offline, forever."

### 9.1 Verification Steps (in order)

```
1. Load VPEC JSON
2. Resolve public key:
   a. If --trust-root <pem>: load from file (zero network)
   b. Else: fetch from trust_anchor_url in VPEC signature field (cached by key_id)
3. Verify Ed25519 signature over canonical VPEC JSON
4. Check key status via JWKS (revoked/rotated → exit 3)
5. Verify RFC 3161 timestamp: genTime within expected window, TSA chain valid
6. Verify ZK proofs (all Mathematical/Verifiable Inference claims):
   For each claim: Noir verify(proof, public_inputs, circuit_id) → true/false
7. Verify hash chain integrity: recompute SHA256 chain from record 0 to N
8. Check governance gaps: any unresolved Critical gaps → exit 1 (configurable)
```

### 9.2 Exit Codes

| Code | Meaning |
|---|---|
| 0 | Valid VPEC, all claims verified |
| 1 | Invalid — signature, chain, or ZK proof failure |
| 2 | Valid VPEC, SANDBOX flag (environment: "sandbox") — not audit-acceptable |
| 3 | Valid VPEC, signing key expired or revoked (per JWKS) |

### 9.3 Offline Operation

After first public key fetch, all subsequent verifications require zero network calls.
Only key status (revocation) requires network — skipped with `--trust-root`.

### 9.4 Audit Report Verification (NEW — v7)

```bash
primust verify-report report.pdf
```

Steps:
1. Load PDF
2. Extract signature, key_id, trust_anchor_url from PDF metadata fields (/PrimusReport*)
3. Recompute SHA256 of full PDF bytes (excluding metadata fields)
4. Fetch public key from trust_anchor_url (cached by key_id) or --trust-root
5. Verify Ed25519(signature, sha256_of_pdf, public_key)
6. Check key status via JWKS (unless --trust-root)

Exit codes: 0=valid, 1=invalid, 2=sandbox (any VPEC in underlying pack was sandbox), 3=key revoked.

The report signature is independent of the Evidence Pack signature. Both must be verified separately for full chain assurance.

---

## 10. EVIDENCE PACK FRAMEWORK VIEW SPEC

See TECH_SPEC_v6 §10 — unchanged in v7.

framework_view schema, Primust's disclosure on framework views, AIUC-1 alignment note.

---

## 11. CODING AGENT HOOK ATTACHMENT SPEC (FROM AMDT-16)

See TECH_SPEC_v6 §11 — unchanged in v7.

Claude Code + Cursor hashable payloads, open questions blocking P29-A.

---

## 12. AUDIT REPORT API SPEC (NEW — v7)

### 12.1 Generate Report

**POST /api/v1/evidence-packs/{pack_id}/report**
Auth: org API key required
Body: optional `{ include_framework_view: bool (default: true), locale: "en" }`

Process:
1. Load Evidence Pack from DB, verify org ownership
2. Run primust-verify against all VPECs in pack (server-side)
3. Generate PDF (five sections: see §12.2)
4. Sign: Ed25519(GCP KMS or BYOK) over SHA256(pdf_bytes)
5. Embed signature in PDF metadata (/PrimusReport* fields)
6. Store in R2 (report_id keyed)
7. Write to audit_reports table (migration 008)
8. Return: `{ report_id, download_url, signed_at, expires_at }`

P1 coverage basis: full-page diagonal watermark injected server-side. No client override.

### 12.2 Report Sections

1. **Cover page:** org, period, coverage basis, proof level floor, provable surface, signing key, report ID, verification CLI instruction
2. **Governance summary:** run count, VPEC count, check count, proof level distribution, gap count by severity, framework disposition
3. **Per-VPEC verification results:** signature ✓/✗, timestamp ✓/✗, ZK proofs N/N verified, hash chain ✓/✗, gaps
4. **Framework control mapping** (if framework_view present): per-control claim-to-evidence table
5. **Gaps and waivers table:** all gaps with severity, state, waiver_id, risk_treatment, resolution status
6. **Verification instructions:** verbatim `primust verify-report`, `primust pack verify`, `primust verify` CLI commands

Required disclosure in report (verbatim):
> "Framework control mappings are derived from policy bundle declarations. Primust proves that declared checks ran at the stated proof level. The conclusion that these checks satisfy specific regulatory controls is the customer's compliance determination, not Primust's assertion."

### 12.3 Download

**GET /api/v1/evidence-packs/{pack_id}/report/{report_id}**
Auth: org API key required
Returns: application/pdf

Reports expire after 90 days. Regenerate from same Evidence Pack at any time. Evidence Pack is the source of truth.

### 12.4 Database (Migration 008)

```sql
CREATE TABLE audit_reports (
  report_id       TEXT PRIMARY KEY,
  org_id          TEXT NOT NULL,
  pack_id         TEXT NOT NULL,
  generated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  pdf_sha256      TEXT NOT NULL,
  signature       TEXT NOT NULL,   -- base64 Ed25519
  key_id          TEXT NOT NULL,
  coverage_basis  TEXT NOT NULL,
  expires_at      TIMESTAMPTZ NOT NULL
);
```

---

## 13. AIUC-1 SCHEMA ADDITIONS (NEW — v7 — MIGRATION 009 PENDING)

All additive, nullable unless stated. No architectural changes. Write migration 009 before any production data.

### 13.1 Pipeline Init Fields

```python
p = primust.Pipeline(
    api_key="pk_live_xxx",
    policy="...",
    retention_policy="EU_AI_ACT_10Y",    # string|null — flows into policy_snapshot
    risk_classification="EU_HIGH_RISK"   # string|null — flows into policy_snapshot
)
```

| Field | Type | Closes |
|---|---|---|
| retention_policy | string\|null: FDA_PART11_7Y \| EU_AI_ACT_10Y \| HIPAA_6Y \| SOC2_1Y \| GDPR_3Y | AIUC-1 A001, FDA 21 CFR Part 11 |
| risk_classification | string\|null: EU_HIGH_RISK \| EU_LIMITED_RISK \| EU_MINIMAL_RISK \| US_FEDERAL | EU AI Act Art 6, NIST AI RMF |

### 13.2 check_execution_record New Fields

```json
{
  "manifest_id": "sha256:...",
  "input_commitment_hash": "poseidon2:...",
  "output_commitment_hash": "poseidon2:...",
  "check_result": "pass",
  "proof_level_achieved": "mathematical",
  "actor_id": "user_550e8400 | null",
  "explanation_commitment": "poseidon2:hex | null",
  "bias_audit": {
    "protected_categories": ["race", "gender"],
    "disparity_metric": "demographic_parity",
    "disparity_threshold": 0.05,
    "disparity_result_commitment": "poseidon2:hex",
    "result": "pass | fail | not_applicable"
  }
}
```

| Field | Type | Closes |
|---|---|---|
| actor_id | user_{uuid}\|null | AIUC-1 B007, FDA 21 CFR Part 11 §11.10(d) ALCOA, SOC 2 CC6.1 |
| explanation_commitment | poseidon2:hex\|null | GDPR Art 22, ECOA, EU AI Act Art 13 |
| bias_audit | object\|null | NYC Local Law 144, ECOA/FHA, Colorado SB 24-205 |

Invariant: All values in bias_audit are committed locally. Disparity values never sent to Primust.
Invariant: explanation_commitment = Poseidon2(explanation_text). Plaintext never sent to Primust.

### 13.3 Gap Record New Field

```json
{
  "gap_id": "...",
  "gap_type": "enforcement_override",
  "severity": "critical",
  "incident_report_ref": "EU_AIOFFICE_2026_00456 | null"
}
```

| Field | Type | Closes |
|---|---|---|
| incident_report_ref | string\|null | EU AI Act Art 73, FDA 21 CFR Part 803, DORA Art 19 |

Populated by Approver role via PATCH /v1/gaps/{gap_id}. Only meaningful on severity = critical.

### 13.4 Waiver New Field (REQUIRED)

```json
{
  "waiver_id": "...",
  "risk_treatment": "accept | mitigate | transfer | avoid"
}
```

**risk_treatment is REQUIRED. No default. Approver must declare at waiver creation. UI enforces selection.**

| Value | Meaning |
|---|---|
| accept | Accept risk with time limit (existing waiver behavior, now explicit) |
| mitigate | Active remediation in progress; resolution_vpec_id expected at expiry |
| transfer | Risk transferred to third party (insurer, vendor contract) |
| avoid | Process being modified to eliminate risk entirely |

Closes NIST AI RMF MANAGE 4.1, ISO 42001 §6.1, SOC 2 CC9.1.

### 13.5 policy_pack New Blocks

**compliance_requirements** (nullable object):
```json
{
  "require_actor_id": true,
  "require_explanation_commitment": {
    "on_check_result": ["fail"],
    "on_check_types": ["llm_api", "policy_engine"]
  },
  "require_bias_audit": {
    "on_check_types": ["llm_api"],
    "protected_categories": ["race", "gender", "age"]
  },
  "require_retention_policy": true,
  "require_risk_classification": true
}
```

null = no compliance requirements declared. When set: fires explanation_missing or bias_audit_missing gaps when fields absent. CISO/compliance officer configuration surface.

**sla_policy** (nullable object):
```json
{
  "proof_level_floor_minimum": "execution",
  "provable_surface_minimum": 0.80,
  "max_open_critical_gaps": 0,
  "max_open_high_gaps": 5,
  "retention_policy_required": "EU_AI_ACT_10Y"
}
```

Replaces external --sla-policy file. Threshold inside signed artifact — self-evidencing.

### 13.6 policy_snapshot New Fields

```json
{
  "policy_snapshot_hash": "sha256:...",
  "prompt_version_id": "prompt_v2.4.1 | null",
  "prompt_approved_by": "user_uuid | null",
  "prompt_approved_at": "2026-03-15T09:00:00Z | null",
  "regulatory_context": ["EU_AI_ACT_ART13", "AIUC1_E015", "HIPAA_164_312"]
}
```

| Field | Type | Closes |
|---|---|---|
| prompt_version_id | string\|null | AIUC-1 E004 — change approval evidence |
| prompt_approved_by | user_{uuid}\|null | AIUC-1 E004 |
| prompt_approved_at | ISO8601\|null | AIUC-1 E004 |
| regulatory_context | string[]\|null | AIUC-1 E012 — applicable frameworks per workflow |

---

## 14. UNSTRUCTURED CHECK HANDLING (NEW — v7)

### 14.1 Archetype System

14 named archetypes + custom_check (15th, catch-all) + process_only (opt-out mode).

**Confidence scoring (gated on P15-A primust discover CLI):**

| Signal | Weight | Source |
|---|---|---|
| model_id | 40 | model_id in p.register_check() or p.record() |
| import | 30 | Static import analysis |
| check_id | 20 | check_id string pattern matching |
| config | 10 | Config keys, env vars near call site |

| Tier | Score | Behavior |
|---|---|---|
| HIGH | ≥80 | Auto-accept named archetype. VPEC issued immediately. archetype_verified: true. |
| MEDIUM | 50–79 | Shortlist to developer. Default = highest-scored if no selection within 30s. |
| LOW | <50 | custom_check assigned. archetype_candidates[] populated for officer review. |

### 14.2 custom_check VPEC Schema Fields

```json
{
  "archetype": "custom_check",
  "archetype_confidence": 0.38,
  "archetype_inference": "low_confidence",
  "archetype_candidates": [
    { "archetype": "scope_enforcement", "score": 0.42 },
    { "archetype": "output_validation", "score": 0.31 },
    { "archetype": "policy_enforcement", "score": 0.18 }
  ],
  "archetype_verified": false,
  "compliance_mapping_status": "pending_review"
}
```

> ⚠ custom_check is NOT a failure state. A VPEC with archetype: custom_check is a valid, billable credential. It proves the check ran.

### 14.3 process_only VPEC Schema Fields

```json
{
  "archetype": "process_only",
  "archetype_inference": "explicit_declaration",
  "compliance_mapping_status": "opted_out",
  "framework_controls": [],
  "provable_surface_contribution": false
}
```

**CRITICAL:** archetype: process_only cannot be set globally via p.init(). Must be declared per check. Prevents accidental compliance opt-out.

**Retroactive mapping boundary:** custom_check → retroactive officer mapping applies (mapping was pending). process_only → NO retroactive reclassification (credential was deliberately issued without compliance claim).

### 14.4 Compliance Officer Mapping Queue

custom_check VPECs appear in Compliance Officer mapping queue (L3 dashboard layer). Officer sees: check_id, archetype_candidates with scores, stage type, VPEC count. Mapping action: assign to named archetype, create custom, or mark process_only.

Once mapped: all historical VPECs with that check_id retroactively mapped (within retention window). provable_surface recalculates.

### 14.5 Check Candidate Detection (P15-A dependent)

primust scan runs static analysis (Process 2). check_candidates are advisory signals, NOT gap types.

check_candidate schema fields: candidate_id (deterministic SHA-256), file, line_start, line_end, pattern_category, pattern_match, suggested_archetypes[], confidence, suggested_check_id, scaffold_available, dismissed, dismissed_reason.

`primust scaffold <candidate_id>` generates ready-to-integrate instrumentation template.

**CRITICAL:** Do NOT conflate check_candidate (uninstrumented code advisory) with control_not_covered (framework control gap).

---

## 15. GAP TAXONOMY — 47 TYPES (CANONICAL)

### Core (22)

| Gap Type | Severity | Detection Point |
|---|---|---|
| check_not_executed | High | Run close |
| enforcement_override | Critical | p.record() |
| engine_error | High | p.record() |
| check_degraded | Medium | p.record() |
| external_boundary_traversal | High | p.record_delegation() |
| lineage_token_missing | High | p.resume_from_lineage() |
| admission_gate_override | Critical | Admission gate |
| check_timing_suspect | Medium | p.record() |
| reviewer_credential_invalid | Critical | Witnessed record |
| witnessed_display_missing | High | Witnessed record |
| witnessed_rationale_missing | High | Witnessed record |
| witnessed_timestamp_invalid | High | Witnessed record |
| deterministic_consistency_violation | Critical | Cross-run analysis |
| skip_rationale_missing | High | p.record() |
| policy_config_drift | Medium | Pipeline open |
| proof_level_floor_breach | Critical | VPEC issuance |
| zkml_proof_pending_timeout | Medium | Modal webhook |
| zkml_proof_failed | High | Modal webhook |
| system_error | High | Any checkpoint |
| sla_breach | Medium | primust-verify / sla_policy |
| explanation_missing | Medium | p.record() — fires when compliance_requirements.require_explanation_commitment set |
| bias_audit_missing | High | p.record() — fires when compliance_requirements.require_bias_audit set |

### System Availability (1)

| Gap Type | Severity | When Emitted | Notes |
|---|---|---|---|
| system_unavailable | High | Primust API unreachable — SDK queued locally, queue lost or TTL expired. | Distinct from system_error (Primust processing failure). Auto-records when queue expires. |

### Unstructured Check (1)

| Gap Type | Severity | When Emitted | Auto-Resolves |
|---|---|---|---|
| archetype_unmapped | Medium | custom_check VPEC exists for check_id and officer has not mapped it. One gap per unique unmapped check_id. | Yes — when officer completes mapping |

### Cross-Org Verification (7)

| Gap Type | Severity | Trigger |
|---|---|---|
| upstream_vpec_invalid_signature | Critical | Ed25519 verification fails |
| upstream_vpec_sandbox | High | Upstream environment: "sandbox" |
| upstream_vpec_key_revoked | High | Signing key revoked |
| upstream_vpec_insufficient_proof_level | High | proof_level_floor below minimum |
| upstream_vpec_missing_claim | Medium | Required claim absent from upstream VPEC |
| upstream_vpec_issuer_mismatch | Critical | expected_issuer_org_id does not match |
| upstream_vpec_missing | High | No VPEC delivered alongside upstream output |

### Connector-Specific (16)

Pattern: `{platform}_api_error` (High) = vendor API unreachable or 5xx. `{platform}_auth_failure` (Critical) = vendor API 401/403. Distinct from system_error and system_unavailable.

complyadvantage_api_error (High), complyadvantage_auth_failure (Critical), actimize_api_error (High), actimize_auth_failure (Critical), blaze_api_error (High), blaze_auth_failure (Critical), odm_api_error (High), odm_auth_failure (Critical), falcon_api_error (High), falcon_auth_failure (Critical), pega_api_error (High), pega_auth_failure (Critical), wolters_kluwer_api_error (High), wolters_kluwer_auth_failure (Critical), guidewire_api_error (High), guidewire_auth_failure (Critical)

> ⚠ check_candidate findings are NOT gap types. They are scan advisories. They do not appear in VPEC gap_records and do not affect provable_surface.
---

## 16. INFRASTRUCTURE TOPOLOGY

```
primust.com / app.primust.com / verify.primust.com → Vercel (Next.js 15)

api.primust.com → Fly.io (FastAPI, always-on)
  ├── US region → Neon Postgres DATABASE_URL_US (aws-us-east-1)
  ├── EU region → Neon Postgres DATABASE_URL_EU (aws-eu-central-1 Frankfurt)
  ├── GCP KMS → PRIMUST_KMS_KEY_US + PRIMUST_KMS_KEY_EU (Ed25519, HSM)
  └── Cloudflare R2 → R2_BUCKET_US + R2_BUCKET_EU

Modal (async, serverless)
  ├── zk-worker (Noir/nargo CPU proving)
  └── [Tier 2] EZKL GPU proving

docs.primust.com → Mintlify via CNAME
```

**Regional resolution:** org.region on every authenticated request routes to correct Neon shard and KMS key.

**Bootstrap API key deprecation: 2026-06-01. Hardcoded. No exceptions.**

---

*PRIMUST_TECH_SPEC_v8.0 · March 16, 2026 · Primust, Inc.*
*Supersedes TECH_SPEC v7 and all prior versions.*
*Canonical sources: DECISIONS_v13, ARCHITECTURE_v1, MASTER_v9*
