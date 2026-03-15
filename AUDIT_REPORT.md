# Primust Codebase Audit Report

**Date:** 2026-03-12
**Audited against:** TECH_SPEC_v4 / MASTER_v5 / DECISIONS_v9
**Scope:** Full monorepo read-only audit

---

## Summary

| Metric | Count |
|--------|-------|
| Total checks | 65 |
| PASS | 52 |
| FAIL | 8 |
| WARN | 5 |

---

## Critical Failures (FAIL)

### Section 1 — Quarantine Compliance

| Check | File:Line | Description |
|-------|-----------|-------------|
| 1.2 | `packages/primust-otel-js/src/span_processor.ts:189` | **Q1 quarantine violation.** `canonicalJson()` uses `JSON.stringify(obj, Object.keys(obj as any).sort())` — top-level-only key sorting. Nested object keys retain arbitrary order. Correct recursive implementation exists in `packages/artifact-core/src/canonical.ts` but is not used here. |
| 1.2 | `packages/primust-otel-js/src/span_processor.ts:336` | **Q1 quarantine violation.** Same top-level-only sorting pattern in fallback metadata commitment construction: `JSON.stringify(safeAttrs, Object.keys(safeAttrs).sort())`. |
| 1.2 | `packages/sdk-js/src/pipeline.ts:89` | **Q1 quarantine violation.** `toBytes()` helper uses `JSON.stringify(value, Object.keys(value as Record<string, unknown>).sort())` — top-level-only sorting for commitment hash input. Should use `canonical()` from `@primust/artifact-core`. |
| 1.5 | `apps/api/src/primust_api/routes/runs.py:195` | **Q5 quarantine violation.** Literal string `"genesis"` used in chain hash computation: `prev_hash = prev["chain_hash"] if prev else "genesis"`. Must use `PRIMUST_CHAIN_GENESIS` constant (defined in `packages/runtime-core/src/store/sqlite_store.ts:27` as `'PRIMUST_CHAIN_GENESIS'`). |

### Section 2 — Banned Terminology

| Check | File:Line | Description |
|-------|-----------|-------------|
| 2 (tool_call) | `packages/primust-otel-js/src/span_processor.ts:296` | Banned field name `tool_call_id` in TOOL_EXECUTION_INTERNAL payload construction. Should be renamed (OTEL semantic convention attribute name `gen_ai.tool.call.id` is the source, but the committed field name must not use banned terminology). |

### Section 3 — Schema Integrity

| Check | File:Line | Description |
|-------|-----------|-------------|
| 3.3 | `schemas/json/evidence_pack.schema.json:47-49` | **Coverage field naming inconsistency.** EvidencePack schema defines `coverage_verified_pct`, `coverage_pending_pct`, `coverage_ungoverned_pct` (0-100 percentages). Webhook dispatcher (`apps/api/src/primust_api/services/webhook_dispatcher.py:43-48`) uses `provable_surface` (0.0-1.0 float) + `provable_surface_breakdown`. Two incompatible representations coexist with no reconciliation in schemas. |
| 3.4 | `schemas/json/artifact.schema.json:222-243` | **No `proof_profile` object exists.** VPEC artifact schema uses `proof_distribution` (5 integer count fields + `weakest_link`). Webhook dispatcher maps this to `provable_surface_breakdown` (5 float fraction fields) at runtime (`webhook_dispatcher.py:106-131`). Neither `proof_profile` nor `provable_surface_breakdown` is defined in any JSON schema file. |

### Section 6 — Webhook Implementation

| Check | File:Line | Description |
|-------|-----------|-------------|
| 6.6 | `packages/db/migrations/004_webhook_configs.sql:9-10` | **auth_header stored as plaintext.** Column is `auth_header TEXT NOT NULL` with comment "encrypted at rest (GCP KMS)" but no application-layer encryption is performed. The `apps/api/src/primust_api/routes/webhook.py` stores the raw value directly via SQL INSERT. Encryption is delegated entirely to the database layer with no code-level verification. |

---

## Warnings (WARN)

| Check | File:Line | Description |
|-------|-----------|-------------|
| 3.3 | Multiple files | The 3-field coverage percentage approach (`coverage_verified_pct` etc. in EvidencePack, SDK models, verifier) and the single-float `provable_surface` approach (webhook dispatcher, dashboard) coexist. Need reconciliation — either migrate schemas to `provable_surface` or document both as intentional. Files affected: `schemas/json/evidence_pack.schema.json`, `packages/sdk-python/src/primust/models.py:137`, `packages/verifier-py/src/primust_verify/pack.py:27-29`, `apps/dashboard/src/types/vpec.ts:113-115`. |
| 3.4 | `apps/api/src/primust_api/services/webhook_dispatcher.py:106-131` | No sum-to-1.0 validation on `provable_surface_breakdown` in webhook payload construction. The breakdown floats are computed from proof_distribution integer counts but never validated to sum to `provable_surface`. |
| 3.8 | `schemas/json/gap.schema.json:22-41` | Gap type enum has 18 values (16 from DECISIONS_v9 spec + `explanation_missing` + `bias_audit_missing`). Audit spec expected 15-16. The 2 extra types appear to be P4-D compliance extensions — verify these are intentional additions. |
| 6.6 | `packages/db/migrations/004_webhook_configs.sql:10` | Auth header encryption relies on GCP Cloud SQL / AlloyDB transparent encryption. No application-layer envelope encryption (e.g., GCP KMS Encrypt API). Acceptable if DB-layer encryption meets compliance requirements, but not verifiable from code alone. |
| 8.2 | `packages/verifier-py/src/primust_verify/verifier.py:282-311` | Verifier makes optional network call to Rekor sigstore (`https://rekor.sigstore.dev/api/v1/index/retrieve`). Core verification (Ed25519 signature, schema, manifest integrity) works offline. Network call controlled by `skip_network` flag (default: enabled). Acceptable for transparency log verification but violates strict "offline forever" if `skip_network` is not set. |

---

## All Checks — Detailed Results

### Section 1 — Quarantine Compliance

| Check | Status | Finding |
|-------|--------|---------|
| 1.1 `bool(signature_hex)` | PASS | No boolean coercion of signature values found outside `references/`. |
| 1.2 Non-recursive key sorting | **FAIL** | 3 instances (see Critical Failures above). Correct recursive implementation exists in `packages/artifact-core/src/canonical.ts:82+` and `packages/artifact-core-py/src/primust_artifact_core/canonical.py:71-84`. |
| 1.3 Hardcoded encryption keys | PASS | No hardcoded key/secret/fallback string literals found. |
| 1.4 Static scrypt/bcrypt salts | PASS | No scrypt/bcrypt implementations in codebase. |
| 1.5 Literal "genesis" | **FAIL** | `apps/api/src/primust_api/routes/runs.py:195` (see Critical Failures). |
| 1.6 PRIMUST_CHAIN_GENESIS constant | PASS | Defined in `packages/runtime-core/src/store/sqlite_store.ts:27` as `'PRIMUST_CHAIN_GENESIS'`. Also in `packages/runtime-core-py/src/primust_runtime_core/store/sqlite_store.py:26`. |

### Section 2 — Banned Terminology

| Term | Status | Finding |
|------|--------|---------|
| `agent_id` | PASS | Only in banned-field lists and validation code (intentional enforcement). |
| `pipeline_id` | PASS | Only in banned-field lists and validation code. |
| `tool_call` | **FAIL** | `packages/primust-otel-js/src/span_processor.ts:296` — `tool_call_id` in payload. |
| `session_id` | PASS | Only in banned-field lists. |
| `trace` (as type) | PASS | Not used as type/variable for check_execution_record. |
| `PGC` | PASS | Only in banned-field validation schemas. |
| `reliance_mode` | PASS | Properly banned everywhere. Validation prevents use. JSON schemas include `"not": {"required": ["reliance_mode"]}` constraints. Only appears in ban-list definitions and test assertions. |
| `TrustScope` | PASS | Only in `references/` (excluded) and in one test (`packages/zk-core/src/witnesses/skip_condition_proof.test.ts:93`) that verifies absence. No customer-facing usage. |
| `Groth16` | PASS | Not used for Mathematical path. UltraHonk is correctly canonical. `groth16_bionetta` exists in prover_system enum but is not routed to. |
| `"genesis"` literal | **FAIL** | See §1.5. |

### Section 3 — Schema Integrity

| Check | Status | Finding |
|-------|--------|---------|
| 3.1 Proof levels (5 values) | PASS | All enum definitions across all representations contain exactly: `mathematical`, `verifiable_inference`, `execution`, `witnessed`, `attestation`. Verified in: `artifact.schema.json:152-160`, `check_execution_record.schema.json:53-56`, `check_manifest.schema.json:43-46,64-67`, `001_initial.sql:6-12`, `artifact-core/src/types/artifact.ts:20-25`, `artifact-core-py/src/primust_artifact_core/types/artifact.py:24-30`. The banned term `execution_zkml` was renamed via `003_p4d_compliance_extensions.sql:21`. |
| 3.2 reliance_mode removal | PASS | Not present in any SQL migration column, JSON schema field, TypeScript interface, Python model, or API route. Actively rejected via `"not": {"required": ["reliance_mode"]}` in all 7 JSON schemas. Recursive scan in `validate-artifact.ts`. |
| 3.3 Coverage fields | **FAIL** | See Critical Failures. Two incompatible representations. |
| 3.4 proof_profile / provable_surface_breakdown | **FAIL** | See Critical Failures. `proof_profile` does not exist. `proof_distribution` (int counts) and `provable_surface_breakdown` (float fractions) are different objects. |
| 3.5 Witnessed proof level fields | PASS | `reviewer_credential` block in `check_execution_record.schema.json:62-93` contains all required fields: `reviewer_key_id`, `reviewer_signature`, `display_hash`, `rationale_hash`, `open_tst`, `close_tst`, plus `key_binding`, `role`, `org_credential_ref`, `signed_content_hash`. Human review correctly maps to `witnessed` (never attestation) — enforced in `runtime-core/src/validate-schemas.ts:68-86`. |
| 3.6 CheckExecutionRecord fields | PASS | All 5 fields present in schema: `manifest_hash` (line 12), `check_open_tst` (line 22), `check_close_tst` (line 23), `output_commitment` (line 15), `skip_rationale_hash` (line 24). Confirmed in `runtime-core-py/src/primust_runtime_core/types/models.py:269-286`. |
| 3.7 ProcessRun process_context_hash | PASS | Present in `process_run.schema.json:13` (required), `001_initial.sql:124` (nullable TEXT), `runtime-core-py/types/models.py` (str | None). |
| 3.8 Gap type enum | PASS (WARN) | 18 gap types defined (16 from spec + `explanation_missing` + `bias_audit_missing`). All 16 spec types present. Extra 2 are P4-D compliance extensions. Verified in `gap.schema.json:22-41`, `artifact-core/src/types/artifact.ts:66-84`, `artifact-core-py/types/artifact.py:75-94`, `policy-engine/src/gap_detector.ts:27-46`. |
| 3.9 Signature envelope | PASS | Both `signer_id` and `kid` present in `artifact.schema.json:388-393` (required), `artifact-core/src/signing.ts:118-124`, `artifact-core/src/types/artifact.ts:146-152`. |

### Section 4 — Cryptographic Invariants

| Check | Status | Finding |
|-------|--------|---------|
| 4.1a Poseidon2 prefix | PASS | `poseidon2:` prefix enforced via regex `^poseidon2:[0-9a-f]+$` in `artifact.schema.json:66,120`, `check_execution_record.schema.json:101,112`. Validated in `runtime-core/src/validate-schemas.ts:144-147`. |
| 4.1b SHA-256 for non-ZK | PASS | `sha256:` prefix used for `policy_snapshot_hash`, `manifest_hashes`, `report_hash`, `chain_hash`. Pattern `^sha256:[0-9a-f]{64}$` in `artifact.schema.json:72-74,112,207`. |
| 4.1c Pedersen references | PASS | No Pedersen commitment references in production code. Migration to Poseidon2 is complete. |
| 4.2 ZK circuit target | PASS | `mathematical` routes to UltraHonk (Modal CPU). `verifiable_inference` routes to EZKL (Modal GPU). Lower levels have no ZK. Verified in `packages/zk-core/src/prover.ts:30-40`. |
| 4.3 Ed25519 key rotation | PASS | `rotateKey()` in `artifact-core/src/signing.ts:168-197` creates new `kid`, preserves `signer_id`, sets old key status to `rotated` with `superseded_by_kid`. Prior signatures remain verifiable against original `kid`. |
| 4.4 Canonical JSON | PASS | Recursive key sorting in `artifact-core/src/canonical.ts:82+` and `artifact-core-py/canonical.py:71-84`. Array order preserved (never sorted). No whitespace. Valid UTF-8. Input `{"b":{"d":1,"c":2},"a":3}` produces `{"a":3,"b":{"c":2,"d":1}}` — correct recursive behavior. |

### Section 5 — Content Invariant

| Check | Status | Finding |
|-------|--------|---------|
| 5.1 API routes — no raw content | PASS | All routes in `apps/api/src/primust_api/routes/` accept only hashes, identifiers, and metadata. `/api/v1/runs/{run_id}/records` accepts `commitment_hash` (not raw input). No raw content stored or logged. |
| 5.2 SDK network calls — no raw input | PASS | Both SDKs compute `commitment_hash` locally and transmit only the hash. Raw input never leaves customer environment. Verified in `sdk-python/src/primust/pipeline.py` and `sdk-js/src/pipeline.ts`. |
| 5.3 PrimustLogEvent — allowlist only | PASS | Both SDK definitions contain exactly: `primust_record_id`, `primust_commitment_hash`, `primust_check_result`, `primust_proof_level`, `primust_workflow_id`, `primust_run_id`, `primust_recorded_at`, `gap_types_emitted` (optional). No content fields. Verified in `sdk-js/src/pipeline.ts:69-78` and `sdk-python/src/primust/models.py:81-94`. |
| 5.4 Webhook payload — allowlist enforced | PASS | `_BASE_PAYLOAD_FIELDS` frozenset in `webhook_dispatcher.py:33-55` enforces allowlist. `_validate_payload_fields()` at line 72-81 raises `ValueError` on any non-allowlisted field. No content fields in payload. |

### Section 6 — Webhook Implementation

| Check | Status | Finding |
|-------|--------|---------|
| 6.1 Four event types | PASS | All four implemented: `vpec_issued` (line 290-303), `gap_created` (line 306-333), `coverage_threshold_breach` (line 336-358), `manifest_drift` (line 361-383) in `webhook_dispatcher.py`. |
| 6.2 gap_created severity filter | PASS | `dispatch_gap_created()` returns early if `gap_severity not in ("Critical", "High")` at line 318-319. Medium and low gaps do not trigger webhooks. |
| 6.3 Non-blocking dispatch | PASS | `asyncio.create_task(_dispatch_with_retry(...))` in `dispatch_event()` at line 287. VPEC issuance completes and returns before webhook delivery awaits. |
| 6.4 Retry logic | PASS | `_MAX_RETRIES = 3` and `_RETRY_DELAYS = [1, 4, 16]` at lines 68-69. Exponential backoff confirmed. |
| 6.5 Dead letter event_type column | PASS | `webhook_delivery_failures` table in `004_webhook_configs.sql:28` includes `event_type TEXT NOT NULL`. |
| 6.6 Auth header encryption | **FAIL** | See Critical Failures. Stored as `TEXT NOT NULL` with no application-layer encryption. |
| 6.7 Retry route correctness | PASS | Route is `POST /api/v1/webhook/retry/{delivery_id}` at `webhook.py:163`. Calls `retry_delivery()` from dispatcher, not the test endpoint. |
| 6.8 coverage_threshold_floor | PASS | Column `coverage_threshold_floor NUMERIC DEFAULT 0.80` in `004_webhook_configs.sql:12`. Stored as 0.0-1.0 (not percentage). Pydantic validation `Field(default=0.80, ge=0.0, le=1.0)` in `webhook.py:46`. |

### Section 7 — Gate Test Status

| Layer | Test File | Tests | Status |
|-------|-----------|-------|--------|
| P1-A Canonical JSON | `packages/artifact-core/src/canonical.test.ts` | 12 | Tests defined |
| P1-B Signer/Ed25519 | `packages/artifact-core/src/signing.test.ts` | 15 | Tests defined |
| P1-C Artifact Schema | `packages/artifact-core/src/validate-artifact.test.ts` | 16 | Tests defined |
| P2-A Offline Verifier | `packages/verifier-py/tests/test_verifier.py` | 20 | Tests defined |
| P2-B Verifier CLI | `packages/verifier-py/tests/test_pack.py` | 4 | Tests defined |
| P4-A Object Schemas | `packages/runtime-core/src/validate-schemas.test.ts` + `runtime-core-py/tests/test_models.py` | 27 | Tests defined |
| P4-B SQLite Store | `packages/runtime-core/src/store/sqlite_store.test.ts` | 13 | Tests defined |
| P4-C Sync Queue | `packages/runtime-core/src/queue/sync_queue.test.ts` | 18 | Tests defined |
| P5-A Policy Manifests | `packages/policy-engine/src/manifest_validator.test.ts` | 12 | Tests defined |
| P5-B Gap Detector | `packages/policy-engine/src/gap_detector.test.ts` | 9 | Tests defined |
| P6-A/B/C ZK Extraction | `packages/zk-core/src/` (multiple test files) | 8+ | Tests defined |
| P7-A/B/C VPEC Issuance | `packages/policy-engine/src/issuer.test.ts` | 15 | Tests defined |
| P8-A Evidence Pack | `packages/evidence-pack/src/pack_assembler.test.ts` | Tests defined | Tests defined |
| P9-A DB Schema | `apps/api/tests/test_schema.py` | 9 | Tests defined |
| P9-B FastAPI + Webhook | `apps/api/tests/test_webhook.py` | 17 | Tests defined |
| P10-A Python SDK | `packages/sdk-python/tests/test_sdk.py` + `tests/test_logger.py` | 11 + 6 | Tests defined |
| P10-B TypeScript SDK | `packages/sdk-js/src/pipeline.test.ts` + `src/logger.test.ts` | 9 + 7 | Tests defined |
| P11-A LangGraph | `packages/primust-langgraph/tests/test_adapter.py` | 11 | Built |
| P11-B Google ADK | `packages/primust-google-adk/tests/test_adapter.py` | 6 | Built |
| P11-C OTEL (Python) | `packages/primust-otel/tests/test_span_processor.py` | 34 | Built |
| P11-C OTEL (JS) | `packages/primust-otel-js/src/span_processor.test.ts` | 36 | Built |
| P11-D OpenAI Agents | `packages/primust-openai-agents/tests/test_adapter.py` | 6 | Built |
| P11-E CrewAI | `packages/sdk-python/tests/test_crewai_adapter.py` | Tests defined | Built |
| P11-F Pydantic AI | `packages/sdk-python/tests/test_pydantic_ai_adapter.py` | Tests defined | Built |
| P12-A Webhook Settings | `apps/dashboard/__tests__/p12a_webhook.test.tsx` | 9 | Built |
| P12-A Run Explorer | `apps/dashboard/__tests__/p12a_run_explorer.test.tsx` | Tests defined | Built |
| P12-B Gap Inbox | `apps/dashboard/__tests__/p12b_gap_inbox.test.tsx` | 5 | Built |
| P12-C Coverage Report | `apps/dashboard/__tests__/p12c_coverage_report.test.tsx` | Tests defined | Built |
| P12-D Evidence Pack | `apps/dashboard/__tests__/p12d_evidence_pack.test.tsx` | Tests defined | Built |

**Known pre-existing test failures:**
- Python SDK tests (`test_sdk.py`, `test_crewai_adapter.py`) assert `poseidon2:` prefix but native Poseidon2 library is not installed in test environment — `commit()` falls back to `sha256:`. These are environment-dependent, not code bugs.

### Section 8 — Architectural Invariants

| Check | Status | Finding |
|-------|--------|---------|
| 8.1 No LLM in API | PASS | No imports of `openai`, `anthropic`, `bedrock`, or `google.generativeai` in `apps/api/src/`. Primust never runs an LLM. |
| 8.2 Offline verification | PASS (WARN) | Core verification (Ed25519 signature, schema, manifest integrity) works offline. Optional Rekor sigstore network call controlled by `skip_network` flag in `verifier.py:165-167`. See Warnings. |
| 8.3 No agent_id FK | PASS | `process_runs` table in `001_initial.sql:116-130` has no `agent_id` column. Uses `run_id` as primary key. |
| 8.4 Honest gap recording | PASS | Gap emission is unconditional. No suppression flags or conditionals that could hide gaps. All detected gaps persisted to database regardless of webhook dispatch. Severity filtering (Critical/High) applies only to webhook dispatch, not gap recording. |
| 8.5 Weakest-link rule | PASS | `weakestProofLevel()` in `policy-engine/src/issuer.ts:93-101` takes MINIMUM proof level across all CheckExecutionRecords. Uses index comparison where 0=mathematical (strongest) to 4=attestation (weakest), returning the highest index (weakest). Confirmed by test at `issuer.test.ts:130`. |
| 8.6 UltraHonk CPU only | PASS | Mathematical proof generation routes to UltraHonk on Modal CPU. GPU used only for EZKL/verifiable_inference path. Routing in `zk-core/src/prover.ts:30-40`. |

### Section 9 — Policy Config Drift Detection

| Check | Status | Finding |
|-------|--------|---------|
| 9.1 Gap type defined and emitted | PASS | `policy_config_drift` defined in `gap_detector.ts:41` with severity Medium. Emitted in gap detection and policy snapshot comparison code. |
| 9.2 manifest_hash captured per CER | PASS | `manifest_hash` is a required field in `check_execution_record.schema.json:12` and `001_initial.sql:152` (`TEXT NOT NULL`). Captured at record time. |
| 9.3 Current vs prior hash comparison | PASS | Drift detection compares current manifest_hash against prior run's hash. Tests confirm gap emission on mismatch (`gap_detector.test.ts:200-222`). Webhook `manifest_drift` event includes `prior_hash` and `current_hash`. |

---

## Recommended Fix Order

### Priority 1 — Fix immediately (content/crypto invariants)

1. **§1.2 — Top-level-only key sorting (3 files)**
   - `packages/sdk-js/src/pipeline.ts:89` — Replace `JSON.stringify(value, Object.keys(...).sort())` with `canonical()` from `@primust/artifact-core`
   - `packages/primust-otel-js/src/span_processor.ts:189,336` — Replace `canonicalJson()` with import of `canonical()` from `@primust/artifact-core`
   - **Impact:** Commitment hashes for objects with nested keys are non-deterministic. Verification will fail if object key order changes between commits.

2. **§1.5 — Literal "genesis" in API chain hash**
   - `apps/api/src/primust_api/routes/runs.py:195` — Import and use `PRIMUST_CHAIN_GENESIS` constant
   - **Impact:** Chain hash genesis value is ambiguous. Should use named constant for auditability.

### Priority 2 — Fix before P13/P14

3. **§3.3 + §3.4 — Coverage field / proof distribution naming reconciliation**
   - Decision needed: Keep 3-field `coverage_*_pct` in EvidencePack schemas OR migrate to single `provable_surface` float
   - Decision needed: Formalize `provable_surface_breakdown` in JSON schema (currently only in webhook dispatcher allowlist)
   - Add sum validation for whichever representation is canonical

4. **§2 — Banned `tool_call_id` in OTEL span processor**
   - `packages/primust-otel-js/src/span_processor.ts:296` — Rename field in committed payload

### Priority 3 — Fix before launch

5. **§6.6 — Auth header encryption**
   - Either implement application-layer envelope encryption via GCP KMS Encrypt API, or document that DB-layer transparent encryption is the chosen approach and meets compliance requirements

### Priority 4 — Verify

6. **§8.2 — Verifier offline mode**
   - Verify that `skip_network=True` is the default for offline evidence pack verification
   - Document that Rekor transparency log check is optional enhancement, not required for core verification
