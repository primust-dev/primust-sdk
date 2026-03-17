# Primust Schema Provisional Freeze — v5.0.0

**Date:** 2026-03-16
**Status:** Provisional-frozen
**Schema Version:** 5.0.0
**Previous Version:** 4.0.0 (2026-03-12)

---

## v4.0.0 → v5.0.0 Migration (Migration 012 — Schema Reconciliation)

### Breaking changes
- **VPEC field renames:** `proof_level` → `proof_level_floor`, `proof_distribution` → `provable_surface_breakdown`, `coverage_verified_pct` → `provable_surface` (float 0.0–1.0), `governance_gaps` → `gaps`
- **ProofLevelBreakdown:** fields changed from integer counts to float shares (must sum to provable_surface ±0.0001)
- **test_mode → environment:** `test_mode: boolean` replaced by `environment: "sandbox" | "production"`
- **API key prefix:** `pk_test_` banned from all docs/fixtures; canonical sandbox prefix is `pk_sb_`

### Additive changes
- **VPEC:** added `provable_surface_pending`, `provable_surface_ungoverned`, `provable_surface_basis`, `provable_surface_suppressed`
- **GapType:** expanded from 32 to 49 types: added `system_unavailable` + 16 connector-specific types (`{platform}_api_error`, `{platform}_auth_failure` for 8 connectors)

---

## v3.0.0 → v4.0.0 Migration (P4-D)

### Breaking changes
- **StageType renames:** `byollm` → `llm_api`, `human_review` → `witnessed`
- **ProofLevel rename:** `execution_zkml` → `verifiable_inference`
- **GapType:** removed `api_unavailable` (codebase drift, not in canonical spec)
- **Waiver:** `risk_treatment` is now REQUIRED (no default for new records)

### Additive changes
- **GapType:** added `explanation_missing` (Medium), `bias_audit_missing` (High) → 18 total (spec says 17 but lists 16 existing + 2 new)
- **CheckExecutionRecord:** added `actor_id`, `explanation_commitment`, `bias_audit` (all nullable)
- **Gap:** added `incident_report_ref` (nullable)
- **Waiver:** added `risk_treatment` (required: accept | mitigate | transfer | avoid)
- **PolicyPack:** added `compliance_requirements`, `sla_policy` (both nullable)
- **PolicySnapshot:** added `retention_policy`, `risk_classification`, `regulatory_context` (all nullable)
- **CheckManifest:** added `prompt_version_id`, `prompt_approved_by`, `prompt_approved_at` (all nullable)

---

## Frozen Objects (10)

| # | Object | Primary Key | Signed |
|---|--------|-------------|--------|
| 1 | ObservationSurface | surface_id | No |
| 2 | CheckManifest | manifest_id (SHA-256 content hash) | Yes |
| 3 | PolicyPack | policy_pack_id | Yes |
| 4 | PolicySnapshot | snapshot_id | No |
| 5 | ProcessRun | run_id | No |
| 6 | ActionUnit | action_unit_id | No |
| 7 | CheckExecutionRecord | record_id | No (append-only) |
| 8 | Gap | gap_id | No |
| 9 | Waiver | waiver_id | Yes |
| 10 | EvidencePack | pack_id | Yes |

## Frozen Enums

**From artifact-core:**
- ProofLevel: mathematical, verifiable_inference, execution, witnessed, attestation
- GapType: 49 values (check_not_executed, enforcement_override, engine_error, check_degraded, external_boundary_traversal, lineage_token_missing, admission_gate_override, check_timing_suspect, reviewer_credential_invalid, witnessed_display_missing, witnessed_rationale_missing, witnessed_timestamp_invalid, deterministic_consistency_violation, skip_rationale_missing, policy_config_drift, proof_level_floor_breach, zkml_proof_pending_timeout, zkml_proof_failed, system_error, sla_breach, explanation_missing, bias_audit_missing, archetype_unmapped, upstream_vpec_invalid_signature, upstream_vpec_sandbox, upstream_vpec_key_revoked, upstream_vpec_insufficient_proof_level, upstream_vpec_missing_claim, upstream_vpec_issuer_mismatch, upstream_vpec_missing, system_unavailable, complyadvantage_api_error, complyadvantage_auth_failure, actimize_api_error, actimize_auth_failure, blaze_api_error, blaze_auth_failure, odm_api_error, odm_auth_failure, falcon_api_error, falcon_auth_failure, pega_api_error, pega_auth_failure, wolters_kluwer_api_error, wolters_kluwer_auth_failure, guidewire_api_error, guidewire_auth_failure)
- GapSeverity: Critical, High, Medium, Low, Informational
- SurfaceType: in_process_adapter, network_proxy, log_collector, api_gateway, sidecar
- ObservationMode: pre_action, post_action, streaming, batch
- ScopeType: full_workflow, partial_workflow, single_step, external_boundary
- CommitmentAlgorithm: poseidon2, sha256
- PolicyBasis: P1_self_declared, P2_auditor_reviewed, P3_regulator_mandated
- TsaProvider: digicert_us, digicert_eu, none

**From runtime-core:**
- ManifestDomain: ai_agent, cicd, financial, pharma, generic
- ImplementationType: ml_model, rule, threshold, approval_chain, zkml_model, custom
- StageType: deterministic_rule, ml_model, zkml_model, statistical_test, custom_code, witnessed, policy_engine, llm_api, open_source_ml, hardware_attested
- EvaluationScope: per_run, per_action_unit, per_surface, per_window
- AggregationMethod: all_stages_must_pass, worst_case, threshold_vote, sequential_gate
- CheckResult: pass, fail, error, skipped, degraded, override, not_applicable, timed_out
- GapState: open, investigating, waived, remediated, resolved, escalated
- RunState: open, closed, partial, cancelled, auto_closed
- CommitmentType: input_commitment, metadata_commitment, foreign_event_commitment
- KeyBinding: software, hardware

## Critical Invariants (10)

1. **No banned field names** — agent_id, pipeline_id, tool_name, session_id, trace_id, reliance_mode, PGC, attestation (as a field name) are forbidden everywhere.
2. **witnessed stage → witnessed proof** — witnessed stage type must use witnessed proof level, NEVER attestation.
3. **manifest_hash captured** — Every CheckExecutionRecord must include manifest_hash at record time for drift detection.
4. **reviewer_credential required** — When proof_level_achieved = witnessed, reviewer_credential is mandatory.
5. **skip_rationale_hash required** — When check_result = not_applicable, skip_rationale_hash is mandatory.
6. **Append-only records** — CheckExecutionRecord is append-only after commit (no UPDATE).
7. **No permanent waivers** — Waiver expires_at is REQUIRED. Maximum 90 days from approved_at. Reason minimum 50 characters.
8. **Provable surface sum** — PS-INV-1: provable_surface_breakdown sub-fields must sum to provable_surface ±0.0001. EvidencePack: coverage_verified_pct + coverage_pending_pct + coverage_ungoverned_pct must equal 100.
9. **risk_treatment required** — Waiver risk_treatment is REQUIRED, no default. Must be: accept, mitigate, transfer, or avoid.
10. **Banned stage type terms** — `byollm`, `human_review`, `execution_zkml` must not appear anywhere in codebase. Build must fail if found.

## Banned Field Names (8)

- `agent_id`
- `pipeline_id`
- `tool_name`
- `session_id`
- `trace_id`
- `reliance_mode`
- `PGC`
- `attestation` (as a field name)

## Banned Field Names — Migration 012 (6)

- `pk_test_xxx` (replaced by `pk_sb_xxx`)
- `proof_level` as VPEC-level field (replaced by `proof_level_floor`)
- `proof_distribution` (replaced by `provable_surface_breakdown`)
- `proof_level_breakdown` (replaced by `provable_surface_breakdown`)
- `coverage_verified_pct` (replaced by `provable_surface`)
- `governance_gaps` (replaced by `gaps`)

## Banned Stage Type / Proof Level Terms (3)

- `byollm` (replaced by `llm_api`)
- `human_review` (replaced by `witnessed`)
- `execution_zkml` (replaced by `verifiable_inference`)

## JSON Schema Files

All schemas located at `schemas/json/`:

- artifact.schema.json (VPEC Artifact)
- observation_surface.schema.json
- check_manifest.schema.json
- policy_pack.schema.json
- policy_snapshot.schema.json
- process_run.schema.json
- action_unit.schema.json
- check_execution_record.schema.json
- gap.schema.json
- waiver.schema.json
- evidence_pack.schema.json

## Implementation Coverage

| Package | Language | Tests |
|---------|----------|-------|
| @primust/artifact-core | TypeScript | 56 |
| @primust/runtime-core | TypeScript | 27 |
| @primust/verifier | TypeScript | 19 |
| @primust/registry | TypeScript | 22 |
| primust-artifact-core | Python | 57+ |
| primust-runtime-core | Python | 28 |
| primust-verify | Python | 19 |

## Freeze Condition

Schema changes after 2026-03-16 require a version bump in schema_version and a migration.

## Amendment Process

Any change to a frozen schema requires:
1. Schema migration document with before/after diff
2. Semantic version bump (breaking = major)
3. All existing tests must continue to pass
4. New tests for the changed invariant
