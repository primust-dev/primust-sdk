# Primust Schema Provisional Freeze — v3.0.0

**Date:** 2026-03-10
**Status:** Provisional-frozen
**Schema Version:** 3.0.0

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
- ProofLevel: mathematical, execution_zkml, execution, witnessed, attestation
- GapType: 16 values (check_not_executed through zkml_proof_failed)
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
- StageType: deterministic_rule, ml_model, zkml_model, statistical_test, custom_code, human_review
- EvaluationScope: per_run, per_action_unit, per_surface, per_window
- AggregationMethod: all_stages_must_pass, worst_case, threshold_vote, sequential_gate
- CheckResult: pass, fail, error, skipped, degraded, override, not_applicable, timed_out
- GapState: open, investigating, waived, remediated, resolved, escalated
- RunState: open, closed, partial, cancelled, auto_closed
- CommitmentType: input_commitment, metadata_commitment, foreign_event_commitment
- KeyBinding: software, hardware

## Critical Invariants (8)

1. **No banned field names** — agent_id, pipeline_id, tool_name, session_id, trace_id, reliance_mode, PGC, attestation (as a field name) are forbidden everywhere.
2. **human_review → witnessed** — human_review stage type must use witnessed proof level, NEVER attestation.
3. **manifest_hash captured** — Every CheckExecutionRecord must include manifest_hash at record time for drift detection.
4. **reviewer_credential required** — When proof_level_achieved = witnessed, reviewer_credential is mandatory.
5. **skip_rationale_hash required** — When check_result = not_applicable, skip_rationale_hash is mandatory.
6. **Append-only records** — CheckExecutionRecord is append-only after commit (no UPDATE).
7. **No permanent waivers** — Waiver expires_at is REQUIRED. Maximum 90 days from approved_at. Reason minimum 50 characters.
8. **Coverage sum = 100** — EvidencePack: coverage_verified_pct + coverage_pending_pct + coverage_ungoverned_pct must equal 100.

## Banned Field Names (8)

- `agent_id`
- `pipeline_id`
- `tool_name`
- `session_id`
- `trace_id`
- `reliance_mode`
- `PGC`
- `attestation` (as a field name)

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

Schema changes after 2026-03-10 require a version bump in schema_version and a migration.

## Amendment Process

Any change to a frozen schema requires:
1. Schema migration document with before/after diff
2. Semantic version bump (breaking = major)
3. All existing tests must continue to pass
4. New tests for the changed invariant
