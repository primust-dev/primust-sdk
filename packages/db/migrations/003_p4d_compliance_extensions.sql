-- Primust Postgres Schema — P4-D Compliance Extensions
-- Schema version: 3.0.0 → 4.0.0
-- Dual-region: DATABASE_URL_US (us-east-1) + DATABASE_URL_EU (eu-central-1)
-- Apply to BOTH regions. Never use a single DATABASE_URL.
--
-- Breaking changes:
--   proof_level enum: execution_zkml → verifiable_inference
--   Waiver: risk_treatment REQUIRED (backfill existing as 'accept')
--   GapType: api_unavailable removed, explanation_missing + bias_audit_missing added
--
-- Additive changes:
--   CheckExecutionRecord: actor_id, explanation_commitment, bias_audit
--   Gap: incident_report_ref
--   PolicyPack: compliance_requirements, sla_policy
--   PolicySnapshot: retention_policy, risk_classification, regulatory_context
--   CheckManifest: prompt_version_id, prompt_approved_by, prompt_approved_at
--   Workflow registrations: retention_policy, risk_classification, regulatory_context

-- ── 1. Rename proof_level enum value: execution_zkml → verifiable_inference ──

ALTER TYPE proof_level RENAME VALUE 'execution_zkml' TO 'verifiable_inference';

-- ── 2. CheckExecutionRecord — three new columns ──

ALTER TABLE check_execution_records
  ADD COLUMN actor_id TEXT,
  ADD COLUMN explanation_commitment TEXT,
  ADD COLUMN bias_audit JSONB;

-- ── 3. Gap — one new column ──

ALTER TABLE gaps
  ADD COLUMN incident_report_ref TEXT;

-- ── 4. Waiver — risk_treatment (required, backfill existing as 'accept') ──

ALTER TABLE waivers
  ADD COLUMN risk_treatment TEXT NOT NULL DEFAULT 'accept';

-- Remove default after backfill — new inserts must provide explicitly
ALTER TABLE waivers
  ALTER COLUMN risk_treatment DROP DEFAULT;

-- ── 5. PolicyPack — two new JSONB columns ──

ALTER TABLE policy_packs
  ADD COLUMN compliance_requirements JSONB,
  ADD COLUMN sla_policy JSONB;

-- ── 6. PolicySnapshot — three new columns ──

ALTER TABLE policy_snapshots
  ADD COLUMN retention_policy TEXT,
  ADD COLUMN risk_classification TEXT,
  ADD COLUMN regulatory_context JSONB;

-- ── 7. CheckManifest — three new columns for change approval ──

ALTER TABLE check_manifests
  ADD COLUMN prompt_version_id TEXT,
  ADD COLUMN prompt_approved_by TEXT,
  ADD COLUMN prompt_approved_at TIMESTAMPTZ;

-- ── 8. Workflow registrations — pipeline init fields ──
-- Add retention_policy and risk_classification to process_runs
-- (workflow_registrations table does not exist yet — these fields
--  flow through process_runs into policy_snapshots)

ALTER TABLE process_runs
  ADD COLUMN retention_policy TEXT,
  ADD COLUMN risk_classification TEXT,
  ADD COLUMN regulatory_context JSONB;

-- ── 9. VPEC table — update default schema_version ──

ALTER TABLE vpecs
  ALTER COLUMN schema_version SET DEFAULT '4.0.0';
