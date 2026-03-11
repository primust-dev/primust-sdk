-- Primust Postgres Schema — P9-A
-- Dual-region: DATABASE_URL_US (us-east-1) + DATABASE_URL_EU (eu-central-1)
-- Apply to BOTH regions. Never use a single DATABASE_URL.

-- Proof level enum (all 5 — used across multiple tables)
CREATE TYPE proof_level AS ENUM (
  'mathematical',
  'execution_zkml',
  'execution',
  'witnessed',
  'attestation'
);

-- Gap severity enum
CREATE TYPE gap_severity AS ENUM (
  'Critical',
  'High',
  'Medium',
  'Low',
  'Informational'
);

-- Gap state enum
CREATE TYPE gap_state AS ENUM (
  'open',
  'resolved',
  'waived'
);

-- Run state enum
CREATE TYPE run_state AS ENUM (
  'open',
  'closed',
  'expired'
);

-- Check result enum
CREATE TYPE check_result AS ENUM (
  'pass',
  'fail',
  'degraded',
  'not_applicable',
  'error',
  'override'
);

-- ── Table 1: observation_surfaces ──

CREATE TABLE observation_surfaces (
  surface_id         TEXT PRIMARY KEY,
  org_id             TEXT NOT NULL,
  environment        TEXT NOT NULL,
  surface_type       TEXT NOT NULL,
  surface_name       TEXT NOT NULL,
  surface_version    TEXT NOT NULL,
  observation_mode   TEXT NOT NULL,
  scope_type         TEXT NOT NULL,
  scope_description  TEXT NOT NULL,
  surface_coverage_statement TEXT NOT NULL,
  proof_ceiling      proof_level NOT NULL,
  gaps_detectable    JSONB NOT NULL DEFAULT '[]',
  gaps_not_detectable JSONB NOT NULL DEFAULT '[]',
  registered_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Table 2: check_manifests ──

CREATE TABLE check_manifests (
  manifest_id             TEXT PRIMARY KEY,
  manifest_hash           TEXT NOT NULL,
  domain                  TEXT NOT NULL,
  name                    TEXT NOT NULL,
  semantic_version        TEXT NOT NULL,
  check_type              TEXT NOT NULL,
  implementation_type     TEXT NOT NULL,
  supported_proof_level   proof_level NOT NULL,
  evaluation_scope        TEXT NOT NULL,
  evaluation_window_seconds INTEGER,
  stages                  JSONB NOT NULL DEFAULT '[]',
  aggregation_config      JSONB NOT NULL DEFAULT '{}',
  freshness_threshold_hours INTEGER,
  benchmark               JSONB,
  model_or_tool_hash      TEXT,
  publisher               TEXT NOT NULL,
  signer_id               TEXT NOT NULL,
  kid                     TEXT NOT NULL,
  signed_at               TIMESTAMPTZ NOT NULL,
  signature               JSONB NOT NULL
);

-- ── Table 3: policy_packs ──

CREATE TABLE policy_packs (
  policy_pack_id  TEXT PRIMARY KEY,
  org_id          TEXT NOT NULL,
  name            TEXT NOT NULL,
  version         TEXT NOT NULL,
  checks          JSONB NOT NULL DEFAULT '[]',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  signer_id       TEXT NOT NULL,
  kid             TEXT NOT NULL,
  signature       JSONB NOT NULL
);

-- ── Table 4: policy_snapshots ──

CREATE TABLE policy_snapshots (
  snapshot_id          TEXT PRIMARY KEY,
  policy_pack_id       TEXT NOT NULL REFERENCES policy_packs(policy_pack_id),
  policy_pack_version  TEXT NOT NULL,
  effective_checks     JSONB NOT NULL DEFAULT '[]',
  snapshotted_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  policy_basis         TEXT NOT NULL
);

-- ── Table 5: process_runs ──

CREATE TABLE process_runs (
  run_id                TEXT PRIMARY KEY,
  workflow_id           TEXT NOT NULL,
  org_id                TEXT NOT NULL,
  surface_id            TEXT NOT NULL REFERENCES observation_surfaces(surface_id),
  policy_snapshot_hash  TEXT NOT NULL,
  process_context_hash  TEXT,          -- nullable (P9-A test requirement)
  state                 run_state NOT NULL DEFAULT 'open',
  action_unit_count     INTEGER NOT NULL DEFAULT 0,
  started_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  closed_at             TIMESTAMPTZ,
  ttl_seconds           INTEGER NOT NULL DEFAULT 3600
);

CREATE INDEX idx_process_runs_org_state_started
  ON process_runs(org_id, state, started_at);

-- ── Table 6: action_units ──

CREATE TABLE action_units (
  action_unit_id  TEXT PRIMARY KEY,
  run_id          TEXT NOT NULL REFERENCES process_runs(run_id),
  surface_id      TEXT NOT NULL,
  action_type     TEXT NOT NULL,
  recorded_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Table 7: check_execution_records (APPEND-ONLY) ──

CREATE TABLE check_execution_records (
  record_id              TEXT PRIMARY KEY,
  run_id                 TEXT NOT NULL REFERENCES process_runs(run_id),
  action_unit_id         TEXT NOT NULL,
  manifest_id            TEXT NOT NULL,
  manifest_hash          TEXT NOT NULL,
  surface_id             TEXT NOT NULL,
  commitment_hash        TEXT NOT NULL,
  output_commitment      TEXT,
  commitment_algorithm   TEXT NOT NULL,
  commitment_type        TEXT NOT NULL,
  check_result           check_result NOT NULL,
  proof_level_achieved   proof_level NOT NULL,
  proof_pending          BOOLEAN NOT NULL DEFAULT FALSE,
  zkml_proof_pending     BOOLEAN NOT NULL DEFAULT FALSE,
  check_open_tst         TEXT,
  check_close_tst        TEXT,
  skip_rationale_hash    TEXT,
  reviewer_credential    JSONB,
  unverified_provenance  BOOLEAN NOT NULL DEFAULT FALSE,
  freshness_warning      BOOLEAN NOT NULL DEFAULT FALSE,
  chain_hash             TEXT NOT NULL,
  idempotency_key        TEXT NOT NULL UNIQUE,
  recorded_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_cer_run_manifest
  ON check_execution_records(run_id, manifest_id);

CREATE INDEX idx_cer_commitment_hash
  ON check_execution_records(commitment_hash);

-- Append-only: prevent UPDATE on check_execution_records
CREATE OR REPLACE FUNCTION prevent_cer_update()
RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION 'check_execution_records is append-only: UPDATE not allowed';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_cer_no_update
  BEFORE UPDATE ON check_execution_records
  FOR EACH ROW EXECUTE FUNCTION prevent_cer_update();

-- ── Table 8: gaps ──

CREATE TABLE gaps (
  gap_id       TEXT PRIMARY KEY,
  run_id       TEXT NOT NULL REFERENCES process_runs(run_id),
  gap_type     TEXT NOT NULL,
  severity     gap_severity NOT NULL,
  state        gap_state NOT NULL DEFAULT 'open',
  details      JSONB NOT NULL DEFAULT '{}',
  detected_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  resolved_at  TIMESTAMPTZ
);

CREATE INDEX idx_gaps_run_type_severity
  ON gaps(run_id, gap_type, severity);

-- ── Table 9: waivers ──

CREATE TABLE waivers (
  waiver_id            TEXT PRIMARY KEY,
  gap_id               TEXT NOT NULL REFERENCES gaps(gap_id),
  org_id               TEXT NOT NULL,
  requestor_user_id    TEXT NOT NULL,
  approver_user_id     TEXT NOT NULL,
  reason               TEXT NOT NULL,
  compensating_control TEXT,
  expires_at           TIMESTAMPTZ NOT NULL,  -- REQUIRED: no permanent waivers
  signature            JSONB NOT NULL,
  approved_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_waivers_gap_expires
  ON waivers(gap_id, expires_at);

-- ── Table 10: vpecs ──

CREATE TABLE vpecs (
  vpec_id                TEXT PRIMARY KEY,
  org_id                 TEXT NOT NULL,
  run_id                 TEXT NOT NULL REFERENCES process_runs(run_id),
  workflow_id            TEXT NOT NULL,
  schema_version         TEXT NOT NULL DEFAULT '3.0.0',
  process_context_hash   TEXT,
  partial                BOOLEAN NOT NULL DEFAULT FALSE,
  proof_level            proof_level NOT NULL,
  state                  TEXT NOT NULL DEFAULT 'signed',
  test_mode              BOOLEAN NOT NULL DEFAULT FALSE,
  issued_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  payload                JSONB NOT NULL
);

CREATE INDEX idx_vpecs_org_workflow_issued
  ON vpecs(org_id, workflow_id, issued_at);

-- ── Table 11: evidence_packs ──

CREATE TABLE evidence_packs (
  pack_id                 TEXT PRIMARY KEY,
  org_id                  TEXT NOT NULL,
  period_start            DATE NOT NULL,
  period_end              DATE NOT NULL,
  artifact_ids            JSONB NOT NULL DEFAULT '[]',
  merkle_root             TEXT NOT NULL,
  proof_distribution      JSONB NOT NULL DEFAULT '{}',
  coverage_verified_pct   NUMERIC(5,2) NOT NULL,
  coverage_pending_pct    NUMERIC(5,2) NOT NULL,
  coverage_ungoverned_pct NUMERIC(5,2) NOT NULL,
  observation_summary     JSONB NOT NULL DEFAULT '[]',
  gap_summary             JSONB NOT NULL DEFAULT '{}',
  report_hash             TEXT NOT NULL,
  signature               JSONB NOT NULL,
  generated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
