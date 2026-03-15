-- Migration 009: AIUC-1 prompt version fields on policy_snapshots
-- These fields already exist on check_manifests (migration 003).
-- Adding to policy_snapshots per TECH_SPEC §13.6 / DECISIONS §28.6.
-- check_manifests: records who approved the specific check version
-- policy_snapshots: records which prompt version was active for the run
-- Apply to BOTH regions.

ALTER TABLE policy_snapshots
  ADD COLUMN IF NOT EXISTS prompt_version_id TEXT,
  ADD COLUMN IF NOT EXISTS prompt_approved_by TEXT,
  ADD COLUMN IF NOT EXISTS prompt_approved_at TIMESTAMPTZ;
