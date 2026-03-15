-- Rollback 009: Remove AIUC-1 prompt version fields from policy_snapshots

ALTER TABLE policy_snapshots
  DROP COLUMN IF EXISTS prompt_version_id,
  DROP COLUMN IF EXISTS prompt_approved_by,
  DROP COLUMN IF EXISTS prompt_approved_at;
