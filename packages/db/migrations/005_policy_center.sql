-- Migration 005: Policy Center tables
-- New tables for bundle management. Does NOT modify frozen v4.0.0 schema.

CREATE TABLE IF NOT EXISTS policy_bundles (
    bundle_id       TEXT PRIMARY KEY,
    org_id          TEXT,              -- NULL for built-in bundles
    name            TEXT NOT NULL,
    description     TEXT,
    version         TEXT NOT NULL,
    checks          JSONB NOT NULL DEFAULT '[]',
    framework_mappings JSONB NOT NULL DEFAULT '[]',
    estimated_provable_surface REAL,
    is_builtin      BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_policy_bundles_org ON policy_bundles (org_id) WHERE org_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_policy_bundles_builtin ON policy_bundles (is_builtin) WHERE is_builtin = TRUE;
