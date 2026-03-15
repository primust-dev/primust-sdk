-- Primust Migration 007 — Sandbox API keys and organization tracking
-- Enables P24-F sign-up flow: new users get a sandbox key on first dashboard visit.
-- Apply to BOTH regions.

-- Add 'sandbox' to key_type — existing constraint only allows 'live' and 'test'
ALTER TABLE api_keys DROP CONSTRAINT IF EXISTS api_keys_key_type_check;
ALTER TABLE api_keys ADD CONSTRAINT api_keys_key_type_check
    CHECK (key_type IN ('live', 'test', 'sandbox'));

-- Track organizations
CREATE TABLE IF NOT EXISTS organizations (
    org_id          TEXT PRIMARY KEY,
    org_region      TEXT NOT NULL CHECK (org_region IN ('us', 'eu')),
    display_name    TEXT,
    clerk_org_id    TEXT UNIQUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by      TEXT
);

CREATE INDEX IF NOT EXISTS idx_organizations_clerk ON organizations (clerk_org_id) WHERE clerk_org_id IS NOT NULL;
