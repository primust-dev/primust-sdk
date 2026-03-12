-- Primust Migration 002 — API Key Registry
-- Supports hybrid auth: HMAC validates issuance, DB validates status/revocation/org-binding.
-- Apply to BOTH regions.

CREATE TABLE api_keys (
  key_hash     TEXT PRIMARY KEY,              -- SHA-256(raw_key), never store raw
  org_id       TEXT NOT NULL,
  status       TEXT NOT NULL CHECK (status IN ('active', 'revoked', 'expired')),
  key_type     TEXT NOT NULL CHECK (key_type IN ('live', 'test')),
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at   TIMESTAMPTZ,
  revoked_at   TIMESTAMPTZ
);

CREATE INDEX idx_api_keys_org_status ON api_keys(org_id, status);
