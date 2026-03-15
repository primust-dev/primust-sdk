-- Migration 006: BYOK (Bring Your Own Key) signing support
-- Enterprise tier: orgs can register their own Ed25519 signing keys

CREATE TABLE IF NOT EXISTS org_signing_keys (
    key_id              TEXT PRIMARY KEY,
    org_id              TEXT NOT NULL,
    kid                 TEXT NOT NULL UNIQUE,
    public_key_pem      TEXT NOT NULL,
    signing_endpoint_url TEXT,
    status              TEXT NOT NULL DEFAULT 'pending_verification'
                        CHECK (status IN ('pending_verification', 'active', 'revoked')),
    challenge           TEXT,
    challenge_expires_at TIMESTAMPTZ,
    verified_at         TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at          TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_org_signing_keys_org ON org_signing_keys (org_id);
CREATE INDEX IF NOT EXISTS idx_org_signing_keys_active ON org_signing_keys (org_id, status) WHERE status = 'active';
