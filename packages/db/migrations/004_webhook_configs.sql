-- P9-B SIEM Webhook: webhook_configs + webhook_delivery_failures tables
-- One webhook config per org. Single endpoint per org for V1.
-- Stored on both DATABASE_URL_US and DATABASE_URL_EU per org.region.

CREATE TABLE IF NOT EXISTS webhook_configs (
    id                       TEXT PRIMARY KEY,           -- whcfg_{uuid}
    org_id                   TEXT NOT NULL,
    endpoint_url             TEXT NOT NULL,              -- customer SIEM HTTP intake URL
    auth_header              TEXT NOT NULL,              -- e.g. "Authorization: Splunk <token>"
                                                        -- encrypted at rest (GCP KMS)
    enabled                  BOOLEAN DEFAULT TRUE,
    coverage_threshold_floor NUMERIC DEFAULT 0.80,      -- fires coverage_threshold_breach
                                                        -- when provable_surface drops below this
                                                        -- stored as 0.0–1.0 (NOT percentage)
    created_at               TIMESTAMPTZ DEFAULT NOW(),
    last_delivery            TIMESTAMPTZ,
    last_status              INTEGER                     -- HTTP status of last delivery attempt
);

-- One config per org constraint
CREATE UNIQUE INDEX IF NOT EXISTS idx_webhook_configs_org_id ON webhook_configs (org_id);

CREATE TABLE IF NOT EXISTS webhook_delivery_failures (
    id           TEXT PRIMARY KEY,
    org_id       TEXT NOT NULL,
    delivery_id  TEXT NOT NULL,
    vpec_id      TEXT NOT NULL,
    event_type   TEXT NOT NULL,
    payload      JSONB,                                  -- full payload for retry
    attempted_at TIMESTAMPTZ DEFAULT NOW(),
    http_status  INTEGER,
    error_msg    TEXT
);

CREATE INDEX IF NOT EXISTS idx_webhook_failures_org_id ON webhook_delivery_failures (org_id);
CREATE INDEX IF NOT EXISTS idx_webhook_failures_delivery_id ON webhook_delivery_failures (delivery_id);
