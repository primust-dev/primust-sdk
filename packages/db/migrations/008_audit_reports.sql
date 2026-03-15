-- 008_audit_reports.sql
-- Stores generated audit report metadata (PDF stored on disk/R2).
-- Replaces the original JSON-based schema.

DROP TABLE IF EXISTS audit_reports;

CREATE TABLE audit_reports (
    report_id       TEXT PRIMARY KEY,
    org_id          TEXT NOT NULL,
    pack_id         TEXT NOT NULL,
    generated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    pdf_sha256      TEXT NOT NULL,
    signature       TEXT NOT NULL,
    key_id          TEXT NOT NULL,
    coverage_basis  TEXT NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_audit_reports_org ON audit_reports (org_id);
CREATE INDEX idx_audit_reports_pack ON audit_reports (pack_id);
