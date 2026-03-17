-- Migration 012: Schema reconciliation — canonical field names
-- Reconciles VPEC table fields with canonical spec (MIGRATION_009_SPEC_v1).
-- Pre-production only. Apply to US environment first, then EU.

-- 1. Rename proof_level → proof_level_floor (weakest-link scalar)
ALTER TABLE vpecs RENAME COLUMN proof_level TO proof_level_floor;

-- 2. Add provable_surface fields
ALTER TABLE vpecs ADD COLUMN provable_surface FLOAT;
ALTER TABLE vpecs ADD COLUMN provable_surface_breakdown JSONB;
ALTER TABLE vpecs ADD COLUMN provable_surface_pending FLOAT DEFAULT 0.0;
ALTER TABLE vpecs ADD COLUMN provable_surface_ungoverned FLOAT DEFAULT 0.0;
ALTER TABLE vpecs ADD COLUMN provable_surface_basis TEXT DEFAULT 'executed_records';
ALTER TABLE vpecs ADD COLUMN provable_surface_suppressed BOOLEAN DEFAULT FALSE;

-- 3. Replace test_mode boolean with environment text
ALTER TABLE vpecs ADD COLUMN environment TEXT DEFAULT 'production'
    CHECK (environment IN ('sandbox', 'production'));
UPDATE vpecs SET environment = CASE WHEN test_mode THEN 'sandbox' ELSE 'production' END;
ALTER TABLE vpecs DROP COLUMN test_mode;
