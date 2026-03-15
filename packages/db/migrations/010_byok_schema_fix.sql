-- Migration 010: BYOK schema alignment with TECH_SPEC §6.1
-- 1. Change primary key from key_id alone to (org_id, key_id) composite
-- 2. Make signing_endpoint_url NOT NULL (prevents inconsistent active-but-no-endpoint state)
-- Apply to BOTH regions.

-- Step 1: Drop the existing primary key constraint
ALTER TABLE org_signing_keys DROP CONSTRAINT org_signing_keys_pkey;

-- Step 2: Add composite primary key
ALTER TABLE org_signing_keys ADD PRIMARY KEY (org_id, key_id);

-- Step 3: Make signing_endpoint_url NOT NULL
-- First set a placeholder for any NULL values (shouldn't exist yet, table is empty)
UPDATE org_signing_keys SET signing_endpoint_url = '' WHERE signing_endpoint_url IS NULL;
ALTER TABLE org_signing_keys ALTER COLUMN signing_endpoint_url SET NOT NULL;
