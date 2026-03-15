-- Rollback 010: Revert BYOK schema to pre-fix state
-- Restores key_id-only primary key and makes signing_endpoint_url nullable again.

-- Step 1: Drop composite primary key
ALTER TABLE org_signing_keys DROP CONSTRAINT org_signing_keys_pkey;

-- Step 2: Restore original key_id-only primary key
ALTER TABLE org_signing_keys ADD PRIMARY KEY (key_id);

-- Step 3: Make signing_endpoint_url nullable again
ALTER TABLE org_signing_keys ALTER COLUMN signing_endpoint_url DROP NOT NULL;
