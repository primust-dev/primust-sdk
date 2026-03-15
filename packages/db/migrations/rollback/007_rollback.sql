-- Rollback migration 007: Drop organizations table and revert api_keys key_type constraint
DROP TABLE IF EXISTS organizations;

ALTER TABLE api_keys DROP CONSTRAINT IF EXISTS api_keys_key_type_check;
ALTER TABLE api_keys ADD CONSTRAINT api_keys_key_type_check
    CHECK (key_type IN ('live', 'test'));
