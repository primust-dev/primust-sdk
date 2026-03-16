-- Migration 011: Align check_result and gap_state enums with API/JSON schemas
-- check_result: add 'skipped' and 'timed_out' (Pydantic model + JSON schema)
-- gap_state: add 'investigating', 'remediated', 'escalated' (gap.schema.json)

-- check_result currently: pass, fail, degraded, not_applicable, error, override
ALTER TYPE check_result ADD VALUE IF NOT EXISTS 'skipped';
ALTER TYPE check_result ADD VALUE IF NOT EXISTS 'timed_out';

-- gap_state currently: open, resolved, waived
ALTER TYPE gap_state ADD VALUE IF NOT EXISTS 'investigating';
ALTER TYPE gap_state ADD VALUE IF NOT EXISTS 'remediated';
ALTER TYPE gap_state ADD VALUE IF NOT EXISTS 'escalated';
