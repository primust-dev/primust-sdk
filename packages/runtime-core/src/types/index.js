/**
 * Primust Runtime Core — Domain-neutral object schemas v4.
 *
 * Provisional-frozen at schema_version 4.0.0.
 *
 * BANNED FIELD NAMES (enforced in validate-schemas.ts):
 *   agent_id, pipeline_id, tool_name, session_id, trace_id,
 *   reliance_mode, PGC, attestation (as a field name)
 *
 * INVARIANTS:
 *   1. No banned field names anywhere
 *   2. witnessed stage type → witnessed proof level (NEVER attestation)
 *   3. manifest_hash captured per CheckExecutionRecord at record time
 *   4. reviewer_credential required when proof_level_achieved = witnessed
 *   5. skip_rationale_hash required when check_result = not_applicable
 *   6. CheckExecutionRecord is append-only (no UPDATE after commit)
 *   7. Waiver expires_at REQUIRED — no permanent waivers (max 90 days)
 *   8. EvidencePack: coverage_verified + coverage_pending + coverage_ungoverned = 100
 */
export {};
//# sourceMappingURL=index.js.map