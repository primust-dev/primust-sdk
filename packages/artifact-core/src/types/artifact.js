/**
 * Primust VPEC Artifact Schema — TypeScript types
 *
 * Provisional-frozen at schema_version 4.0.0
 * Canonical source: schemas/json/artifact.schema.json
 *
 * INVARIANTS (enforced in validateArtifact):
 * 1. proof_level MUST equal proof_distribution.weakest_link
 * 2. reliance_mode field ANYWHERE → validation error
 * 3. manifest_hashes MUST be object (map), not array
 * 4. gaps[] entries MUST have gap_type + severity (not bare strings)
 * 5. partial: true → policy_coverage_pct must be 0
 * 6. instrumentation_surface_pct and policy_coverage_pct never collapsed
 * 7. issuer.public_key_url must match primust.com/.well-known/ pattern
 * 8. test_mode: true rejected by primust-verify in --production mode
 */
export {};
//# sourceMappingURL=artifact.js.map