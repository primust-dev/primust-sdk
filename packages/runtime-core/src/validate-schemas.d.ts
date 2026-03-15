/**
 * Primust Runtime Core — Cross-field validation for domain-neutral objects v3.
 *
 * Enforces all invariants from the schema spec:
 *   1. No banned field names anywhere
 *   2. witnessed stage type → witnessed proof level (NEVER attestation)
 *   3. manifest_hash captured per CheckExecutionRecord at record time
 *   4. reviewer_credential required when proof_level_achieved = witnessed
 *   5. skip_rationale_hash required when check_result = not_applicable
 *   6. CheckExecutionRecord is append-only (no UPDATE after commit)
 *   7. Waiver expires_at REQUIRED — no permanent waivers (max 90 days)
 *   8. EvidencePack: coverage_verified + coverage_pending + coverage_ungoverned = 100
 *   9. Waiver risk_treatment REQUIRED — must be: accept, mitigate, transfer, or avoid
 */
import type { CheckExecutionRecord, ManifestStage, Waiver, EvidencePack } from './types/index.js';
export interface ValidationError {
    code: string;
    message: string;
}
/**
 * Recursively scan an object for banned field names.
 * Returns a list of violations with the field path.
 */
export declare function scanBannedFields(obj: unknown, path?: string): ValidationError[];
/**
 * Validate a ManifestStage — invariant 2:
 * witnessed type → witnessed proof_level (NEVER attestation).
 */
export declare function validateManifestStage(stage: ManifestStage): ValidationError[];
/**
 * Validate a CheckExecutionRecord — invariants 3, 4, 5.
 */
export declare function validateCheckExecutionRecord(record: CheckExecutionRecord): ValidationError[];
/**
 * Validate a Waiver — invariant 7.
 */
export declare function validateWaiver(waiver: Waiver): ValidationError[];
/**
 * Validate an EvidencePack — invariant 8.
 */
export declare function validateEvidencePack(pack: EvidencePack): ValidationError[];
//# sourceMappingURL=validate-schemas.d.ts.map