/**
 * VPEC Artifact validation — enforces all critical invariants.
 *
 * This is structural/semantic validation beyond what JSON Schema covers.
 * JSON Schema handles type checks; this function enforces cross-field invariants.
 */
export interface ValidationError {
    code: string;
    message: string;
    path?: string;
}
export interface ValidationResult {
    valid: boolean;
    errors: ValidationError[];
}
/**
 * Validate a VPEC artifact against all critical invariants.
 *
 * @param artifact - The artifact payload (parsed JSON)
 * @returns ValidationResult with errors if any invariants are violated
 */
export declare function validateArtifact(artifact: Record<string, unknown>): ValidationResult;
//# sourceMappingURL=validate-artifact.d.ts.map