/**
 * Primust Runtime Core — Lineage Token Infrastructure (P7-C)
 *
 * Enables cross-boundary governance continuity when a governed workflow
 * calls an external service (sub-agent, API, tool).
 *
 * Token signing: HMAC-SHA256 with PRIMUST_LINEAGE_HMAC_KEY.
 * Separate from Ed25519 signing key — different key, different purpose.
 *
 * Flow:
 *   p.record_delegation(context) → LineageToken
 *     → external_boundary_traversal gap (Informational)
 *
 *   p.resume_from_lineage(token) → ResumedContext
 *     → if invalid: lineage_token_missing gap (High)
 */
export type BoundaryType = 'agent_to_agent' | 'service_call' | 'tool_invocation';
export interface DelegationContext {
    caller_record_id: string;
    delegation_type: string;
    boundary_type: BoundaryType;
}
export interface LineageToken {
    token: string;
    run_id: string;
    surface_id: string;
    issued_at: string;
    expires_at: string;
    delegation_context: DelegationContext;
}
export interface LineageValidationResult {
    valid: boolean;
    run_id?: string;
    delegation_context?: DelegationContext;
    errors: string[];
}
/**
 * Generate a lineage token for cross-boundary delegation.
 *
 * @param runId - The run to delegate from
 * @param surfaceId - The surface the delegation originates from
 * @param delegationContext - Context about the delegation
 * @param hmacKey - PRIMUST_LINEAGE_HMAC_KEY (NOT the Ed25519 signing key)
 * @param ttlSeconds - Token TTL in seconds (default 3600 = 1 hour)
 * @returns Signed LineageToken
 */
export declare function generateLineageToken(runId: string, surfaceId: string, delegationContext: DelegationContext, hmacKey: string, ttlSeconds?: number): LineageToken;
/**
 * Validate a lineage token.
 *
 * @param tokenObj - The LineageToken to validate
 * @param expectedRunId - The run_id to verify against
 * @param hmacKey - PRIMUST_LINEAGE_HMAC_KEY
 * @returns Validation result with errors
 */
export declare function validateLineageToken(tokenObj: LineageToken, expectedRunId: string, hmacKey: string): LineageValidationResult;
//# sourceMappingURL=lineage.d.ts.map