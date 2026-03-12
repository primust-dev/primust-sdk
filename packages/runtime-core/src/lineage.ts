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

import { createHmac, timingSafeEqual } from 'node:crypto';
import { canonical } from '@primust/artifact-core';

// ── Types ──

export type BoundaryType = 'agent_to_agent' | 'service_call' | 'tool_invocation';

export interface DelegationContext {
  caller_record_id: string;
  delegation_type: string;
  boundary_type: BoundaryType;
}

export interface LineageToken {
  token: string;      // base64url HMAC-SHA256 signature
  run_id: string;
  surface_id: string;
  issued_at: string;  // ISO 8601
  expires_at: string; // ISO 8601
  delegation_context: DelegationContext;
}

export interface LineageValidationResult {
  valid: boolean;
  run_id?: string;
  delegation_context?: DelegationContext;
  errors: string[];
}

// ── Helpers ──

function toBase64Url(buf: Buffer): string {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function computeHmac(payload: string, hmacKey: string): string {
  const mac = createHmac('sha256', hmacKey).update(payload).digest();
  return toBase64Url(mac);
}

// ── Public API ──

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
export function generateLineageToken(
  runId: string,
  surfaceId: string,
  delegationContext: DelegationContext,
  hmacKey: string,
  ttlSeconds: number = 3600,
): LineageToken {
  const now = new Date();
  const issuedAt = now.toISOString();
  const expiresAt = new Date(now.getTime() + ttlSeconds * 1000).toISOString();

  // Build payload (everything except the token field itself)
  const payload = {
    run_id: runId,
    surface_id: surfaceId,
    issued_at: issuedAt,
    expires_at: expiresAt,
    delegation_context: delegationContext,
  };

  // HMAC-SHA256 over canonical(payload)
  const canonicalPayload = canonical(payload);
  const token = computeHmac(canonicalPayload, hmacKey);

  return {
    token,
    ...payload,
  };
}

/**
 * Validate a lineage token.
 *
 * @param tokenObj - The LineageToken to validate
 * @param expectedRunId - The run_id to verify against
 * @param hmacKey - PRIMUST_LINEAGE_HMAC_KEY
 * @returns Validation result with errors
 */
export function validateLineageToken(
  tokenObj: LineageToken,
  expectedRunId: string,
  hmacKey: string,
): LineageValidationResult {
  const errors: string[] = [];

  // Recompute HMAC over canonical(payload_without_token)
  const { token, ...payload } = tokenObj;
  const canonicalPayload = canonical(payload);
  const expectedToken = computeHmac(canonicalPayload, hmacKey);

  // Verify HMAC (timing-safe comparison to prevent timing attacks)
  const tokenBuf = Buffer.from(token);
  const expectedBuf = Buffer.from(expectedToken);
  if (tokenBuf.length !== expectedBuf.length || !timingSafeEqual(tokenBuf, expectedBuf)) {
    errors.push('hmac_invalid');
  }

  // Verify run_id matches
  if (tokenObj.run_id !== expectedRunId) {
    errors.push('run_id_mismatch');
  }

  // Verify not expired
  const expiresAt = new Date(tokenObj.expires_at).getTime();
  if (isNaN(expiresAt) || Date.now() > expiresAt) {
    errors.push('token_expired');
  }

  if (errors.length > 0) {
    return { valid: false, errors };
  }

  return {
    valid: true,
    run_id: tokenObj.run_id,
    delegation_context: tokenObj.delegation_context,
    errors: [],
  };
}
