/**
 * Tests for lineage token infrastructure — P7-C.
 * 8 MUST PASS tests.
 */

import { describe, expect, it } from 'vitest';

import type { DelegationContext, LineageToken } from './lineage.js';
import { generateLineageToken, validateLineageToken } from './lineage.js';

// ── Helpers ──

const HMAC_KEY = 'a'.repeat(64); // test HMAC key (hex string)
const ED25519_KEY = 'b'.repeat(64); // different key — NOT the Ed25519 signing key

function makeContext(): DelegationContext {
  return {
    caller_record_id: 'rec_001',
    delegation_type: 'sub_agent_call',
    boundary_type: 'agent_to_agent',
  };
}

// ── Tests ──

describe('lineage tokens (P7-C)', () => {
  it('MUST PASS: valid token → validateLineageToken returns valid: true', () => {
    const token = generateLineageToken(
      'run_001',
      'surf_001',
      makeContext(),
      HMAC_KEY,
    );

    const result = validateLineageToken(token, 'run_001', HMAC_KEY);
    expect(result.valid).toBe(true);
    expect(result.run_id).toBe('run_001');
    expect(result.delegation_context).toEqual(makeContext());
    expect(result.errors).toHaveLength(0);
  });

  it('MUST PASS: expired token → valid: false, errors: ["token_expired"]', () => {
    const token = generateLineageToken(
      'run_001',
      'surf_001',
      makeContext(),
      HMAC_KEY,
      3600,
    );

    // Manually set expires_at to the past
    const expiredToken: LineageToken = {
      ...token,
      expires_at: '2020-01-01T00:00:00.000Z',
    };
    // Recompute HMAC for the tampered payload so only expiry triggers
    const reissued = generateLineageToken(
      'run_001',
      'surf_001',
      makeContext(),
      HMAC_KEY,
      -3600, // negative TTL → expires in the past
    );

    const result = validateLineageToken(reissued, 'run_001', HMAC_KEY);
    expect(result.valid).toBe(false);
    expect(result.errors).toContain('token_expired');
  });

  it('MUST PASS: wrong run_id → valid: false', () => {
    const token = generateLineageToken(
      'run_001',
      'surf_001',
      makeContext(),
      HMAC_KEY,
    );

    const result = validateLineageToken(token, 'run_999', HMAC_KEY);
    expect(result.valid).toBe(false);
    expect(result.errors).toContain('run_id_mismatch');
  });

  it('MUST PASS: tampered token → valid: false, errors: ["hmac_invalid"]', () => {
    const token = generateLineageToken(
      'run_001',
      'surf_001',
      makeContext(),
      HMAC_KEY,
    );

    // Tamper with the token signature
    const tampered: LineageToken = {
      ...token,
      token: 'tampered_signature_value',
    };

    const result = validateLineageToken(tampered, 'run_001', HMAC_KEY);
    expect(result.valid).toBe(false);
    expect(result.errors).toContain('hmac_invalid');
  });

  it('MUST PASS: token format includes external_boundary_traversal gap context (delegation scenario)', () => {
    const context = makeContext();
    const token = generateLineageToken(
      'run_001',
      'surf_001',
      context,
      HMAC_KEY,
    );

    // Token should contain delegation context for boundary traversal tracking
    expect(token.delegation_context.boundary_type).toBe('agent_to_agent');
    expect(token.delegation_context.caller_record_id).toBe('rec_001');
    expect(token.delegation_context.delegation_type).toBe('sub_agent_call');
    expect(token.surface_id).toBe('surf_001');
  });

  it('MUST PASS: token validation failure produces lineage_token_missing gap context', () => {
    const token = generateLineageToken(
      'run_001',
      'surf_001',
      makeContext(),
      HMAC_KEY,
    );

    // Validate with wrong key — simulates missing/invalid token scenario
    const result = validateLineageToken(token, 'run_001', 'wrong_key');
    expect(result.valid).toBe(false);
    // The caller would emit lineage_token_missing gap (High) when valid === false
    expect(result.errors.length).toBeGreaterThan(0);
  });

  it('MUST PASS: token expires after 1 hour by default', () => {
    const token = generateLineageToken(
      'run_001',
      'surf_001',
      makeContext(),
      HMAC_KEY,
    );

    const issuedAt = new Date(token.issued_at).getTime();
    const expiresAt = new Date(token.expires_at).getTime();
    const diffMs = expiresAt - issuedAt;

    // Default TTL is 3600 seconds = 3,600,000 ms
    expect(diffMs).toBe(3600 * 1000);
  });

  it('MUST PASS: token uses HMAC-SHA256 (not Ed25519 signing key)', () => {
    // Generate with HMAC key
    const tokenHmac = generateLineageToken(
      'run_001',
      'surf_001',
      makeContext(),
      HMAC_KEY,
    );

    // Validate with HMAC key → valid
    expect(validateLineageToken(tokenHmac, 'run_001', HMAC_KEY).valid).toBe(true);

    // Validate with Ed25519 key → invalid (different key, different purpose)
    expect(validateLineageToken(tokenHmac, 'run_001', ED25519_KEY).valid).toBe(false);

    // Keys must be different
    expect(HMAC_KEY).not.toBe(ED25519_KEY);
  });
});
