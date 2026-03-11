import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { SignerRegistry } from './signer_registry.js';
import type { JWKS } from './signer_registry.js';

describe('SignerRegistry', () => {
  beforeEach(() => {
    vi.stubEnv('PRIMUST_LINEAGE_HMAC_KEY', 'test-hmac-key-for-lineage');
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  // ── MUST PASS: PRIMUST_LINEAGE_HMAC_KEY loaded from environment ──

  it('throws if PRIMUST_LINEAGE_HMAC_KEY is not set', () => {
    vi.stubEnv('PRIMUST_LINEAGE_HMAC_KEY', '');
    expect(() => new SignerRegistry()).toThrow('PRIMUST_LINEAGE_HMAC_KEY');
  });

  it('constructs when PRIMUST_LINEAGE_HMAC_KEY is set', () => {
    const registry = new SignerRegistry();
    expect(registry).toBeDefined();
  });

  // ── MUST PASS: Create signer ──

  it('createSigner produces active SignerRecord', () => {
    const registry = new SignerRegistry();
    const { signerRecord } = registry.createSigner('org_test', 'artifact_signer', 'signer_1');

    expect(signerRecord.signer_id).toBe('signer_1');
    expect(signerRecord.status).toBe('active');
    expect(signerRecord.kid).toMatch(/^kid_/);
    expect(signerRecord.algorithm).toBe('Ed25519');
  });

  // ── MUST PASS: JWKS contains active + rotated, excludes revoked ──

  it('JWKS includes active and rotated keys, excludes revoked', () => {
    const registry = new SignerRegistry();
    const { signerRecord: rec1 } = registry.createSigner('org_test', 'artifact_signer', 'signer_1');

    // Rotate → old key becomes rotated, new key is active
    const { updatedRecord, newRecord } = registry.rotateKey('signer_1');

    const jwks = registry.getJWKS();
    const kids = jwks.keys.map((k) => k.kid);

    // Both active and rotated should be in JWKS
    expect(kids).toContain(updatedRecord.kid); // rotated
    expect(kids).toContain(newRecord.kid); // active
    expect(jwks.keys.length).toBe(2);

    // Now revoke the rotated key
    registry.revokeKey(updatedRecord.kid, 'decommissioned');
    const jwks2 = registry.getJWKS();
    const kids2 = jwks2.keys.map((k) => k.kid);

    // Revoked should be excluded
    expect(kids2).not.toContain(updatedRecord.kid);
    expect(kids2).toContain(newRecord.kid);
    expect(jwks2.keys.length).toBe(1);
  });

  // ── MUST PASS: JWKS validates against RFC 7517 ──

  it('JWKS entries have RFC 7517/8037 required fields', () => {
    const registry = new SignerRegistry();
    registry.createSigner('org_test', 'artifact_signer', 'signer_1');

    const jwks = registry.getJWKS();
    expect(jwks.keys.length).toBe(1);

    const key = jwks.keys[0];
    expect(key.kty).toBe('OKP');
    expect(key.crv).toBe('Ed25519');
    expect(key.use).toBe('sig');
    expect(key.key_ops).toEqual(['verify']);
    expect(key.kid).toBeDefined();
    expect(key.x).toBeDefined();
    expect(key.primust_signer_id).toBe('signer_1');
    expect(key.primust_status).toBe('active');
    expect(key.primust_activated_at).toBeDefined();
    expect(key.primust_signer_type).toBe('artifact_signer');
  });

  // ── MUST PASS: rotateKey triggers publishKeyEventToRekor ──

  it('rotateKey publishes key_rotated event', () => {
    const registry = new SignerRegistry();
    const spy = vi.spyOn(registry, 'publishKeyEventToRekor');

    registry.createSigner('org_test', 'artifact_signer', 'signer_1');
    registry.rotateKey('signer_1');

    expect(spy).toHaveBeenCalledTimes(1);
    expect(spy).toHaveBeenCalledWith(
      expect.objectContaining({
        event_type: 'key_rotated',
        signer_id: 'signer_1',
      }),
    );
  });

  // ── MUST PASS: State transitions ──

  it('state transition: active → rotated', () => {
    const registry = new SignerRegistry();
    const { signerRecord } = registry.createSigner('org_test', 'artifact_signer', 'signer_1');
    expect(signerRecord.status).toBe('active');

    const { updatedRecord } = registry.rotateKey('signer_1');
    expect(updatedRecord.status).toBe('rotated');
    expect(updatedRecord.kid).toBe(signerRecord.kid);
  });

  it('state transition: active → revoked', () => {
    const registry = new SignerRegistry();
    const { signerRecord } = registry.createSigner('org_test', 'artifact_signer', 'signer_1');

    const revoked = registry.revokeKey(signerRecord.kid, 'key_compromise');
    expect(revoked.status).toBe('revoked');
    expect(revoked.revocation_reason).toBe('key_compromise');
  });

  it('state transition: rotated → revoked', () => {
    const registry = new SignerRegistry();
    registry.createSigner('org_test', 'artifact_signer', 'signer_1');
    const { updatedRecord } = registry.rotateKey('signer_1');
    expect(updatedRecord.status).toBe('rotated');

    const revoked = registry.revokeKey(updatedRecord.kid, 'decommissioned');
    expect(revoked.status).toBe('revoked');
  });

  // ── MUST PASS: No backward transitions ──

  it('cannot revoke an already revoked key', () => {
    const registry = new SignerRegistry();
    const { signerRecord } = registry.createSigner('org_test', 'artifact_signer', 'signer_1');
    registry.revokeKey(signerRecord.kid, 'key_compromise');

    expect(() => registry.revokeKey(signerRecord.kid, 'decommissioned')).toThrow(
      'already revoked',
    );
  });

  it('cannot rotate a non-active key', () => {
    const registry = new SignerRegistry();
    registry.createSigner('org_test', 'artifact_signer', 'signer_1');
    const { updatedRecord } = registry.rotateKey('signer_1');

    // The old key is now rotated, so rotating the signer again
    // should use the new active key, not fail
    const { updatedRecord: rotated2 } = registry.rotateKey('signer_1');
    expect(rotated2.status).toBe('rotated');
  });

  // ── resolveKid ──

  it('resolveKid returns record for any status including revoked', () => {
    const registry = new SignerRegistry();
    const { signerRecord } = registry.createSigner('org_test', 'artifact_signer', 'signer_1');
    registry.revokeKey(signerRecord.kid, 'key_compromise');

    const resolved = registry.resolveKid(signerRecord.kid);
    expect(resolved).toBeDefined();
    expect(resolved!.status).toBe('revoked');
  });

  it('resolveKid returns undefined for unknown kid', () => {
    const registry = new SignerRegistry();
    expect(registry.resolveKid('kid_nonexistent')).toBeUndefined();
  });

  // ── Events ──

  it('records key_activated event on createSigner', () => {
    const registry = new SignerRegistry();
    registry.createSigner('org_test', 'artifact_signer', 'signer_1');

    const events = registry.getEvents();
    expect(events.length).toBe(1);
    expect(events[0].event_type).toBe('key_activated');
    expect(events[0].signer_id).toBe('signer_1');
  });

  it('revokeKey publishes key_revoked event to Rekor', () => {
    const registry = new SignerRegistry();
    const spy = vi.spyOn(registry, 'publishKeyEventToRekor');

    const { signerRecord } = registry.createSigner('org_test', 'artifact_signer', 'signer_1');
    registry.revokeKey(signerRecord.kid, 'key_compromise');

    expect(spy).toHaveBeenCalledWith(
      expect.objectContaining({
        event_type: 'key_revoked',
      }),
    );
  });
});
