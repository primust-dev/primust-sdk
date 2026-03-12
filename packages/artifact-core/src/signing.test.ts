import { describe, it, expect } from 'vitest';
import { generateKeyPair, sign, verify, rotateKey } from './signing.js';

describe('signing', () => {
  const SIGNER_ID = 'signer_test_001';
  const ORG_ID = 'org_test_001';
  const SIGNER_TYPE = 'artifact_signer' as const;

  describe('generateKeyPair', () => {
    it('produces a valid SignerRecord with distinct kid', () => {
      const { signerRecord, privateKey } = generateKeyPair(SIGNER_ID, ORG_ID, SIGNER_TYPE);

      expect(signerRecord.signer_id).toBe(SIGNER_ID);
      expect(signerRecord.kid).toMatch(/^kid_[0-9a-f]{16}$/);
      expect(signerRecord.algorithm).toBe('Ed25519');
      expect(signerRecord.status).toBe('active');
      expect(signerRecord.revocation_reason).toBeNull();
      expect(signerRecord.revoked_at).toBeNull();
      expect(signerRecord.superseded_by_kid).toBeNull();
      expect(signerRecord.org_id).toBe(ORG_ID);
      expect(signerRecord.signer_type).toBe(SIGNER_TYPE);
      expect(signerRecord.public_key_b64url).toBeTypeOf('string');
      expect(signerRecord.public_key_b64url.length).toBeGreaterThan(0);
      expect(privateKey).toBeInstanceOf(Uint8Array);
      expect(privateKey.length).toBe(32);
    });

    it('generates distinct kid on each call (signer_id ≠ kid)', () => {
      const a = generateKeyPair(SIGNER_ID, ORG_ID, SIGNER_TYPE);
      const b = generateKeyPair(SIGNER_ID, ORG_ID, SIGNER_TYPE);

      // Same signer_id
      expect(a.signerRecord.signer_id).toBe(b.signerRecord.signer_id);
      // Different kid
      expect(a.signerRecord.kid).not.toBe(b.signerRecord.kid);
      // Different key material
      expect(a.signerRecord.public_key_b64url).not.toBe(b.signerRecord.public_key_b64url);
    });
  });

  describe('sign → verify roundtrip', () => {
    it('MUST PASS: sign → verify roundtrip', () => {
      const { signerRecord, privateKey } = generateKeyPair(SIGNER_ID, ORG_ID, SIGNER_TYPE);
      const doc = { action: 'create', target: 'resource_42', ts: '2026-03-10T00:00:00Z' };

      const { document, signatureEnvelope } = sign(doc, privateKey, signerRecord);

      expect(signatureEnvelope.signer_id).toBe(SIGNER_ID);
      expect(signatureEnvelope.kid).toBe(signerRecord.kid);
      expect(signatureEnvelope.algorithm).toBe('Ed25519');
      expect(signatureEnvelope.signature).toBeTypeOf('string');
      expect(signatureEnvelope.signed_at).toMatch(/^\d{4}-/);

      const valid = verify(document, signatureEnvelope, signerRecord.public_key_b64url);
      expect(valid).toBe(true);
    });

    it('MUST PASS: tampered document fails verify', () => {
      const { signerRecord, privateKey } = generateKeyPair(SIGNER_ID, ORG_ID, SIGNER_TYPE);
      const doc = { action: 'create', target: 'resource_42' };

      const { signatureEnvelope } = sign(doc, privateKey, signerRecord);

      // Tamper with the document
      const tampered = { action: 'delete', target: 'resource_42' };
      const valid = verify(tampered, signatureEnvelope, signerRecord.public_key_b64url);
      expect(valid).toBe(false);
    });

    it('wrong public key fails verify', () => {
      const { signerRecord, privateKey } = generateKeyPair(SIGNER_ID, ORG_ID, SIGNER_TYPE);
      const other = generateKeyPair('signer_other', ORG_ID, SIGNER_TYPE);
      const doc = { msg: 'hello' };

      const { document, signatureEnvelope } = sign(doc, privateKey, signerRecord);

      const valid = verify(document, signatureEnvelope, other.signerRecord.public_key_b64url);
      expect(valid).toBe(false);
    });

    it('corrupted signature fails verify', () => {
      const { signerRecord, privateKey } = generateKeyPair(SIGNER_ID, ORG_ID, SIGNER_TYPE);
      const doc = { data: 'test' };

      const { document, signatureEnvelope } = sign(doc, privateKey, signerRecord);

      const corrupted = { ...signatureEnvelope, signature: 'AAAA_bad_signature' };
      const valid = verify(document, corrupted, signerRecord.public_key_b64url);
      expect(valid).toBe(false);
    });
  });

  describe('sign guards', () => {
    it('refuses to sign with a rotated key', () => {
      const { signerRecord, privateKey } = generateKeyPair(SIGNER_ID, ORG_ID, SIGNER_TYPE);
      const rotatedRecord = { ...signerRecord, status: 'rotated' as const };

      expect(() => sign({ data: 'test' }, privateKey, rotatedRecord)).toThrow(/rotated/);
    });

    it('refuses to sign with a revoked key', () => {
      const { signerRecord, privateKey } = generateKeyPair(SIGNER_ID, ORG_ID, SIGNER_TYPE);
      const revokedRecord = { ...signerRecord, status: 'revoked' as const };

      expect(() => sign({ data: 'test' }, privateKey, revokedRecord)).toThrow(/revoked/);
    });
  });

  describe('rotateKey', () => {
    it('MUST PASS: rotated kid still verifies historical document', () => {
      const { signerRecord: original, privateKey } = generateKeyPair(
        SIGNER_ID,
        ORG_ID,
        SIGNER_TYPE,
      );
      const doc = { historical: true, version: 1 };

      // Sign with original key
      const { document, signatureEnvelope } = sign(doc, privateKey, original);

      // Rotate the key
      const { updatedRecord, newRecord } = rotateKey(original);

      // Original record is now rotated
      expect(updatedRecord.status).toBe('rotated');
      expect(updatedRecord.kid).toBe(original.kid);
      expect(updatedRecord.signer_id).toBe(SIGNER_ID);

      // New record is active under the same signer_id
      expect(newRecord.status).toBe('active');
      expect(newRecord.signer_id).toBe(SIGNER_ID);
      expect(newRecord.kid).not.toBe(original.kid);

      // Historical document STILL verifies against the original public key
      const valid = verify(document, signatureEnvelope, updatedRecord.public_key_b64url);
      expect(valid).toBe(true);
    });

    it('MUST PASS: rotateKey sets superseded_by_kid on old record', () => {
      const { signerRecord } = generateKeyPair(SIGNER_ID, ORG_ID, SIGNER_TYPE);

      const { updatedRecord, newRecord } = rotateKey(signerRecord);

      expect(updatedRecord.superseded_by_kid).toBe(newRecord.kid);
      expect(updatedRecord.deactivated_at).toMatch(/^\d{4}-/);
    });

    it('rotateKey preserves signer_id across rotation', () => {
      const { signerRecord } = generateKeyPair(SIGNER_ID, ORG_ID, SIGNER_TYPE);

      const { updatedRecord, newRecord } = rotateKey(signerRecord);

      expect(updatedRecord.signer_id).toBe(SIGNER_ID);
      expect(newRecord.signer_id).toBe(SIGNER_ID);
    });

    it('cannot rotate an already-rotated key', () => {
      const { signerRecord } = generateKeyPair(SIGNER_ID, ORG_ID, SIGNER_TYPE);
      const { updatedRecord } = rotateKey(signerRecord);

      expect(() => rotateKey(updatedRecord)).toThrow(/rotated/);
    });
  });

  describe('quarantine compliance', () => {
    it('MUST PASS: no hardcoded keys anywhere', () => {
      // Generate multiple keypairs and verify they are all unique
      const keys = Array.from({ length: 5 }, () =>
        generateKeyPair(SIGNER_ID, ORG_ID, SIGNER_TYPE),
      );
      const publicKeys = new Set(keys.map((k) => k.signerRecord.public_key_b64url));
      const kids = new Set(keys.map((k) => k.signerRecord.kid));

      expect(publicKeys.size).toBe(5);
      expect(kids.size).toBe(5);
    });

    it('signature envelope always contains both signer_id and kid', () => {
      const { signerRecord, privateKey } = generateKeyPair(SIGNER_ID, ORG_ID, SIGNER_TYPE);
      const doc = { test: true };

      const { signatureEnvelope } = sign(doc, privateKey, signerRecord);

      expect(signatureEnvelope.signer_id).toBe(SIGNER_ID);
      expect(signatureEnvelope.kid).toBe(signerRecord.kid);
      expect(signatureEnvelope.signer_id).not.toBe(signatureEnvelope.kid);
    });

    it('canonical serialization is recursive (Q1 enforcement)', () => {
      const { signerRecord, privateKey } = generateKeyPair(SIGNER_ID, ORG_ID, SIGNER_TYPE);

      // Two documents with same data but different nested key order
      const doc1 = { outer: { z: 1, a: 2 }, id: 'test' };
      const doc2 = { id: 'test', outer: { a: 2, z: 1 } };

      const { signatureEnvelope: sig1 } = sign(doc1, privateKey, signerRecord);

      // doc2 should verify against sig1 because canonical form is identical
      const valid = verify(doc2, sig1, signerRecord.public_key_b64url);
      expect(valid).toBe(true);
    });
  });
});
