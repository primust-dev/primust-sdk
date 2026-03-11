/**
 * Primust Signer Registry — In-memory signer management with JWKS.
 *
 * Manages signer lifecycle: create → rotate → revoke.
 * Publishes JWKS (RFC 7517 / RFC 8037) with active+rotated keys.
 * Stores key rotation events for Rekor transparency log submission.
 *
 * PRIMUST_LINEAGE_HMAC_KEY is loaded from process.env — never hardcoded.
 */

import {
  generateKeyPair,
  rotateKey as coreRotateKey,
} from '@primust/artifact-core';
import type {
  SignerRecord,
  KeyStatus,
  RevocationReason,
  SignerType,
} from '@primust/artifact-core';

// ── Types ──

export interface JWK {
  kid: string;
  kty: 'OKP';
  crv: 'Ed25519';
  x: string; // base64url public key
  use: 'sig';
  key_ops: ['verify'];
  primust_signer_id: string;
  primust_status: KeyStatus;
  primust_activated_at: string;
  primust_signer_type: SignerType;
}

export interface JWKS {
  keys: JWK[];
}

export interface KeyRotationEvent {
  event_type: 'key_activated' | 'key_rotated' | 'key_revoked';
  signer_id: string;
  old_kid: string | null;
  new_kid: string | null;
  effective_at: string;
  reason: string;
}

// ── Registry ──

export class SignerRegistry {
  private signers = new Map<string, SignerRecord>(); // kid → SignerRecord
  private privateKeys = new Map<string, Uint8Array>(); // kid → privateKey
  private events: KeyRotationEvent[] = [];
  private lineageHmacKey: string;

  constructor() {
    const key = process.env.PRIMUST_LINEAGE_HMAC_KEY;
    if (!key) {
      throw new Error(
        'PRIMUST_LINEAGE_HMAC_KEY must be set in environment. Never hardcode this value.',
      );
    }
    this.lineageHmacKey = key;
  }

  /**
   * Create a new signer. Delegates to artifact-core generateKeyPair().
   */
  createSigner(
    orgId: string,
    signerType: SignerType,
    signerId?: string,
  ): { signerRecord: SignerRecord; privateKey: Uint8Array } {
    const sid = signerId ?? `signer_${Date.now().toString(36)}`;
    const { signerRecord, privateKey } = generateKeyPair(sid, orgId, signerType);

    this.signers.set(signerRecord.kid, signerRecord);
    this.privateKeys.set(signerRecord.kid, privateKey);

    const event: KeyRotationEvent = {
      event_type: 'key_activated',
      signer_id: signerRecord.signer_id,
      old_kid: null,
      new_kid: signerRecord.kid,
      effective_at: signerRecord.activated_at,
      reason: 'Initial key generation',
    };
    this.events.push(event);

    return { signerRecord, privateKey };
  }

  /**
   * Rotate a signer's key. Delegates to artifact-core rotateKey().
   * Old key transitions to 'rotated', new key becomes 'active'.
   */
  rotateKey(signerId: string): {
    updatedRecord: SignerRecord;
    newRecord: SignerRecord;
    newPrivateKey: Uint8Array;
  } {
    const existing = this.findActiveBySigner(signerId);
    if (!existing) {
      throw new Error(`No active key found for signer ${signerId}`);
    }

    const { updatedRecord, newRecord, newPrivateKey } = coreRotateKey(existing);

    this.signers.set(updatedRecord.kid, updatedRecord);
    this.signers.set(newRecord.kid, newRecord);
    this.privateKeys.set(newRecord.kid, newPrivateKey);

    const event: KeyRotationEvent = {
      event_type: 'key_rotated',
      signer_id: signerId,
      old_kid: updatedRecord.kid,
      new_kid: newRecord.kid,
      effective_at: newRecord.activated_at,
      reason: 'Key rotation',
    };
    this.events.push(event);
    this.publishKeyEventToRekor(event);

    return { updatedRecord, newRecord, newPrivateKey };
  }

  /**
   * Revoke a key. State transition: active→revoked or rotated→revoked.
   * No backward transitions (revoked→active is forbidden).
   */
  revokeKey(kid: string, reason: RevocationReason): SignerRecord {
    const record = this.signers.get(kid);
    if (!record) {
      throw new Error(`Key ${kid} not found`);
    }
    if (record.status === 'revoked') {
      throw new Error(`Key ${kid} is already revoked`);
    }

    const now = new Date().toISOString();
    const revoked: SignerRecord = {
      ...record,
      status: 'revoked',
      revocation_reason: reason,
      revoked_at: now,
      deactivated_at: record.deactivated_at ?? now,
    };

    this.signers.set(kid, revoked);

    const event: KeyRotationEvent = {
      event_type: 'key_revoked',
      signer_id: record.signer_id,
      old_kid: kid,
      new_kid: null,
      effective_at: now,
      reason,
    };
    this.events.push(event);
    this.publishKeyEventToRekor(event);

    return revoked;
  }

  /**
   * Get JWKS (RFC 7517). Includes active + rotated keys. Revoked excluded.
   */
  getJWKS(): JWKS {
    const keys: JWK[] = [];
    for (const record of this.signers.values()) {
      if (record.status === 'revoked') continue;

      keys.push({
        kid: record.kid,
        kty: 'OKP',
        crv: 'Ed25519',
        x: record.public_key_b64url,
        use: 'sig',
        key_ops: ['verify'],
        primust_signer_id: record.signer_id,
        primust_status: record.status,
        primust_activated_at: record.activated_at,
        primust_signer_type: record.signer_type,
      });
    }
    return { keys };
  }

  /**
   * Resolve a kid to its SignerRecord (including revoked).
   */
  resolveKid(kid: string): SignerRecord | undefined {
    return this.signers.get(kid);
  }

  /**
   * Get the private key for a kid.
   */
  getPrivateKey(kid: string): Uint8Array | undefined {
    return this.privateKeys.get(kid);
  }

  /**
   * Get all key rotation events.
   */
  getEvents(): readonly KeyRotationEvent[] {
    return this.events;
  }

  /**
   * Stub: Publish key event to Rekor transparency log.
   * In production, this would submit to Sigstore Rekor.
   */
  publishKeyEventToRekor(event: KeyRotationEvent): void {
    // Stub — stores event in memory. Will be wired to Rekor in P9.
    // The event is already pushed to this.events in the caller.
  }

  private findActiveBySigner(signerId: string): SignerRecord | undefined {
    for (const record of this.signers.values()) {
      if (record.signer_id === signerId && record.status === 'active') {
        return record;
      }
    }
    return undefined;
  }
}
