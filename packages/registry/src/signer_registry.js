/**
 * Primust Signer Registry — In-memory signer management with JWKS.
 *
 * Manages signer lifecycle: create → rotate → revoke.
 * Publishes JWKS (RFC 7517 / RFC 8037) with active+rotated keys.
 * Stores key rotation events for Rekor transparency log submission.
 *
 * PRIMUST_LINEAGE_HMAC_KEY is loaded from process.env — never hardcoded.
 */
import { generateKeyPair, rotateKey as coreRotateKey, } from '@primust/artifact-core';
// ── Registry ──
export class SignerRegistry {
    signers = new Map(); // kid → SignerRecord
    privateKeys = new Map(); // kid → privateKey
    events = [];
    lineageHmacKey;
    constructor() {
        const key = process.env.PRIMUST_LINEAGE_HMAC_KEY;
        if (!key) {
            throw new Error('PRIMUST_LINEAGE_HMAC_KEY must be set in environment. Never hardcode this value.');
        }
        this.lineageHmacKey = key;
    }
    /**
     * Create a new signer. Delegates to artifact-core generateKeyPair().
     */
    createSigner(orgId, signerType, signerId) {
        const sid = signerId ?? `signer_${Date.now().toString(36)}`;
        const { signerRecord, privateKey } = generateKeyPair(sid, orgId, signerType);
        this.signers.set(signerRecord.kid, signerRecord);
        this.privateKeys.set(signerRecord.kid, privateKey);
        const event = {
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
    rotateKey(signerId) {
        const existing = this.findActiveBySigner(signerId);
        if (!existing) {
            throw new Error(`No active key found for signer ${signerId}`);
        }
        const { updatedRecord, newRecord, newPrivateKey } = coreRotateKey(existing);
        this.signers.set(updatedRecord.kid, updatedRecord);
        this.signers.set(newRecord.kid, newRecord);
        this.privateKeys.set(newRecord.kid, newPrivateKey);
        const event = {
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
    revokeKey(kid, reason) {
        const record = this.signers.get(kid);
        if (!record) {
            throw new Error(`Key ${kid} not found`);
        }
        if (record.status === 'revoked') {
            throw new Error(`Key ${kid} is already revoked`);
        }
        const now = new Date().toISOString();
        const revoked = {
            ...record,
            status: 'revoked',
            revocation_reason: reason,
            revoked_at: now,
            deactivated_at: record.deactivated_at ?? now,
        };
        this.signers.set(kid, revoked);
        const event = {
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
    getJWKS() {
        const keys = [];
        for (const record of this.signers.values()) {
            if (record.status === 'revoked')
                continue;
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
    resolveKid(kid) {
        return this.signers.get(kid);
    }
    /**
     * Get the private key for a kid.
     */
    getPrivateKey(kid) {
        return this.privateKeys.get(kid);
    }
    /**
     * Get all key rotation events.
     */
    getEvents() {
        return this.events;
    }
    /**
     * Stub: Publish key event to Rekor transparency log.
     * In production, this would submit to Sigstore Rekor.
     */
    publishKeyEventToRekor(event) {
        // Stub — stores event in memory. Will be wired to Rekor in P9.
        // The event is already pushed to this.events in the caller.
    }
    findActiveBySigner(signerId) {
        for (const record of this.signers.values()) {
            if (record.signer_id === signerId && record.status === 'active') {
                return record;
            }
        }
        return undefined;
    }
}
//# sourceMappingURL=signer_registry.js.map