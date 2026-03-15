/**
 * Primust Signer Registry — In-memory signer management with JWKS.
 *
 * Manages signer lifecycle: create → rotate → revoke.
 * Publishes JWKS (RFC 7517 / RFC 8037) with active+rotated keys.
 * Stores key rotation events for Rekor transparency log submission.
 *
 * PRIMUST_LINEAGE_HMAC_KEY is loaded from process.env — never hardcoded.
 */
import type { SignerRecord, KeyStatus, RevocationReason, SignerType } from '@primust/artifact-core';
export interface JWK {
    kid: string;
    kty: 'OKP';
    crv: 'Ed25519';
    x: string;
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
export declare class SignerRegistry {
    private signers;
    private privateKeys;
    private events;
    private lineageHmacKey;
    constructor();
    /**
     * Create a new signer. Delegates to artifact-core generateKeyPair().
     */
    createSigner(orgId: string, signerType: SignerType, signerId?: string): {
        signerRecord: SignerRecord;
        privateKey: Uint8Array;
    };
    /**
     * Rotate a signer's key. Delegates to artifact-core rotateKey().
     * Old key transitions to 'rotated', new key becomes 'active'.
     */
    rotateKey(signerId: string): {
        updatedRecord: SignerRecord;
        newRecord: SignerRecord;
        newPrivateKey: Uint8Array;
    };
    /**
     * Revoke a key. State transition: active→revoked or rotated→revoked.
     * No backward transitions (revoked→active is forbidden).
     */
    revokeKey(kid: string, reason: RevocationReason): SignerRecord;
    /**
     * Get JWKS (RFC 7517). Includes active + rotated keys. Revoked excluded.
     */
    getJWKS(): JWKS;
    /**
     * Resolve a kid to its SignerRecord (including revoked).
     */
    resolveKid(kid: string): SignerRecord | undefined;
    /**
     * Get the private key for a kid.
     */
    getPrivateKey(kid: string): Uint8Array | undefined;
    /**
     * Get all key rotation events.
     */
    getEvents(): readonly KeyRotationEvent[];
    /**
     * Stub: Publish key event to Rekor transparency log.
     * In production, this would submit to Sigstore Rekor.
     */
    publishKeyEventToRekor(event: KeyRotationEvent): void;
    private findActiveBySigner;
}
//# sourceMappingURL=signer_registry.d.ts.map