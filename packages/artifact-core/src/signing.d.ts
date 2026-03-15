/**
 * Primust Signing — Ed25519 key generation, signing, verification, rotation
 *
 * Signing process (spec):
 *   1. canonical(document) → string
 *   2. SHA-256(canonical_string) → bytes
 *   3. Ed25519.sign(hash_bytes, private_key) → signature_bytes
 *   4. base64url(signature_bytes) → signature field
 *
 * Key identity invariants (SIGNER_TRUST_POLICY.md):
 *   - signer_id: stable logical identifier, survives rotation
 *   - kid: specific key version, unique per generation
 *   - Both required in every SignatureEnvelope
 *   - Rotation creates new kid, same signer_id
 *   - Rotation does NOT invalidate prior signatures (Q2 quarantine)
 *
 * Libraries: @noble/ed25519 + @noble/hashes
 */
import type { SignerRecord, SignatureEnvelope, SignerType } from './types.js';
/** Encode bytes to base64url (no padding) */
declare function toBase64Url(bytes: Uint8Array): string;
/** Decode base64url to bytes */
declare function fromBase64Url(b64url: string): Uint8Array;
/**
 * Generate a new Ed25519 key pair and produce a SignerRecord.
 *
 * Each call produces a distinct kid. No silent auto-generation (Q4 quarantine).
 */
export declare function generateKeyPair(signerId: string, orgId: string, signerType: SignerType): {
    signerRecord: SignerRecord;
    privateKey: Uint8Array;
};
/**
 * Sign a document.
 *
 * Process:
 *   1. canonical(document) → deterministic JSON string
 *   2. SHA-256(canonical_string) → 32-byte hash
 *   3. Ed25519.sign(hash, privateKey) → 64-byte signature
 *   4. base64url(signature) → string
 *
 * @param document - The document to sign (must contain only JSON-native types)
 * @param privateKey - Ed25519 private key bytes
 * @param signerRecord - The signer's active record (must have status 'active')
 * @returns The original document and its signature envelope
 */
export declare function sign(document: Record<string, unknown>, privateKey: Uint8Array, signerRecord: SignerRecord): {
    document: Record<string, unknown>;
    signatureEnvelope: SignatureEnvelope;
};
/**
 * Verify a document's signature.
 *
 * Recomputes canonical(document) → SHA-256 → verifies Ed25519 signature.
 * Does NOT evaluate key status — that is the verifier's responsibility
 * (SIGNER_TRUST_POLICY.md §3–4).
 *
 * @param document - The document that was signed
 * @param signatureEnvelope - The signature envelope
 * @param publicKeyB64Url - Base64url-encoded Ed25519 public key
 * @returns true if the cryptographic signature is valid
 */
export declare function verify(document: Record<string, unknown>, signatureEnvelope: SignatureEnvelope, publicKeyB64Url: string): boolean;
/**
 * Rotate a key: create a new kid under the same signer_id.
 *
 * The existing record transitions to 'rotated'. A new record is created
 * with status 'active'. Prior signatures remain valid against the old kid
 * (SIGNER_TRUST_POLICY.md §2, Q2 quarantine).
 *
 * @param existingRecord - The current active SignerRecord
 * @returns Updated old record (rotated) and new active record + private key
 */
export declare function rotateKey(existingRecord: SignerRecord): {
    updatedRecord: SignerRecord;
    newRecord: SignerRecord;
    newPrivateKey: Uint8Array;
};
export { toBase64Url, fromBase64Url };
//# sourceMappingURL=signing.d.ts.map