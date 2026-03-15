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
import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { sha256 } from '@noble/hashes/sha256';
import { canonical } from './canonical.js';
// Configure ed25519 to use sha512
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));
/** Generate a cryptographically random hex string */
function randomHex(bytes) {
    const buf = ed.utils.randomPrivateKey().slice(0, bytes);
    return Array.from(buf)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
}
/** Encode bytes to base64url (no padding) */
function toBase64Url(bytes) {
    let binary = '';
    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
/** Decode base64url to bytes */
function fromBase64Url(b64url) {
    const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
    const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}
/**
 * Generate a new Ed25519 key pair and produce a SignerRecord.
 *
 * Each call produces a distinct kid. No silent auto-generation (Q4 quarantine).
 */
export function generateKeyPair(signerId, orgId, signerType) {
    const privateKey = ed.utils.randomPrivateKey();
    const publicKey = ed.getPublicKey(privateKey);
    const kid = `kid_${randomHex(8)}`;
    const now = new Date().toISOString();
    const signerRecord = {
        signer_id: signerId,
        kid,
        public_key_b64url: toBase64Url(publicKey),
        algorithm: 'Ed25519',
        status: 'active',
        revocation_reason: null,
        revoked_at: null,
        superseded_by_kid: null,
        activated_at: now,
        deactivated_at: null,
        org_id: orgId,
        signer_type: signerType,
    };
    return { signerRecord, privateKey };
}
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
export function sign(document, privateKey, signerRecord) {
    if (signerRecord.status !== 'active') {
        throw new Error(`Cannot sign with ${signerRecord.status} key (kid: ${signerRecord.kid})`);
    }
    const canonicalStr = canonical(document);
    const hashBytes = sha256(new TextEncoder().encode(canonicalStr));
    const signatureBytes = ed.sign(hashBytes, privateKey);
    const signatureEnvelope = {
        signer_id: signerRecord.signer_id,
        kid: signerRecord.kid,
        algorithm: 'Ed25519',
        signature: toBase64Url(signatureBytes),
        signed_at: new Date().toISOString(),
    };
    return { document, signatureEnvelope };
}
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
export function verify(document, signatureEnvelope, publicKeyB64Url) {
    try {
        const canonicalStr = canonical(document);
        const hashBytes = sha256(new TextEncoder().encode(canonicalStr));
        const signatureBytes = fromBase64Url(signatureEnvelope.signature);
        const publicKeyBytes = fromBase64Url(publicKeyB64Url);
        return ed.verify(signatureBytes, hashBytes, publicKeyBytes);
    }
    catch {
        return false;
    }
}
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
export function rotateKey(existingRecord) {
    if (existingRecord.status !== 'active') {
        throw new Error(`Cannot rotate ${existingRecord.status} key (kid: ${existingRecord.kid}). Only active keys can be rotated.`);
    }
    // Generate new key pair under the same signer_id
    const { signerRecord: newRecord, privateKey: newPrivateKey } = generateKeyPair(existingRecord.signer_id, existingRecord.org_id, existingRecord.signer_type);
    const now = new Date().toISOString();
    // Transition old record to rotated
    const updatedRecord = {
        ...existingRecord,
        status: 'rotated',
        superseded_by_kid: newRecord.kid,
        deactivated_at: now,
    };
    return { updatedRecord, newRecord, newPrivateKey };
}
// Re-export utilities for consumer use
export { toBase64Url, fromBase64Url };
//# sourceMappingURL=signing.js.map