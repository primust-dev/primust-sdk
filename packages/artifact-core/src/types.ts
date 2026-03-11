/**
 * Primust Artifact Core — Type definitions
 *
 * Frozen schemas from P1-B spec. Do not modify without schema migration.
 */

/** Key lifecycle states per SIGNER_TRUST_POLICY.md §2 */
export type KeyStatus = 'active' | 'rotated' | 'revoked';

/** Revocation reasons per SIGNER_TRUST_POLICY.md §3 */
export type RevocationReason = 'key_compromise' | 'decommissioned';

/** Signer purpose */
export type SignerType = 'artifact_signer' | 'manifest_signer' | 'policy_pack_signer';

/**
 * SignerRecord — frozen schema.
 *
 * One record per kid. A signer_id may have multiple SignerRecords
 * (one active, zero or more rotated/revoked).
 */
export interface SignerRecord {
  signer_id: string;
  kid: string;
  public_key_b64url: string;
  algorithm: 'Ed25519';
  status: KeyStatus;
  revocation_reason: RevocationReason | null;
  revoked_at: string | null;
  superseded_by_kid: string | null;
  activated_at: string;
  deactivated_at: string | null;
  org_id: string;
  signer_type: SignerType;
}

/**
 * SignatureEnvelope — frozen schema.
 *
 * Attached to every signed Primust artifact. Both signer_id and kid
 * are required — no exceptions.
 */
export interface SignatureEnvelope {
  signer_id: string;
  kid: string;
  algorithm: 'Ed25519';
  signature: string; // base64url-encoded Ed25519 signature
  signed_at: string; // ISO 8601
}
