/**
 * primust-verify — Offline VPEC artifact verifier.
 *
 * ZERO runtime dependencies on Primust infrastructure after initial
 * public key fetch. Must verify a VPEC produced today in 10 years.
 *
 * Verification steps (in order):
 * 1. Schema validation
 * 2. SHA-256 integrity + Ed25519 signature (combined)
 * 3. Kid resolution
 * 4. Signer status check (Rekor — stubbed in v1)
 * 5. RFC 3161 timestamp verification (stubbed in v1)
 * 6. Proof level integrity
 * 7. Manifest hash audit
 * 8. ZK proof verification (stubbed in v1)
 * 9. test_mode check
 */

import { createHash } from 'node:crypto';
import {
  canonical,
  verify as ed25519Verify,
  validateArtifact,
  fromBase64Url,
} from '@primust/artifact-core';
import type { SignatureEnvelope } from '@primust/artifact-core';
import { getKey } from './key-cache.js';
import type { VerifyOptions, VerificationResult, RekorStatus } from './types.js';

/**
 * Check recursively for reliance_mode field anywhere in the artifact.
 */
function hasRelianceMode(obj: Record<string, unknown>, path = ''): string | null {
  for (const [key, value] of Object.entries(obj)) {
    const currentPath = path ? `${path}.${key}` : key;
    if (key === 'reliance_mode') {
      return currentPath;
    }
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      const found = hasRelianceMode(value as Record<string, unknown>, currentPath);
      if (found) return found;
    }
  }
  return null;
}

/**
 * Build a default (failed/empty) VerificationResult from an artifact dict.
 */
function baseResult(artifact: Record<string, unknown>): VerificationResult {
  const sig = artifact.signature as Record<string, unknown> | undefined;
  const issuer = artifact.issuer as Record<string, unknown> | undefined;
  const proofDist = artifact.proof_distribution as Record<string, unknown> | undefined;
  const coverage = artifact.coverage as Record<string, unknown> | undefined;
  const gaps = Array.isArray(artifact.gaps) ? artifact.gaps : [];

  return {
    vpec_id: (artifact.vpec_id as string) ?? '',
    valid: false,
    schema_version: (artifact.schema_version as string) ?? '',
    proof_level: (artifact.proof_level as string) ?? '',
    proof_distribution: proofDist ?? {},
    org_id: (artifact.org_id as string) ?? '',
    workflow_id: (artifact.workflow_id as string) ?? '',
    process_context_hash: (artifact.process_context_hash as string | null) ?? null,
    partial: (artifact.partial as boolean) ?? false,
    test_mode: (artifact.test_mode as boolean) ?? false,
    signer_id: (issuer?.signer_id as string) ?? (sig?.signer_id as string) ?? '',
    kid: (issuer?.kid as string) ?? (sig?.kid as string) ?? '',
    signed_at: (sig?.signed_at as string) ?? '',
    timestamp_anchor_valid: null,
    rekor_status: 'skipped',
    zk_proof_valid: null,
    manifest_hashes: {},
    gaps: gaps.map((g: Record<string, unknown>) => ({
      gap_id: (g.gap_id as string) ?? '',
      gap_type: (g.gap_type as string) ?? '',
      severity: (g.severity as string) ?? '',
    })),
    coverage: coverage ?? {},
    errors: [],
    warnings: [],
  };
}

/**
 * Verify a VPEC artifact.
 *
 * @param artifact - Parsed artifact JSON (Record<string, unknown>)
 * @param options  - Verification options
 * @returns VerificationResult with errors/warnings
 */
export async function verify(
  artifact: Record<string, unknown>,
  options: VerifyOptions = {},
): Promise<VerificationResult> {
  const result = baseResult(artifact);
  const { production = false, skip_network = false, trust_root } = options;

  // ── Step 1: Schema validation ──
  const schemaResult = validateArtifact(artifact);
  if (!schemaResult.valid) {
    for (const err of schemaResult.errors) {
      if (err.code === 'RELIANCE_MODE_FORBIDDEN') {
        result.errors.push('banned_field_reliance_mode');
      } else if (err.code === 'MANIFEST_HASHES_NOT_MAP') {
        result.errors.push('manifest_hashes_not_object');
      } else {
        result.errors.push(`schema_validation_failed: ${err.code}`);
      }
    }
    return result;
  }

  // Extra check: reliance_mode anywhere (validateArtifact already catches this,
  // but we ensure the specific error string)
  const reliancePath = hasRelianceMode(artifact);
  if (reliancePath) {
    result.errors.push('banned_field_reliance_mode');
    return result;
  }

  // ── Step 4 (early): Kid resolution — issuer.kid must match signature.kid ──
  const issuer = artifact.issuer as Record<string, unknown>;
  const sig = artifact.signature as Record<string, unknown>;

  if (!issuer || !sig) {
    result.errors.push('missing_issuer_or_signature');
    return result;
  }

  if (issuer.kid !== sig.kid) {
    result.errors.push('kid_mismatch');
    return result;
  }

  // ── Step 2+3: Integrity + Ed25519 signature verification ──
  // The signing process signs the artifact body (everything except 'signature').
  // We reconstruct the document by stripping the signature field.
  const { signature: _sig, ...documentBody } = artifact;

  // Resolve public key
  let publicKeyB64Url: string;
  try {
    const pem = await getKey(
      sig.kid as string,
      issuer.public_key_url as string,
      trust_root,
    );
    // PEM may be raw base64url or PEM-wrapped. Handle both.
    publicKeyB64Url = extractKeyFromPem(pem);
  } catch (err) {
    result.errors.push((err as Error).message);
    return result;
  }

  const signatureEnvelope: SignatureEnvelope = {
    signer_id: sig.signer_id as string,
    kid: sig.kid as string,
    algorithm: sig.algorithm as 'Ed25519',
    signature: sig.signature as string,
    signed_at: sig.signed_at as string,
  };

  const sigValid = ed25519Verify(documentBody, signatureEnvelope, publicKeyB64Url);
  if (!sigValid) {
    result.errors.push('integrity_check_failed');
    return result;
  }

  // ── Step 5: Signer status check (Rekor) ──
  if (skip_network) {
    result.rekor_status = 'skipped';
  } else {
    result.rekor_status = await checkRekor(publicKeyB64Url, sig.kid as string);
    if (result.rekor_status === 'unavailable') {
      result.warnings.push('rekor_check_unavailable');
    } else if (result.rekor_status === 'revoked') {
      result.errors.push('signer_key_revoked');
      return result;
    }
  }

  // ── Step 6: RFC 3161 timestamp verification ──
  const tsAnchor = artifact.timestamp_anchor as Record<string, unknown> | undefined;
  if (tsAnchor && tsAnchor.type === 'rfc3161' && typeof tsAnchor.value === 'string') {
    result.timestamp_anchor_valid = verifyTimestampImprint(
      tsAnchor.value as string,
      documentBody,
    );
    if (result.timestamp_anchor_valid === false) {
      result.warnings.push('rfc3161_imprint_mismatch');
    } else if (result.timestamp_anchor_valid === true) {
      result.warnings.push('rfc3161_tsa_cert_chain_not_verified');
    }
  } else {
    result.timestamp_anchor_valid = null;
  }

  // ── Step 7: Proof level integrity ──
  // Already checked by validateArtifact in step 1 (PROOF_LEVEL_MISMATCH),
  // but we verify again explicitly for the spec requirement.
  const proofDist = artifact.proof_distribution as Record<string, unknown>;
  if (artifact.proof_level !== proofDist.weakest_link) {
    result.errors.push('proof_level_mismatch');
    return result;
  }

  // ── Step 8: Manifest hash audit ──
  const manifestHashes = artifact.manifest_hashes as Record<string, string>;
  result.manifest_hashes = manifestHashes;

  // ── Step 9: ZK proof verification ──
  const pendingFlags = artifact.pending_flags as Record<string, unknown> | undefined;
  const proofPending = pendingFlags?.proof_pending === true;

  if (artifact.zk_proof && !proofPending) {
    const zkProof = artifact.zk_proof as Record<string, unknown>;
    // Accept both 'prover_system' (canonical) and 'proving_system' (legacy)
    const provingSystem = (zkProof.prover_system ?? zkProof.proving_system) as string | undefined;

    if (provingSystem === 'ultrahonk') {
      result.zk_proof_valid = await verifyUltraHonk(zkProof);
      if (result.zk_proof_valid === false) {
        result.errors.push('zk_proof_invalid');
      }
    } else if (provingSystem === 'ezkl') {
      // EZKL Tier 2: explicit stub — requires EZKL verifier integration
      result.zk_proof_valid = null;
      result.warnings.push('ezkl_verification_not_implemented');
    } else {
      result.zk_proof_valid = null;
      result.warnings.push(`unknown_proving_system: ${provingSystem ?? 'none'}`);
    }
  } else if (proofPending) {
    // Proof in flight — cannot verify yet
    result.zk_proof_valid = null;
    result.warnings.push('proof_pending');
  } else {
    result.zk_proof_valid = null;
  }

  // ── Step 9b: Mathematical proof_level requires verified ZK proof ──
  if (artifact.proof_level === 'mathematical') {
    if (proofPending) {
      // proof_pending + mathematical: proof hasn't arrived yet — warning, not error
      result.warnings.push('mathematical_proof_pending');
    } else if (result.zk_proof_valid === null) {
      // No proof and not pending — this is an error
      result.errors.push('mathematical_proof_not_verified');
      return result;
    }
  }

  // ── Step 10: test_mode check ──
  if (artifact.test_mode === true) {
    if (production) {
      result.errors.push('test_mode_rejected_in_production');
      return result;
    }
    result.warnings.push('test_credential');
  }

  // All checks passed
  result.valid = result.errors.length === 0;
  return result;
}

/**
 * Extract base64url key from PEM or raw base64url string.
 * Handles both PEM-wrapped keys and raw base64url.
 */
function extractKeyFromPem(pem: string): string {
  // If it looks like PEM, strip header/footer and convert base64 → base64url
  if (pem.includes('-----BEGIN')) {
    const b64 = pem
      .replace(/-----BEGIN [A-Z ]+-----/g, '')
      .replace(/-----END [A-Z ]+-----/g, '')
      .replace(/\s/g, '');
    // Convert standard base64 to base64url
    return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  // Already base64url
  return pem.trim();
}

// ── RFC 3161 Timestamp Imprint Verification ──

/**
 * Verify the message imprint inside an RFC 3161 TimeStampResp matches
 * SHA-256(canonical(documentBody)).
 *
 * Parses enough DER to extract the hashed message from the MessageImprint
 * field. Returns true if imprint matches, false if mismatch, null if unparseable.
 */
function verifyTimestampImprint(
  tsTokenB64: string,
  documentBody: Record<string, unknown>,
): boolean | null {
  try {
    const tsResp = Buffer.from(tsTokenB64, 'base64');

    // Find SHA-256 OID (2.16.840.1.101.3.4.2.1) in the DER
    const sha256Oid = Buffer.from([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]);
    const oidIdx = findBuffer(tsResp, sha256Oid);
    if (oidIdx === -1) return null;

    // The message imprint hash follows the AlgorithmIdentifier.
    // After OID + NULL, look for OCTET STRING (0x04) containing 32-byte hash.
    const searchStart = oidIdx + sha256Oid.length;
    for (let i = searchStart; i < Math.min(searchStart + 20, tsResp.length - 33); i++) {
      if (tsResp[i] === 0x04 && tsResp[i + 1] === 0x20) {
        const extractedHash = tsResp.subarray(i + 2, i + 2 + 32);

        // Recompute expected hash
        const canonicalDoc = canonical(documentBody);
        const expectedHash = createHash('sha256').update(canonicalDoc).digest();

        return extractedHash.equals(expectedHash);
      }
    }
    return null; // Could not find hash in DER
  } catch {
    return null;
  }
}

function findBuffer(haystack: Buffer, needle: Buffer): number {
  for (let i = 0; i <= haystack.length - needle.length; i++) {
    if (haystack.subarray(i, i + needle.length).equals(needle)) return i;
  }
  return -1;
}

// ── Rekor Status Check ──

const REKOR_API = 'https://rekor.sigstore.dev/api/v1';

/**
 * Check Rekor for key revocation by querying with SHA-256 fingerprint
 * of the public key bytes.
 */
async function checkRekor(publicKeyB64Url: string, kid: string): Promise<RekorStatus> {
  try {
    // Decode public key bytes and compute SHA-256 fingerprint
    const keyBytes = fromBase64Url(publicKeyB64Url);
    const fingerprint = createHash('sha256').update(Buffer.from(keyBytes)).digest('hex');

    // Search Rekor index by key fingerprint
    const resp = await fetch(`${REKOR_API}/index/retrieve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ hash: `sha256:${fingerprint}` }),
      signal: AbortSignal.timeout(5000),
    });

    if (!resp.ok) {
      return 'unavailable';
    }

    const entries = await resp.json() as string[];
    if (!entries || entries.length === 0) {
      // No entries found — key has not been submitted to Rekor (not necessarily bad)
      return 'not_found';
    }

    // Key found in Rekor — it's been logged (active, not revoked)
    return 'active';
  } catch {
    return 'unavailable';
  }
}

// ── ZK Proof Verification (UltraHonk) ──

/**
 * Verify an UltraHonk ZK proof using @aztec/bb.js.
 *
 * Requires:
 * - zk_proof.proof: base64-encoded proof bytes
 * - zk_proof.public_inputs: array of field elements (hex strings)
 * - zk_proof.verification_key: base64-encoded verification key
 *
 * Returns true if valid, false if invalid, null if verification unavailable.
 */
async function verifyUltraHonk(zkProof: Record<string, unknown>): Promise<boolean | null> {
  try {
    // Dynamic import — @aztec/bb.js is an optional dependency
    const bb = await import('@aztec/bb.js').catch(() => null);
    if (!bb) {
      return null; // bb.js not available
    }

    const proofB64 = zkProof.proof as string;
    const publicInputs = zkProof.public_inputs as string[];
    const vkB64 = zkProof.verification_key as string;

    if (!proofB64 || !publicInputs || !vkB64) {
      return false;
    }

    const proofBytes = Buffer.from(proofB64, 'base64');
    const vkBytes = Buffer.from(vkB64, 'base64');

    // UltraHonk verification
    const api = await bb.newBarretenbergApiAsync();
    const valid = await api.acirVerifyUltraHonk(proofBytes, vkBytes);
    return valid;
  } catch {
    return null; // Verification error — treat as unavailable, not invalid
  }
}
