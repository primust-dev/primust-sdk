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

  // ── Step 5: Signer status check (Rekor — stubbed in v1) ──
  if (skip_network) {
    result.rekor_status = 'skipped';
  } else {
    // TODO: Integrate with Sigstore Rekor for key revocation events
    result.rekor_status = 'unavailable';
    result.warnings.push('rekor_check_not_implemented');
  }

  // ── Step 6: RFC 3161 timestamp verification (stubbed in v1) ──
  const tsAnchor = artifact.timestamp_anchor as Record<string, unknown> | undefined;
  if (tsAnchor && tsAnchor.type === 'rfc3161') {
    // TODO: Verify RFC 3161 token against TSA certificate chain
    result.timestamp_anchor_valid = null;
    result.warnings.push('rfc3161_verification_not_implemented');
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

  // ── Step 9: ZK proof verification (stubbed in v1) ──
  const pendingFlags = artifact.pending_flags as Record<string, unknown> | undefined;
  if (artifact.zk_proof && !(pendingFlags?.proof_pending)) {
    // TODO: Verify via Barretenberg WASM (ultrahonk) or EZKL
    result.zk_proof_valid = null;
    result.warnings.push('zk_proof_verification_not_implemented');
  } else {
    result.zk_proof_valid = null;
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
