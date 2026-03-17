/**
 * @primust/sdk/verify — Ed25519 signature verification for VPEC artifacts.
 *
 * Re-exports verification primitives from @primust/artifact-core and provides
 * a high-level verifyVpec() function for verifying signed VPEC JSON objects.
 */

import {
  verify as ed25519Verify,
  validateArtifact,
  fromBase64Url,
} from '@primust/artifact-core';
import type {
  SignatureEnvelope,
  ValidationResult,
} from '@primust/artifact-core';

export { ed25519Verify as verifySignature, validateArtifact, fromBase64Url };
export type { SignatureEnvelope, ValidationResult };

export interface VerifyVpecOptions {
  /** Reject artifacts with test_mode: true (production enforcement). */
  production?: boolean;
}

export interface VerifyVpecResult {
  /** Whether the VPEC passed all verification checks. */
  valid: boolean;
  /** Specific validation errors, if any. */
  errors: string[];
  /** Warnings (e.g. test_mode in non-production context). */
  warnings: string[];
}

/**
 * Verify a signed VPEC artifact.
 *
 * Steps:
 *   1. Validate artifact structure (schema invariants).
 *   2. Verify Ed25519 signature against the provided public key.
 *   3. Optionally reject test_mode artifacts in production mode.
 *
 * @param vpec - The VPEC artifact JSON object (without the signature envelope).
 * @param signatureEnvelope - The signature envelope from the artifact.
 * @param publicKeyB64Url - Base64url-encoded Ed25519 public key of the issuer.
 * @param options - Verification options.
 */
export function verifyVpec(
  vpec: Record<string, unknown>,
  signatureEnvelope: SignatureEnvelope,
  publicKeyB64Url: string,
  options: VerifyVpecOptions = {},
): VerifyVpecResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  // Step 1: Structural validation
  const structuralResult: ValidationResult = validateArtifact(vpec);
  if (!structuralResult.valid) {
    for (const err of structuralResult.errors) {
      errors.push(`${err.path}: ${err.message}`);
    }
  }

  // Step 2: Cryptographic signature verification
  const sigValid = ed25519Verify(vpec, signatureEnvelope, publicKeyB64Url);
  if (!sigValid) {
    errors.push('Ed25519 signature verification failed');
  }

  // Step 3: test_mode enforcement
  const testMode = (vpec as Record<string, unknown>).test_mode;
  if (testMode === true) {
    if (options.production) {
      errors.push('test_mode: true rejected in production mode');
    } else {
      warnings.push('Artifact has test_mode: true — not valid for production audit');
    }
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
  };
}
