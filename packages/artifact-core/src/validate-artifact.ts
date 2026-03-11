/**
 * VPEC Artifact validation — enforces all critical invariants.
 *
 * This is structural/semantic validation beyond what JSON Schema covers.
 * JSON Schema handles type checks; this function enforces cross-field invariants.
 */

import type { VPECArtifact, ProofLevel } from './types/artifact.js';

export interface ValidationError {
  code: string;
  message: string;
  path?: string;
}

export interface ValidationResult {
  valid: boolean;
  errors: ValidationError[];
}

const PROOF_LEVELS: ProofLevel[] = [
  'mathematical',
  'execution_zkml',
  'execution',
  'witnessed',
  'attestation',
];

const GAP_TYPES = new Set([
  'check_not_executed',
  'enforcement_override',
  'engine_error',
  'check_degraded',
  'external_boundary_traversal',
  'lineage_token_missing',
  'admission_gate_override',
  'check_timing_suspect',
  'reviewer_credential_invalid',
  'witnessed_display_missing',
  'witnessed_rationale_missing',
  'deterministic_consistency_violation',
  'skip_rationale_missing',
  'policy_config_drift',
  'zkml_proof_pending_timeout',
  'zkml_proof_failed',
]);

const GAP_SEVERITIES = new Set(['Critical', 'High', 'Medium', 'Low', 'Informational']);

const PUBLIC_KEY_URL_PATTERN = /^https:\/\/primust\.com\/\.well-known\/primust-pubkeys\/.+\.pem$/;

/**
 * Validate a VPEC artifact against all critical invariants.
 *
 * @param artifact - The artifact payload (parsed JSON)
 * @returns ValidationResult with errors if any invariants are violated
 */
export function validateArtifact(artifact: Record<string, unknown>): ValidationResult {
  const errors: ValidationError[] = [];

  // Invariant 2: reliance_mode field ANYWHERE → validation error
  if ('reliance_mode' in artifact) {
    errors.push({
      code: 'RELIANCE_MODE_FORBIDDEN',
      message: 'reliance_mode field is forbidden in VPEC artifacts',
      path: 'reliance_mode',
    });
  }
  checkNestedRelianceMode(artifact, '', errors);

  // schema_version must be 3.0.0
  if (artifact.schema_version !== '3.0.0') {
    errors.push({
      code: 'INVALID_SCHEMA_VERSION',
      message: `schema_version must be "3.0.0", got "${artifact.schema_version}"`,
      path: 'schema_version',
    });
  }

  // Invariant 1: proof_level MUST equal proof_distribution.weakest_link
  const proofDist = artifact.proof_distribution as Record<string, unknown> | undefined;
  if (proofDist && artifact.proof_level !== proofDist.weakest_link) {
    errors.push({
      code: 'PROOF_LEVEL_MISMATCH',
      message: `proof_level "${artifact.proof_level}" does not match proof_distribution.weakest_link "${proofDist.weakest_link}"`,
      path: 'proof_level',
    });
  }

  // Validate proof_level is a valid enum value
  if (artifact.proof_level && !PROOF_LEVELS.includes(artifact.proof_level as ProofLevel)) {
    errors.push({
      code: 'INVALID_PROOF_LEVEL',
      message: `proof_level "${artifact.proof_level}" is not a valid proof level`,
      path: 'proof_level',
    });
  }

  // Invariant 3: manifest_hashes MUST be object (map), not array
  if (Array.isArray(artifact.manifest_hashes)) {
    errors.push({
      code: 'MANIFEST_HASHES_NOT_MAP',
      message: 'manifest_hashes must be an object (map), not an array',
      path: 'manifest_hashes',
    });
  }

  // Invariant 4: gaps[] entries MUST have gap_type and severity
  const gaps = artifact.gaps;
  if (Array.isArray(gaps)) {
    for (let i = 0; i < gaps.length; i++) {
      const gap = gaps[i] as Record<string, unknown>;

      if (typeof gap === 'string') {
        errors.push({
          code: 'GAP_BARE_STRING',
          message: `gaps[${i}] is a bare string — must be an object with gap_type and severity`,
          path: `gaps[${i}]`,
        });
        continue;
      }

      if (typeof gap !== 'object' || gap === null) {
        errors.push({
          code: 'GAP_INVALID_TYPE',
          message: `gaps[${i}] must be an object with gap_type and severity`,
          path: `gaps[${i}]`,
        });
        continue;
      }

      if (!gap.gap_type || !gap.severity) {
        errors.push({
          code: 'GAP_MISSING_FIELDS',
          message: `gaps[${i}] must have gap_type and severity fields`,
          path: `gaps[${i}]`,
        });
      }

      if (gap.gap_type && !GAP_TYPES.has(gap.gap_type as string)) {
        errors.push({
          code: 'GAP_INVALID_TYPE_VALUE',
          message: `gaps[${i}].gap_type "${gap.gap_type}" is not a valid gap type`,
          path: `gaps[${i}].gap_type`,
        });
      }

      if (gap.severity && !GAP_SEVERITIES.has(gap.severity as string)) {
        errors.push({
          code: 'GAP_INVALID_SEVERITY',
          message: `gaps[${i}].severity "${gap.severity}" is not a valid severity`,
          path: `gaps[${i}].severity`,
        });
      }
    }
  }

  // Invariant 5: partial: true → policy_coverage_pct must be 0
  const coverage = artifact.coverage as Record<string, unknown> | undefined;
  if (artifact.partial === true && coverage) {
    if (typeof coverage.policy_coverage_pct === 'number' && coverage.policy_coverage_pct !== 0) {
      errors.push({
        code: 'PARTIAL_COVERAGE_NOT_ZERO',
        message: `partial: true requires policy_coverage_pct to be 0, got ${coverage.policy_coverage_pct}`,
        path: 'coverage.policy_coverage_pct',
      });
    }
  }

  // Invariant 7: issuer.public_key_url must match primust.com/.well-known/ pattern
  const issuer = artifact.issuer as Record<string, unknown> | undefined;
  if (issuer && typeof issuer.public_key_url === 'string') {
    if (!PUBLIC_KEY_URL_PATTERN.test(issuer.public_key_url)) {
      errors.push({
        code: 'ISSUER_URL_INVALID',
        message: `issuer.public_key_url must match https://primust.com/.well-known/primust-pubkeys/*.pem, got "${issuer.public_key_url}"`,
        path: 'issuer.public_key_url',
      });
    }
  }

  return { valid: errors.length === 0, errors };
}

/** Recursively check for reliance_mode in any nested object */
function checkNestedRelianceMode(
  obj: Record<string, unknown>,
  path: string,
  errors: ValidationError[],
): void {
  for (const [key, value] of Object.entries(obj)) {
    const currentPath = path ? `${path}.${key}` : key;
    if (key === 'reliance_mode' && currentPath !== 'reliance_mode') {
      errors.push({
        code: 'RELIANCE_MODE_FORBIDDEN',
        message: `reliance_mode field is forbidden in VPEC artifacts (found at ${currentPath})`,
        path: currentPath,
      });
    }
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      checkNestedRelianceMode(value as Record<string, unknown>, currentPath, errors);
    }
  }
}
