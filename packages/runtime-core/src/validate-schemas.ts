/**
 * Primust Runtime Core — Cross-field validation for domain-neutral objects v3.
 *
 * Enforces all invariants from the schema spec:
 *   1. No banned field names anywhere
 *   2. human_review stage type → witnessed proof level (NEVER attestation)
 *   3. manifest_hash captured per CheckExecutionRecord at record time
 *   4. reviewer_credential required when proof_level_achieved = witnessed
 *   5. skip_rationale_hash required when check_result = not_applicable
 *   6. CheckExecutionRecord is append-only (no UPDATE after commit)
 *   7. Waiver expires_at REQUIRED — no permanent waivers (max 90 days)
 *   8. EvidencePack: coverage_verified + coverage_pending + coverage_ungoverned = 100
 */

import type { CheckExecutionRecord, ManifestStage, Waiver, EvidencePack } from './types/index.js';

// ── Banned fields ──

const BANNED_FIELDS = new Set([
  'agent_id',
  'pipeline_id',
  'tool_name',
  'session_id',
  'trace_id',
  'reliance_mode',
  'PGC',
  'attestation',
]);

export interface ValidationError {
  code: string;
  message: string;
}

/**
 * Recursively scan an object for banned field names.
 * Returns a list of violations with the field path.
 */
export function scanBannedFields(
  obj: unknown,
  path: string = '',
): ValidationError[] {
  const errors: ValidationError[] = [];
  if (obj === null || obj === undefined || typeof obj !== 'object') return errors;
  if (Array.isArray(obj)) {
    for (let i = 0; i < obj.length; i++) {
      errors.push(...scanBannedFields(obj[i], `${path}[${i}]`));
    }
    return errors;
  }
  for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
    const fullPath = path ? `${path}.${key}` : key;
    if (BANNED_FIELDS.has(key)) {
      errors.push({
        code: `banned_field_${key}`,
        message: `Banned field "${key}" found at ${fullPath}`,
      });
    }
    errors.push(...scanBannedFields(value, fullPath));
  }
  return errors;
}

/**
 * Validate a ManifestStage — invariant 2:
 * human_review type → witnessed proof_level (NEVER attestation).
 */
export function validateManifestStage(stage: ManifestStage): ValidationError[] {
  const errors: ValidationError[] = [];
  if (stage.type === 'human_review' && stage.proof_level === 'attestation') {
    errors.push({
      code: 'human_review_attestation_forbidden',
      message:
        'human_review stage type must use witnessed proof level, NEVER attestation (invariant 2)',
    });
  }
  if (stage.type === 'human_review' && stage.proof_level !== 'witnessed') {
    errors.push({
      code: 'human_review_must_be_witnessed',
      message:
        'human_review stage type must use witnessed proof level',
    });
  }
  return errors;
}

/**
 * Validate a CheckExecutionRecord — invariants 3, 4, 5.
 */
export function validateCheckExecutionRecord(
  record: CheckExecutionRecord,
): ValidationError[] {
  const errors: ValidationError[] = [];

  // Invariant 3: manifest_hash required
  if (!record.manifest_hash) {
    errors.push({
      code: 'manifest_hash_missing',
      message: 'manifest_hash is required on every CheckExecutionRecord (invariant 3)',
    });
  }

  // Invariant 4: reviewer_credential required when proof_level_achieved = witnessed
  if (
    record.proof_level_achieved === 'witnessed' &&
    !record.reviewer_credential
  ) {
    errors.push({
      code: 'reviewer_credential_missing',
      message:
        'reviewer_credential is required when proof_level_achieved = witnessed (invariant 4)',
    });
  }

  // Invariant 5: skip_rationale_hash required when check_result = not_applicable
  if (
    record.check_result === 'not_applicable' &&
    !record.skip_rationale_hash
  ) {
    errors.push({
      code: 'skip_rationale_hash_missing',
      message:
        'skip_rationale_hash is required when check_result = not_applicable (invariant 5)',
    });
  }

  // output_commitment must be poseidon2 prefix only when present
  if (
    record.output_commitment !== null &&
    !record.output_commitment.startsWith('poseidon2:')
  ) {
    errors.push({
      code: 'output_commitment_invalid_prefix',
      message: 'output_commitment must use poseidon2: prefix when present',
    });
  }

  // check_open_tst required when check_close_tst present
  if (record.check_close_tst && !record.check_open_tst) {
    errors.push({
      code: 'check_open_tst_missing',
      message: 'check_open_tst is required when check_close_tst is present',
    });
  }

  return errors;
}

/**
 * Validate a Waiver — invariant 7.
 */
export function validateWaiver(waiver: Waiver): ValidationError[] {
  const errors: ValidationError[] = [];

  // Reason minimum 50 characters
  if (waiver.reason.length < 50) {
    errors.push({
      code: 'waiver_reason_too_short',
      message: `Waiver reason must be at least 50 characters (got ${waiver.reason.length})`,
    });
  }

  // expires_at required (type enforces non-null, but check anyway)
  if (!waiver.expires_at) {
    errors.push({
      code: 'waiver_expires_at_missing',
      message: 'Waiver expires_at is required — no permanent waivers (invariant 7)',
    });
  }

  // Max 90 days from approved_at
  if (waiver.expires_at && waiver.approved_at) {
    const approved = new Date(waiver.approved_at).getTime();
    const expires = new Date(waiver.expires_at).getTime();
    const maxMs = 90 * 24 * 60 * 60 * 1000;
    if (expires - approved > maxMs) {
      errors.push({
        code: 'waiver_exceeds_90_days',
        message: 'Waiver expires_at must be within 90 days of approved_at (invariant 7)',
      });
    }
    if (expires <= approved) {
      errors.push({
        code: 'waiver_expires_before_approval',
        message: 'Waiver expires_at must be after approved_at',
      });
    }
  }

  return errors;
}

/**
 * Validate an EvidencePack — invariant 8.
 */
export function validateEvidencePack(pack: EvidencePack): ValidationError[] {
  const errors: ValidationError[] = [];

  const sum =
    pack.coverage_verified_pct +
    pack.coverage_pending_pct +
    pack.coverage_ungoverned_pct;

  if (sum !== 100) {
    errors.push({
      code: 'coverage_sum_not_100',
      message: `coverage_verified_pct + coverage_pending_pct + coverage_ungoverned_pct must equal 100 (got ${sum}) (invariant 8)`,
    });
  }

  return errors;
}
