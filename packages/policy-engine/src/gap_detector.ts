/**
 * Primust Policy Engine — Gap Detection at Run Close (P7-B)
 *
 * detectGaps() scans all CheckExecutionRecords for a run and detects
 * all 15 canonical gap types. Pass-through gaps (already stored) are
 * loaded from the store; per-record gaps are detected inline.
 *
 * GAP SEVERITY RULES:
 *   Never downgrade Critical or High gaps.
 *   Multiple gaps of same type on same run → one gap record per occurrence.
 */

import type { SqliteStore } from '@primust/runtime-core';
import type {
  CheckExecutionRecord,
  Gap,
  PolicySnapshot,
  EffectiveCheck,
  ReviewerCredential,
} from '@primust/runtime-core';
import type { GapType, GapSeverity } from '@primust/artifact-core';

// ── Canonical Gap Severity Map ──

const GAP_SEVERITY: Record<string, GapSeverity> = {
  check_not_executed: 'High',
  enforcement_override: 'Critical',
  engine_error: 'Medium',
  check_degraded: 'Low',
  external_boundary_traversal: 'Informational',
  lineage_token_missing: 'High',
  admission_gate_override: 'Critical',
  check_timing_suspect: 'Medium',
  reviewer_credential_invalid: 'Critical',
  witnessed_display_missing: 'High',
  witnessed_rationale_missing: 'High',
  deterministic_consistency_violation: 'Critical',
  skip_rationale_missing: 'High',
  policy_config_drift: 'Medium',
  zkml_proof_pending_timeout: 'High',
  zkml_proof_failed: 'Critical',
};

// ── Helpers ──

function makeGap(
  runId: string,
  gapType: GapType,
  details: Record<string, unknown> = {},
): Gap {
  const suffix = crypto.randomUUID().slice(0, 8);
  return {
    gap_id: `gap_${gapType}_${runId}_${suffix}`,
    run_id: runId,
    gap_type: gapType,
    severity: GAP_SEVERITY[gapType] ?? 'Medium',
    state: 'open',
    details,
    detected_at: new Date().toISOString(),
    resolved_at: null,
  };
}

// ── Main ──

/**
 * Detect all gaps for a run.
 *
 * @param runId - The run to detect gaps for
 * @param store - SqliteStore instance
 * @param policySnapshot - Optional PolicySnapshot for check_not_executed detection
 * @param manifests - Optional map of manifest_id → { implementation_type } for timing checks
 * @returns Array of detected Gap objects
 */
export function detectGaps(
  runId: string,
  store: SqliteStore,
  policySnapshot?: PolicySnapshot | null,
  manifests?: Map<string, { implementation_type: string }>,
): Gap[] {
  const gaps: Gap[] = [];

  // Load existing check records
  const rawRecords = store.getCheckRecords(runId);
  const records = rawRecords as unknown as CheckExecutionRecord[];

  // 1. check_not_executed — required check in policy that has no record
  if (policySnapshot) {
    const recordedManifestIds = new Set(records.map((r) => r.manifest_id));
    for (const check of policySnapshot.effective_checks) {
      if (check.required && !recordedManifestIds.has(check.manifest_id)) {
        gaps.push(
          makeGap(runId, 'check_not_executed', {
            manifest_id: check.manifest_id,
            check_id: check.check_id,
          }),
        );
      }
    }
  }

  // Per-record gap detection
  for (const record of records) {
    // enforcement_override — check_result = "override"
    if (record.check_result === 'override') {
      gaps.push(
        makeGap(runId, 'enforcement_override', {
          record_id: record.record_id,
          manifest_id: record.manifest_id,
        }),
      );
    }

    // engine_error — check_result = "error"
    if (record.check_result === 'error') {
      gaps.push(
        makeGap(runId, 'engine_error', {
          record_id: record.record_id,
          manifest_id: record.manifest_id,
        }),
      );
    }

    // check_degraded — check_result = "degraded"
    if (record.check_result === 'degraded') {
      gaps.push(
        makeGap(runId, 'check_degraded', {
          record_id: record.record_id,
          manifest_id: record.manifest_id,
        }),
      );
    }

    // skip_rationale_missing — not_applicable without skip_rationale_hash
    if (
      record.check_result === 'not_applicable' &&
      !record.skip_rationale_hash
    ) {
      gaps.push(
        makeGap(runId, 'skip_rationale_missing', {
          record_id: record.record_id,
          manifest_id: record.manifest_id,
        }),
      );
    }

    // check_timing_suspect — ml_model/zkml_model with < 100ms duration
    if (record.check_open_tst && record.check_close_tst) {
      const implType = manifests?.get(record.manifest_id)?.implementation_type;
      if (implType === 'ml_model' || implType === 'zkml_model') {
        const openTime = new Date(record.check_open_tst).getTime();
        const closeTime = new Date(record.check_close_tst).getTime();
        if (!isNaN(openTime) && !isNaN(closeTime) && closeTime - openTime < 100) {
          gaps.push(
            makeGap(runId, 'check_timing_suspect', {
              record_id: record.record_id,
              manifest_id: record.manifest_id,
              duration_ms: closeTime - openTime,
            }),
          );
        }
      }
    }

    // Witnessed record gaps
    if (record.proof_level_achieved === 'witnessed') {
      const cred = record.reviewer_credential as ReviewerCredential | null;
      if (cred) {
        // witnessed_display_missing
        if (!cred.display_hash) {
          gaps.push(
            makeGap(runId, 'witnessed_display_missing', {
              record_id: record.record_id,
            }),
          );
        }

        // witnessed_rationale_missing
        if (!cred.rationale_hash) {
          gaps.push(
            makeGap(runId, 'witnessed_rationale_missing', {
              record_id: record.record_id,
            }),
          );
        }

        // reviewer_credential_invalid — stub: check signature field exists
        if (!cred.reviewer_signature) {
          gaps.push(
            makeGap(runId, 'reviewer_credential_invalid', {
              record_id: record.record_id,
              reason: 'missing_signature',
            }),
          );
        }
      }
    }
  }

  // deterministic_consistency_violation — same commitment_hash + manifest, different result
  const commitmentMap = new Map<string, string>(); // "commitment_hash|manifest_id" → check_result
  for (const record of records) {
    const key = `${record.commitment_hash}|${record.manifest_id}`;
    const prev = commitmentMap.get(key);
    if (prev !== undefined && prev !== record.check_result) {
      gaps.push(
        makeGap(runId, 'deterministic_consistency_violation', {
          manifest_id: record.manifest_id,
          commitment_hash: record.commitment_hash,
          results: [prev, record.check_result],
        }),
      );
    }
    if (prev === undefined) {
      commitmentMap.set(key, record.check_result);
    }
  }

  // Pass-through gaps — load existing gaps from store
  // These were already detected and stored by other components:
  // external_boundary_traversal, lineage_token_missing, admission_gate_override,
  // policy_config_drift, zkml_proof_pending_timeout, zkml_proof_failed
  const existingGaps = store.getGaps(runId) as unknown as Gap[];
  const PASS_THROUGH_TYPES = new Set<string>([
    'external_boundary_traversal',
    'lineage_token_missing',
    'admission_gate_override',
    'policy_config_drift',
    'zkml_proof_pending_timeout',
    'zkml_proof_failed',
  ]);

  for (const existing of existingGaps) {
    if (PASS_THROUGH_TYPES.has(existing.gap_type)) {
      gaps.push(existing);
    }
  }

  // Store newly detected gaps
  for (const gap of gaps) {
    if (!existingGaps.some((e) => e.gap_id === gap.gap_id)) {
      store.insertGap(gap);
    }
  }

  return gaps;
}

/** Get the canonical severity for a gap type. */
export function getGapSeverity(gapType: string): GapSeverity {
  return GAP_SEVERITY[gapType] ?? 'Medium';
}

/** All 15 canonical gap types (excluding api_unavailable which is API-layer only). */
export const CANONICAL_GAP_TYPES: GapType[] = [
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
];
