/**
 * Primust Policy Engine — Gap Detection at Run Close (P7-B)
 *
 * detectGaps() scans all CheckExecutionRecords for a run and detects
 * all 18 canonical gap types. Pass-through gaps (already stored) are
 * loaded from the store; per-record gaps are detected inline.
 *
 * GAP SEVERITY RULES:
 *   Never downgrade Critical or High gaps.
 *   Multiple gaps of same type on same run → one gap record per occurrence.
 */
import type { SqliteStore } from '@primust/runtime-core';
import type { Gap, PolicySnapshot, ComplianceRequirements } from '@primust/runtime-core';
import type { GapType, GapSeverity } from '@primust/artifact-core';
/**
 * Detect all gaps for a run.
 *
 * @param runId - The run to detect gaps for
 * @param store - SqliteStore instance
 * @param policySnapshot - Optional PolicySnapshot for check_not_executed detection
 * @param manifests - Optional map of manifest_id → { implementation_type } for timing checks
 * @returns Array of detected Gap objects
 */
export declare function detectGaps(runId: string, store: SqliteStore, policySnapshot?: PolicySnapshot | null, manifests?: Map<string, {
    implementation_type: string;
}>, complianceRequirements?: ComplianceRequirements | null): Gap[];
/** Get the canonical severity for a gap type. */
export declare function getGapSeverity(gapType: string): GapSeverity;
/** All 18 canonical gap types. */
export declare const CANONICAL_GAP_TYPES: GapType[];
//# sourceMappingURL=gap_detector.d.ts.map