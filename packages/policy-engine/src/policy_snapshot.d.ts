/**
 * Primust Policy Engine — Policy Snapshot Binding
 *
 * PolicySnapshotService.openRun() orchestrates:
 * 1. Resolve PolicyPack → manifest_ids → CheckManifests
 * 2. Build EffectiveCheck[] with manifest_hash per check
 * 3. Compute snapshot_hash = SHA256(canonical(sorted effective_checks))
 * 4. Write immutable PolicySnapshot to store
 * 5. Open ProcessRun with drift detection
 */
import type { PolicyBasis } from '@primust/artifact-core';
import type { PolicyPack } from '@primust/runtime-core';
import type { SqliteStore } from '@primust/runtime-core';
import type { ManifestRegistry } from '@primust/registry';
export interface OpenRunParams {
    workflow_id: string;
    surface_id: string;
    policy_pack_id: string;
    org_id: string;
    process_context_hash?: string | null;
    action_unit_count: number;
    ttl_seconds?: number;
    policy_basis?: PolicyBasis;
}
export interface OpenRunResult {
    run_id: string;
    policy_snapshot_hash: string;
}
export declare class PolicySnapshotService {
    private store;
    private registry;
    private policyPacks;
    constructor(store: SqliteStore, registry: ManifestRegistry, policyPacks: Map<string, PolicyPack>);
    /**
     * Open a new process run with policy snapshot binding.
     *
     * 1. Resolve PolicyPack by policy_pack_id
     * 2. Resolve each manifest_id → CheckManifest, compute manifest_hash
     * 3. Build EffectiveCheck[] (override action_unit_count for per_action_unit scope)
     * 4. Compute snapshot_hash = SHA256(canonical(sorted effective_checks))
     * 5. Write PolicySnapshot (immutable via INSERT OR IGNORE)
     * 6. Open ProcessRun with drift detection via manifest_hashes
     */
    openRun(params: OpenRunParams): OpenRunResult;
}
//# sourceMappingURL=policy_snapshot.d.ts.map