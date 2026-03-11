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

import { sha256 } from '@noble/hashes/sha256';
import { canonical } from '@primust/artifact-core';
import type { PolicyBasis } from '@primust/artifact-core';
import type {
  PolicyPack,
  EffectiveCheck,
  Gap,
} from '@primust/runtime-core';
import type { SqliteStore } from '@primust/runtime-core';
import type { ManifestRegistry } from '@primust/registry';
import { computeManifestHash } from './manifest_validator.js';

// ── Helpers ──

function hexEncode(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

// ── Types ──

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

// ── Service ──

export class PolicySnapshotService {
  private store: SqliteStore;
  private registry: ManifestRegistry;
  private policyPacks: Map<string, PolicyPack>;

  constructor(
    store: SqliteStore,
    registry: ManifestRegistry,
    policyPacks: Map<string, PolicyPack>,
  ) {
    this.store = store;
    this.registry = registry;
    this.policyPacks = policyPacks;
  }

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
  openRun(params: OpenRunParams): OpenRunResult {
    // 1. Resolve policy pack
    const pack = this.policyPacks.get(params.policy_pack_id);
    if (!pack) {
      throw new Error(`PolicyPack not found: ${params.policy_pack_id}`);
    }

    // 2-3. Build effective checks
    const effectiveChecks: EffectiveCheck[] = [];
    const manifestHashes: Record<string, string> = {};

    for (const check of pack.checks) {
      const manifest = this.registry.getManifest(check.manifest_id);
      if (!manifest) {
        throw new Error(`Manifest not found: ${check.manifest_id}`);
      }

      const manifestHash = computeManifestHash(manifest);
      manifestHashes[check.manifest_id] = manifestHash;

      // Coverage denominator: override action_unit_count for per_action_unit scope
      let actionUnitCount: number | null = check.action_unit_count;
      if (check.evaluation_scope === 'per_action_unit') {
        actionUnitCount = params.action_unit_count;
      }

      effectiveChecks.push({
        check_id: check.check_id,
        manifest_id: check.manifest_id,
        manifest_hash: manifestHash,
        required: check.required,
        evaluation_scope: check.evaluation_scope,
        action_unit_count: actionUnitCount,
      });
    }

    // 4. Compute snapshot hash (deterministic: sort by check_id)
    const sortedChecks = [...effectiveChecks].sort((a, b) =>
      a.check_id.localeCompare(b.check_id),
    );
    const snapshotContent = canonical(sortedChecks);
    const hashBytes = sha256(new TextEncoder().encode(snapshotContent));
    const snapshotHash = 'sha256:' + hexEncode(hashBytes);

    // 5. Write immutable PolicySnapshot
    const snapshotAt = new Date().toISOString();

    this.store.writePolicySnapshot({
      snapshot_id: snapshotHash,
      policy_pack_id: pack.policy_pack_id,
      policy_pack_version: pack.version,
      effective_checks: effectiveChecks as unknown as Record<string, unknown>[],
      snapshotted_at: snapshotAt,
      policy_basis: params.policy_basis ?? 'P1_self_declared',
    });

    // 6. Open process run with drift detection
    const runId = `run_${crypto.randomUUID()}`;

    this.store.openRun({
      run_id: runId,
      workflow_id: params.workflow_id,
      org_id: params.org_id,
      surface_id: params.surface_id,
      policy_snapshot_hash: snapshotHash,
      process_context_hash: params.process_context_hash ?? null,
      action_unit_count: params.action_unit_count,
      ttl_seconds: params.ttl_seconds ?? 3600,
      manifest_hashes: manifestHashes,
    });

    return {
      run_id: runId,
      policy_snapshot_hash: snapshotHash,
    };
  }
}
