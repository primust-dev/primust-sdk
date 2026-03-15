import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { PolicySnapshotService } from './policy_snapshot.js';
import { SqliteStore } from '@primust/runtime-core';
import { ManifestRegistry } from '@primust/registry';
// ── Helpers ──
function makeManifest(overrides = {}) {
    return {
        manifest_id: 'placeholder',
        manifest_hash: 'sha256:' + 'a'.repeat(64),
        domain: 'ai_agent',
        name: 'test_check',
        semantic_version: '1.0.0',
        check_type: 'safety_check',
        implementation_type: 'rule',
        supported_proof_level: 'execution',
        evaluation_scope: 'per_run',
        evaluation_window_seconds: null,
        stages: [
            {
                stage: 1,
                name: 'ML Eval',
                type: 'ml_model',
                proof_level: 'execution',
                redacted: false,
            },
        ],
        aggregation_config: {
            method: 'all_stages_must_pass',
            threshold: null,
        },
        freshness_threshold_hours: null,
        benchmark: null,
        model_or_tool_hash: null,
        publisher: 'primust',
        signer_id: 'signer_test',
        kid: 'kid_test',
        signed_at: '2026-03-10T00:00:00Z',
        signature: {
            signer_id: 'signer_test',
            kid: 'kid_test',
            algorithm: 'Ed25519',
            signature: 'sig_placeholder',
            signed_at: '2026-03-10T00:00:00Z',
        },
        ...overrides,
    };
}
function makePolicyPack(manifestIds) {
    return {
        policy_pack_id: 'pp_001',
        org_id: 'org_test',
        name: 'Test Pack',
        version: '1.0.0',
        checks: manifestIds.map((mid, i) => ({
            check_id: `check_${i + 1}`,
            manifest_id: mid,
            required: true,
            evaluation_scope: 'per_run',
            action_unit_count: null,
        })),
        created_at: '2026-03-10T00:00:00Z',
        signer_id: 'signer_test',
        kid: 'kid_test',
        signature: {
            signer_id: 'signer_test',
            kid: 'kid_test',
            algorithm: 'Ed25519',
            signature: 'sig_placeholder',
            signed_at: '2026-03-10T00:00:00Z',
        },
    };
}
// ── Tests ──
describe('PolicySnapshotService', () => {
    let store;
    let registry;
    let policyPacks;
    beforeEach(() => {
        store = new SqliteStore(':memory:');
        registry = new ManifestRegistry();
        policyPacks = new Map();
    });
    afterEach(() => {
        store.close();
    });
    // ── MUST PASS: snapshot unchanged after policy edit ──
    it('edit policy after run open → snapshot unchanged', () => {
        // Register manifest and create policy pack
        const manifest = makeManifest();
        const regResult = registry.registerManifest(manifest);
        const pack = makePolicyPack([regResult.manifest_id]);
        policyPacks.set(pack.policy_pack_id, pack);
        const service = new PolicySnapshotService(store, registry, policyPacks);
        const { policy_snapshot_hash } = service.openRun({
            workflow_id: 'wf_001',
            surface_id: 'surf_001',
            policy_pack_id: 'pp_001',
            org_id: 'org_test',
            action_unit_count: 5,
        });
        // Read the snapshot from the store
        const snapshot = store.getPolicySnapshot(policy_snapshot_hash);
        expect(snapshot).not.toBeNull();
        const originalChecks = snapshot.effective_checks;
        // Mutate the policy pack (add a new check)
        const manifest2 = makeManifest({ name: 'new_check' });
        const regResult2 = registry.registerManifest(manifest2);
        pack.checks.push({
            check_id: 'check_new',
            manifest_id: regResult2.manifest_id,
            required: true,
            evaluation_scope: 'per_run',
            action_unit_count: null,
        });
        // Snapshot in DB should be unchanged
        const snapshotAfter = store.getPolicySnapshot(policy_snapshot_hash);
        expect(snapshotAfter.effective_checks).toEqual(originalChecks);
    });
    // ── MUST PASS: same inputs → same hash ──
    it('same policy pack and version → same snapshot_hash', () => {
        const manifest = makeManifest();
        const regResult = registry.registerManifest(manifest);
        const pack = makePolicyPack([regResult.manifest_id]);
        policyPacks.set(pack.policy_pack_id, pack);
        const service = new PolicySnapshotService(store, registry, policyPacks);
        const result1 = service.openRun({
            workflow_id: 'wf_001',
            surface_id: 'surf_001',
            policy_pack_id: 'pp_001',
            org_id: 'org_test',
            action_unit_count: 5,
        });
        const result2 = service.openRun({
            workflow_id: 'wf_002',
            surface_id: 'surf_001',
            policy_pack_id: 'pp_001',
            org_id: 'org_test',
            action_unit_count: 5,
        });
        expect(result1.policy_snapshot_hash).toBe(result2.policy_snapshot_hash);
        expect(result1.run_id).not.toBe(result2.run_id); // different run_ids
    });
    // ── MUST PASS: drift gap on manifest_hash change ──
    it('manifest_hash changes between runs → policy_config_drift gap emitted', () => {
        // Register manifest and create policy pack
        const manifest = makeManifest();
        const regResult = registry.registerManifest(manifest);
        const manifestId = regResult.manifest_id;
        const pack = makePolicyPack([manifestId]);
        policyPacks.set(pack.policy_pack_id, pack);
        const service = new PolicySnapshotService(store, registry, policyPacks);
        // Open run1 via the service
        const result1 = service.openRun({
            workflow_id: 'wf_drift',
            surface_id: 'surf_001',
            policy_pack_id: 'pp_001',
            org_id: 'org_test',
            action_unit_count: 5,
        });
        // Append a check record to run1 with a DIFFERENT manifest_hash
        // (simulating a prior state where the manifest had different content)
        const oldHash = 'sha256:' + '1'.repeat(64);
        store.appendCheckRecord({
            record_id: 'rec_001',
            run_id: result1.run_id,
            action_unit_id: 'au_1',
            manifest_id: manifestId,
            manifest_hash: oldHash,
            surface_id: 'surf_001',
            commitment_hash: 'poseidon2:' + 'b'.repeat(64),
            output_commitment: null,
            commitment_algorithm: 'poseidon2',
            commitment_type: 'input_commitment',
            check_result: 'pass',
            proof_level_achieved: 'execution',
            proof_pending: false,
            zkml_proof_pending: false,
            check_open_tst: null,
            check_close_tst: null,
            skip_rationale_hash: null,
            reviewer_credential: null,
            unverified_provenance: false,
            freshness_warning: false,
            idempotency_key: 'idem_001',
            recorded_at: '2026-03-10T00:00:00Z',
        });
        // Close run1
        store.closeRun(result1.run_id, 'closed');
        // Open run2 with same manifest_id but current (different) manifest_hash
        // Drift should be detected because run1's check record has oldHash
        const result2 = service.openRun({
            workflow_id: 'wf_drift',
            surface_id: 'surf_001',
            policy_pack_id: 'pp_001',
            org_id: 'org_test',
            action_unit_count: 5,
        });
        // Drift gap should be emitted
        const gaps = store.getGaps(result2.run_id);
        const driftGap = gaps.find((g) => g.gap_type === 'policy_config_drift');
        expect(driftGap).not.toBeNull();
        expect(driftGap.severity).toBe('Medium');
    });
    // ── MUST PASS: per_action_unit denominator ──
    it('per_action_unit check on 10-action run → denominator = 10', () => {
        const manifest = makeManifest();
        const regResult = registry.registerManifest(manifest);
        const pack = {
            ...makePolicyPack([regResult.manifest_id]),
            checks: [
                {
                    check_id: 'check_per_au',
                    manifest_id: regResult.manifest_id,
                    required: true,
                    evaluation_scope: 'per_action_unit',
                    action_unit_count: null,
                },
            ],
        };
        policyPacks.set(pack.policy_pack_id, pack);
        const service = new PolicySnapshotService(store, registry, policyPacks);
        const { policy_snapshot_hash } = service.openRun({
            workflow_id: 'wf_001',
            surface_id: 'surf_001',
            policy_pack_id: 'pp_001',
            org_id: 'org_test',
            action_unit_count: 10,
        });
        const snapshot = store.getPolicySnapshot(policy_snapshot_hash);
        expect(snapshot).not.toBeNull();
        const checks = snapshot.effective_checks;
        expect(checks[0].action_unit_count).toBe(10);
    });
    // ── MUST PASS: process_context_hash stored ──
    it('process_context_hash stored on ProcessRun when provided', () => {
        const manifest = makeManifest();
        const regResult = registry.registerManifest(manifest);
        const pack = makePolicyPack([regResult.manifest_id]);
        policyPacks.set(pack.policy_pack_id, pack);
        const contextHash = 'sha256:' + 'f'.repeat(64);
        const service = new PolicySnapshotService(store, registry, policyPacks);
        const { run_id } = service.openRun({
            workflow_id: 'wf_001',
            surface_id: 'surf_001',
            policy_pack_id: 'pp_001',
            org_id: 'org_test',
            action_unit_count: 5,
            process_context_hash: contextHash,
        });
        const run = store.getProcessRun(run_id);
        expect(run).not.toBeNull();
        expect(run.process_context_hash).toBe(contextHash);
    });
});
//# sourceMappingURL=policy_snapshot.test.js.map