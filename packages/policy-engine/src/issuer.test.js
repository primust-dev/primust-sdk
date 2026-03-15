/**
 * Tests for VPEC issuance — P7-A.
 * 15 MUST PASS tests.
 */
import { describe, expect, it, beforeEach } from 'vitest';
import { generateKeyPair, validateArtifact } from '@primust/artifact-core';
import { SqliteStore } from '@primust/runtime-core';
import { closeRun } from './issuer.js';
// ── Helpers ──
let store;
let signerRecord;
let privateKey;
function setupSigner() {
    const result = generateKeyPair('signer_001', 'org_001', 'artifact_signer');
    signerRecord = result.signerRecord;
    privateKey = result.privateKey;
}
function openTestRun(runId = 'run_001') {
    store.openRun({
        run_id: runId,
        workflow_id: 'wf_001',
        org_id: 'org_001',
        surface_id: 'surf_001',
        policy_snapshot_hash: 'sha256:' + 'aa'.repeat(32),
        process_context_hash: 'poseidon2:' + 'bb'.repeat(32),
        action_unit_count: 10,
        ttl_seconds: 3600,
    });
}
function addRecord(overrides = {}) {
    store.appendCheckRecord({
        record_id: `rec_${Math.random().toString(36).slice(2, 8)}`,
        run_id: 'run_001',
        action_unit_id: 'au_001',
        manifest_id: 'manifest_001',
        manifest_hash: 'sha256:' + 'ab'.repeat(32),
        surface_id: 'surf_001',
        commitment_hash: 'poseidon2:' + `${Math.random().toString(16).slice(2)}`.padEnd(64, '0'),
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
        idempotency_key: `idem_${Math.random().toString(36).slice(2, 8)}`,
        recorded_at: '2026-03-10T00:00:00Z',
        ...overrides,
    });
}
function setupSnapshot() {
    store.writePolicySnapshot({
        snapshot_id: 'sha256:' + 'aa'.repeat(32),
        policy_pack_id: 'pack_001',
        policy_pack_version: '1.0.0',
        effective_checks: [
            {
                check_id: 'chk_001',
                manifest_id: 'manifest_001',
                manifest_hash: 'sha256:' + 'ab'.repeat(32),
                required: true,
                evaluation_scope: 'per_run',
                action_unit_count: null,
            },
        ],
        snapshotted_at: '2026-03-10T00:00:00Z',
        policy_basis: 'P1_self_declared',
    });
}
beforeEach(() => {
    store = new SqliteStore(':memory:');
    setupSigner();
});
// ── Tests ──
describe('VPEC issuance (P7-A)', () => {
    it('MUST PASS: one closed run → one signed VPEC', () => {
        openTestRun();
        setupSnapshot();
        addRecord();
        const vpec = closeRun('run_001', store, signerRecord, privateKey);
        expect(vpec.vpec_id).toMatch(/^vpec_/);
        expect(vpec.state).toBe('signed');
        expect(vpec.run_id).toBe('run_001');
        expect(vpec.signature.signature).toBeTypeOf('string');
    });
    it('MUST PASS: reliance_mode not present in issued artifact', () => {
        openTestRun();
        setupSnapshot();
        addRecord();
        const vpec = closeRun('run_001', store, signerRecord, privateKey);
        const json = JSON.stringify(vpec);
        expect(json).not.toContain('reliance_mode');
    });
    it('MUST PASS: schema_version = "4.0.0"', () => {
        openTestRun();
        setupSnapshot();
        addRecord();
        const vpec = closeRun('run_001', store, signerRecord, privateKey);
        expect(vpec.schema_version).toBe('4.0.0');
    });
    it('MUST PASS: proof_level = proof_distribution.weakest_link', () => {
        openTestRun();
        setupSnapshot();
        addRecord({ proof_level_achieved: 'mathematical' });
        addRecord({ proof_level_achieved: 'witnessed' });
        const vpec = closeRun('run_001', store, signerRecord, privateKey);
        expect(vpec.proof_level).toBe(vpec.proof_distribution.weakest_link);
        expect(vpec.proof_level).toBe('witnessed');
    });
    it('MUST PASS: manifest_hashes is object (map), not array', () => {
        openTestRun();
        setupSnapshot();
        addRecord();
        const vpec = closeRun('run_001', store, signerRecord, privateKey);
        expect(vpec.manifest_hashes).toBeTypeOf('object');
        expect(Array.isArray(vpec.manifest_hashes)).toBe(false);
        expect(vpec.manifest_hashes['manifest_001']).toBeTypeOf('string');
    });
    it('MUST PASS: gaps[] entries include gap_type and severity (not bare strings)', () => {
        openTestRun();
        setupSnapshot();
        addRecord({ check_result: 'override' }); // triggers enforcement_override gap
        const vpec = closeRun('run_001', store, signerRecord, privateKey);
        expect(vpec.gaps.length).toBeGreaterThan(0);
        for (const gap of vpec.gaps) {
            expect(gap.gap_type).toBeTypeOf('string');
            expect(gap.severity).toBeTypeOf('string');
            expect(typeof gap).toBe('object');
        }
    });
    it('MUST PASS: witnessed record → proof_level: witnessed in distribution', () => {
        openTestRun();
        setupSnapshot();
        addRecord({ proof_level_achieved: 'witnessed' });
        const vpec = closeRun('run_001', store, signerRecord, privateKey);
        expect(vpec.proof_distribution.witnessed).toBe(1);
    });
    it('MUST PASS: test key → test_mode: true in artifact', () => {
        openTestRun();
        setupSnapshot();
        addRecord();
        const vpec = closeRun('run_001', store, signerRecord, privateKey, {
            test_mode: true,
        });
        expect(vpec.test_mode).toBe(true);
    });
    it('MUST PASS: partial: true → no coverage credit for missing records', () => {
        openTestRun();
        setupSnapshot();
        // Don't add any records — partial close with no credit
        const vpec = closeRun('run_001', store, signerRecord, privateKey, {
            partial: true,
        });
        expect(vpec.partial).toBe(true);
        expect(vpec.coverage.policy_coverage_pct).toBe(0);
    });
    it('MUST PASS: ZK requested → artifact returned with proof_pending: true (non-blocking)', () => {
        openTestRun();
        setupSnapshot();
        addRecord({ proof_level_achieved: 'mathematical' });
        const vpec = closeRun('run_001', store, signerRecord, privateKey, {
            request_zk: true,
        });
        expect(vpec.pending_flags.proof_pending).toBe(true);
        // VPEC is returned immediately — ZK_IS_BLOCKING is false
        expect(vpec.state).toBe('signed');
    });
    it('MUST PASS: artifact verifies via validateArtifact()', () => {
        openTestRun();
        setupSnapshot();
        addRecord();
        const vpec = closeRun('run_001', store, signerRecord, privateKey);
        const result = validateArtifact(vpec);
        expect(result.valid).toBe(true);
    });
    it('MUST PASS: process_context_hash from ProcessRun propagated into VPEC', () => {
        openTestRun(); // sets process_context_hash = 'poseidon2:' + 'bb'.repeat(32)
        setupSnapshot();
        addRecord();
        const vpec = closeRun('run_001', store, signerRecord, privateKey);
        expect(vpec.process_context_hash).toBe('poseidon2:' + 'bb'.repeat(32));
    });
    it('MUST PASS: observation_mode present in each surface_summary entry', () => {
        // Register a surface first
        store.insertSurface({
            surface_id: 'surf_001',
            org_id: 'org_001',
            environment: 'production',
            surface_type: 'in_process_adapter',
            surface_name: 'test_adapter',
            surface_version: '1.0.0',
            observation_mode: 'pre_action',
            scope_type: 'full_workflow',
            scope_description: 'Full workflow coverage via adapter',
            surface_coverage_statement: 'All workflow steps observed',
            proof_ceiling: 'mathematical',
            gaps_detectable: ['check_not_executed'],
            gaps_not_detectable: [],
            registered_at: '2026-03-10T00:00:00Z',
        });
        openTestRun();
        setupSnapshot();
        addRecord();
        const vpec = closeRun('run_001', store, signerRecord, privateKey);
        for (const entry of vpec.surface_summary) {
            expect(entry.observation_mode).toBeTypeOf('string');
        }
        // Verify at least one entry exists since we registered a surface
        expect(vpec.surface_summary.length).toBeGreaterThan(0);
    });
    it('MUST PASS: instrumentation_surface_pct present (or null for partial_unknown scope)', () => {
        openTestRun();
        setupSnapshot();
        addRecord();
        const vpec = closeRun('run_001', store, signerRecord, privateKey);
        // instrumentation_surface_pct should be present in coverage
        expect('instrumentation_surface_pct' in vpec.coverage).toBe(true);
    });
    it('MUST PASS: all 5 proof levels handled in proof_distribution', () => {
        openTestRun();
        setupSnapshot();
        const levels = ['mathematical', 'verifiable_inference', 'execution', 'witnessed', 'attestation'];
        for (const level of levels) {
            addRecord({ proof_level_achieved: level });
        }
        const vpec = closeRun('run_001', store, signerRecord, privateKey);
        // All 5 levels should appear in the distribution
        expect(vpec.proof_distribution.mathematical).toBe(1);
        expect(vpec.proof_distribution.verifiable_inference).toBe(1);
        expect(vpec.proof_distribution.execution).toBe(1);
        expect(vpec.proof_distribution.witnessed).toBe(1);
        expect(vpec.proof_distribution.attestation).toBe(1);
    });
});
//# sourceMappingURL=issuer.test.js.map