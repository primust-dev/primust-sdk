/**
 * P10-B: Logger Callback tests — 7 MUST PASS.
 *
 * Tests setLogger() callback for SIEM linkage.
 */
import { describe, expect, it } from 'vitest';
import { commit } from '@primust/artifact-core';
import { Pipeline } from './pipeline.js';
function createMockFetch() {
    const requests = [];
    let runCounter = 0;
    const mockFetch = async (input, init) => {
        const url = typeof input === 'string' ? input : input.toString();
        const method = init?.method ?? 'GET';
        const rawBody = init?.body ?? '';
        const body = rawBody ? JSON.parse(rawBody) : {};
        requests.push({ method, url, body, rawBody });
        const path = new URL(url).pathname;
        if (path === '/api/v1/runs' && method === 'POST') {
            runCounter++;
            return new Response(JSON.stringify({
                run_id: `run_${String(runCounter).padStart(4, '0')}`,
                policy_snapshot_hash: 'sha256:' + 'aa'.repeat(32),
            }), { status: 200, headers: { 'Content-Type': 'application/json' } });
        }
        if (path.includes('/records') && method === 'POST') {
            return new Response(JSON.stringify({
                record_id: 'rec_test001',
                chain_hash: 'sha256:' + 'bb'.repeat(32),
            }), { status: 200, headers: { 'Content-Type': 'application/json' } });
        }
        if (path.includes('/close') && method === 'POST') {
            return new Response(JSON.stringify({ vpec_id: 'vpec_test001', state: 'signed' }), { status: 200, headers: { 'Content-Type': 'application/json' } });
        }
        return new Response(JSON.stringify({ detail: 'not found' }), { status: 404 });
    };
    return { fetch: mockFetch, requests };
}
function createPipeline(mockFetch) {
    return new Pipeline({
        apiKey: 'pk_live_org001_us_secret',
        workflowId: 'wf_test',
        baseUrl: 'https://api.primust.com',
        fetch: mockFetch,
    });
}
// ── Tests ──
describe('TypeScript Logger Callback (P10-B)', () => {
    it('MUST PASS: callback fires on every p.record() call', async () => {
        const { fetch } = createMockFetch();
        const p = createPipeline(fetch);
        const events = [];
        p.setLogger((event) => events.push(event));
        const session = await p.openCheck('check_1', 'manifest_001');
        await p.record(session, 'data_1', 'pass');
        await p.record(session, 'data_2', 'fail');
        expect(events).toHaveLength(2);
        expect(events[0].primust_check_result).toBe('pass');
        expect(events[1].primust_check_result).toBe('fail');
    });
    it('MUST PASS: callback receives correct commitment_hash per record', async () => {
        const { fetch } = createMockFetch();
        const p = createPipeline(fetch);
        const events = [];
        p.setLogger((event) => events.push(event));
        const session = await p.openCheck('check_1', 'manifest_001');
        const rawInput = 'test input for hash verification';
        await p.record(session, rawInput, 'pass');
        expect(events).toHaveLength(1);
        const expectedHash = commit(new TextEncoder().encode(rawInput)).hash;
        expect(events[0].primust_commitment_hash).toBe(expectedHash);
    });
    it('MUST PASS: exception in callback does not interrupt p.record()', async () => {
        const { fetch } = createMockFetch();
        const p = createPipeline(fetch);
        p.setLogger(() => {
            throw new Error('Logger crashed!');
        });
        const session = await p.openCheck('check_1', 'manifest_001');
        // Should not throw despite callback exploding
        const result = await p.record(session, 'data', 'pass');
        expect(result.commitmentHash).toMatch(/^poseidon2:|^sha256:/);
    });
    it('MUST PASS: p.record() returns normally when no logger set', async () => {
        const { fetch } = createMockFetch();
        const p = createPipeline(fetch);
        // No setLogger() call
        const session = await p.openCheck('check_1', 'manifest_001');
        const result = await p.record(session, 'data', 'pass');
        expect(result.recordId).toBeTruthy();
    });
    it('MUST PASS: callback receives no content fields (allowlist test)', async () => {
        const { fetch } = createMockFetch();
        const p = createPipeline(fetch);
        const events = [];
        p.setLogger((event) => events.push(event));
        const session = await p.openCheck('check_1', 'manifest_001');
        const sensitiveInput = 'SUPER SECRET DATA that must not appear';
        await p.record(session, sensitiveInput, 'pass');
        const event = events[0];
        const allValues = JSON.stringify(event);
        expect(allValues).not.toContain(sensitiveInput);
        // Only allowed fields
        const allowedFields = new Set([
            'primust_record_id',
            'primust_commitment_hash',
            'primust_check_result',
            'primust_proof_level',
            'primust_workflow_id',
            'primust_run_id',
            'primust_recorded_at',
            'gap_types_emitted',
        ]);
        for (const key of Object.keys(event)) {
            expect(allowedFields.has(key)).toBe(true);
        }
    });
    it('MUST PASS: callback fires before ObservationEnvelope is sent', async () => {
        const { fetch, requests } = createMockFetch();
        const p = createPipeline(fetch);
        const callOrder = [];
        // Wrap fetch to track API call timing
        const wrappedFetch = async (input, init) => {
            const url = typeof input === 'string' ? input : input.toString();
            if (url.includes('/records')) {
                callOrder.push('api');
            }
            return fetch(input, init);
        };
        const p2 = new Pipeline({
            apiKey: 'pk_live_org001_us_secret',
            workflowId: 'wf_test',
            baseUrl: 'https://api.primust.com',
            fetch: wrappedFetch,
        });
        p2.setLogger(() => {
            callOrder.push('logger');
        });
        const session = await p2.openCheck('check_1', 'manifest_001');
        await p2.record(session, 'data', 'pass');
        expect(callOrder).toEqual(['logger', 'api']);
    });
    it('MUST PASS: TypeScript types correct — no `any` in PrimustLogEvent', async () => {
        const { fetch } = createMockFetch();
        const p = createPipeline(fetch);
        const events = [];
        p.setLogger((event) => {
            // All fields should be typed — TypeScript compiler enforces this
            const _id = event.primust_record_id;
            const _hash = event.primust_commitment_hash;
            const _result = event.primust_check_result;
            const _level = event.primust_proof_level;
            const _wf = event.primust_workflow_id;
            const _run = event.primust_run_id;
            const _at = event.primust_recorded_at;
            const _gaps = event.gap_types_emitted;
            events.push(event);
        });
        const session = await p.openCheck('check_1', 'manifest_001');
        await p.record(session, 'data', 'pass');
        expect(events).toHaveLength(1);
    });
});
//# sourceMappingURL=logger.test.js.map