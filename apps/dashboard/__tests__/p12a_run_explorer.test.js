/**
 * P12-A: Dashboard Foundation + Run Explorer — 8 MUST PASS.
 */
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import React from "react";
import { RunList } from "../src/components/RunList";
import { RunDetail } from "../src/components/RunDetail";
import { GapTable } from "../src/components/GapTable";
import { GAP_TYPE_LABELS } from "../src/lib/constants";
// ── Factories ──
function makeVpec(overrides = {}) {
    return {
        vpec_id: "vpec_001",
        schema_version: "4.0.0",
        run_id: "run_001",
        workflow_id: "wf_001",
        org_id: "org_001",
        state: "signed",
        partial: false,
        test_mode: false,
        proof_level: "execution",
        proof_distribution: {
            mathematical: 2,
            verifiable_inference: 3,
            execution: 10,
            witnessed: 1,
            attestation: 1,
            weakest_link: "attestation",
            weakest_link_explanation: "One attestation-level record",
        },
        policy_coverage_pct: 97.3,
        instrumentation_surface_pct: 100,
        instrumentation_surface_basis: "LangGraph adapter",
        coverage_verified_pct: 90,
        coverage_pending_pct: 5,
        coverage_ungoverned_pct: 5,
        records_total: 146,
        records_pass: 142,
        records_fail: 1,
        records_degraded: 2,
        records_not_applicable: 1,
        commitment_root: "poseidon2:abc123",
        manifest_hashes: {
            manifest_001: "sha256:aaa",
            manifest_002: "sha256:bbb",
        },
        gaps: [],
        surface_summary: [
            {
                surface_id: "surf_001",
                surface_type: "in_process_adapter",
                observation_mode: "pre_action",
                proof_ceiling: "execution",
                scope_type: "full_workflow",
                surface_coverage_statement: "All tool calls observed",
            },
        ],
        process_context_hash: null,
        signature: {
            signer_id: "signer_001",
            kid: "kid_001",
            algorithm: "Ed25519",
            signature: "sig_abc",
            signed_at: "2026-03-10T12:00:00Z",
        },
        timestamp_anchor: {
            type: "rfc3161",
            tsa: "digicert_us",
            value: "dGVzdA==",
        },
        transparency_log: { rekor_log_id: null, rekor_pending: true },
        started_at: "2026-03-10T12:00:00Z",
        closed_at: "2026-03-10T12:05:00Z",
        ...overrides,
    };
}
function makeRun(overrides = {}) {
    return {
        run_id: "run_001",
        workflow_id: "wf_001",
        org_id: "org_001",
        state: "closed",
        proof_level: "execution",
        policy_coverage_pct: 97.3,
        gap_count: 2,
        started_at: "2026-03-10T12:00:00Z",
        closed_at: "2026-03-10T12:05:00Z",
        process_context_hash: null,
        partial: false,
        ...overrides,
    };
}
const ALL_15_GAP_TYPES = [
    "check_not_executed",
    "enforcement_override",
    "engine_error",
    "check_degraded",
    "external_boundary_traversal",
    "lineage_token_missing",
    "admission_gate_override",
    "check_timing_suspect",
    "reviewer_credential_invalid",
    "witnessed_display_missing",
    "witnessed_rationale_missing",
    "deterministic_consistency_violation",
    "skip_rationale_missing",
    "policy_config_drift",
    "zkml_proof_pending_timeout",
    "zkml_proof_failed",
];
function makeGap(type, severity = "High") {
    return {
        gap_id: `gap_${type}`,
        gap_type: type,
        severity,
        state: "open",
        details: {},
        detected_at: "2026-03-10T12:00:00Z",
        resolved_at: null,
    };
}
// ── Tests ──
describe("P12-A: Dashboard Foundation + Run Explorer", () => {
    it("MUST PASS: all 5 proof levels render in run list and detail", () => {
        const levels = [
            "mathematical",
            "verifiable_inference",
            "execution",
            "witnessed",
            "attestation",
        ];
        // Run list — one run per level
        const runs = levels.map((level) => makeRun({ run_id: `run_${level}`, proof_level: level }));
        const { unmount } = render(<RunList runs={runs}/>);
        for (const level of levels) {
            expect(screen.getByTestId(`proof-level-${level}`)).toBeInTheDocument();
        }
        unmount();
        // Run detail — proof distribution has all 5
        const vpec = makeVpec();
        render(<RunDetail vpec={vpec}/>);
        for (const level of levels) {
            expect(screen.getByTestId(`proof-count-${level}`)).toBeInTheDocument();
        }
    });
    it("MUST PASS: two denominator display — both present, not collapsed", () => {
        const vpec = makeVpec();
        render(<RunDetail vpec={vpec}/>);
        const policyDenom = screen.getByTestId("policy-denominator");
        expect(policyDenom).toBeInTheDocument();
        expect(policyDenom.textContent).toContain("97.3%");
        expect(policyDenom.textContent).toContain("142/146");
        const surfaceDenom = screen.getByTestId("surface-denominator");
        expect(surfaceDenom).toBeInTheDocument();
        expect(surfaceDenom.textContent).toContain("100%");
        expect(surfaceDenom.textContent).toContain("LangGraph adapter");
    });
    it("MUST PASS: manifest_hashes renders as table from map object (not array)", () => {
        const vpec = makeVpec({
            manifest_hashes: {
                manifest_alpha: "sha256:xxx",
                manifest_beta: "sha256:yyy",
                manifest_gamma: "sha256:zzz",
            },
        });
        render(<RunDetail vpec={vpec}/>);
        const table = screen.getByTestId("manifest-hashes-table");
        expect(table).toBeInTheDocument();
        expect(table.textContent).toContain("manifest_alpha");
        expect(table.textContent).toContain("sha256:xxx");
        expect(table.textContent).toContain("manifest_beta");
        expect(table.textContent).toContain("manifest_gamma");
    });
    it("MUST PASS: partial VPEC visually flagged", () => {
        // In run list
        const runs = [makeRun({ partial: true })];
        const { unmount } = render(<RunList runs={runs}/>);
        expect(screen.getByTestId("partial-badge")).toBeInTheDocument();
        expect(screen.getByTestId("partial-badge").textContent).toBe("PARTIAL");
        unmount();
        // In run detail
        const vpec = makeVpec({ partial: true });
        render(<RunDetail vpec={vpec}/>);
        expect(screen.getByTestId("partial-badge")).toBeInTheDocument();
    });
    it("MUST PASS: process_context_hash shown as config epoch badge", () => {
        // In run list
        const hash = "sha256:configepochabc123def456";
        const runs = [makeRun({ process_context_hash: hash })];
        const { unmount } = render(<RunList runs={runs}/>);
        expect(screen.getByTestId("config-epoch-badge")).toBeInTheDocument();
        unmount();
        // In run detail
        const vpec = makeVpec({ process_context_hash: hash });
        render(<RunDetail vpec={vpec}/>);
        expect(screen.getByTestId("config-epoch-badge")).toBeInTheDocument();
        expect(screen.getByTestId("config-epoch-badge").textContent).toContain(hash);
    });
    it("MUST PASS: all 15 gap types render in gaps table", () => {
        const gaps = ALL_15_GAP_TYPES.map((t) => makeGap(t));
        render(<GapTable gaps={gaps}/>);
        for (const type of ALL_15_GAP_TYPES) {
            const label = screen.getByTestId(`gap-label-${type}`);
            expect(label).toBeInTheDocument();
            expect(label.textContent).toBe(GAP_TYPE_LABELS[type]);
        }
    });
    it("MUST PASS: rekor_pending badge shown until transparency_log populated", () => {
        // Pending
        const vpecPending = makeVpec({
            transparency_log: { rekor_log_id: null, rekor_pending: true },
        });
        const { unmount } = render(<RunDetail vpec={vpecPending}/>);
        expect(screen.getByTestId("rekor-pending-badge")).toBeInTheDocument();
        expect(screen.queryByTestId("rekor-link")).not.toBeInTheDocument();
        unmount();
        // Populated
        const vpecDone = makeVpec({
            transparency_log: { rekor_log_id: "12345", rekor_pending: false },
        });
        render(<RunDetail vpec={vpecDone}/>);
        expect(screen.getByTestId("rekor-link")).toBeInTheDocument();
        expect(screen.queryByTestId("rekor-pending-badge")).not.toBeInTheDocument();
    });
    it("MUST PASS: witnessed records show reviewer_credential badge", () => {
        const vpec = makeVpec();
        const records = [
            {
                record_id: "rec_001",
                run_id: "run_001",
                manifest_id: "manifest_001",
                check_result: "pass",
                proof_level_achieved: "witnessed",
                recorded_at: "2026-03-10T12:00:00Z",
                output_commitment: null,
                check_open_tst: "2026-03-10T12:00:00Z",
                check_close_tst: "2026-03-10T12:00:05Z",
                reviewer_credential: "cred_abc",
            },
            {
                record_id: "rec_002",
                run_id: "run_001",
                manifest_id: "manifest_002",
                check_result: "pass",
                proof_level_achieved: "execution",
                recorded_at: "2026-03-10T12:00:01Z",
                output_commitment: "sha256:out",
                check_open_tst: null,
                check_close_tst: null,
                reviewer_credential: null,
            },
        ];
        render(<RunDetail vpec={vpec} records={records}/>);
        const badges = screen.getAllByTestId("reviewer-credential-badge");
        expect(badges).toHaveLength(1);
        expect(badges[0].textContent).toBe("reviewed");
    });
});
//# sourceMappingURL=p12a_run_explorer.test.js.map