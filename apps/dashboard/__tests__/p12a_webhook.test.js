/**
 * P12-A: Dashboard Webhook Settings — 9 MUST PASS.
 */
import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import React from "react";
import { WebhookSettings, } from "../src/components/WebhookSettings";
import { WebhookStatusBanner } from "../src/components/WebhookStatusBanner";
// ── Helpers ──
function makeConfig(overrides = {}) {
    return {
        configured: true,
        id: "wh_001",
        endpoint_url: "https://http-inputs.splunk.com/services/collector",
        auth_header: "••••••••",
        enabled: true,
        coverage_threshold_floor: 0.80,
        last_delivery: "2026-03-12T00:00:00Z",
        last_status: 200,
        siem_examples: [
            { siem: "Splunk HEC", format: "Authorization: Splunk <HEC_TOKEN>" },
            { siem: "Datadog", format: "DD-API-KEY: <API_KEY>" },
        ],
        ...overrides,
    };
}
function makeFailure(overrides = {}) {
    return {
        id: "fail_001",
        delivery_id: "del_001",
        vpec_id: "vpec_abc123",
        event_type: "vpec_issued",
        attempted_at: "2026-03-12T00:00:00Z",
        http_status: 502,
        error_msg: "Bad Gateway",
        ...overrides,
    };
}
function noop() {
    return Promise.resolve();
}
function noopTest() {
    return Promise.resolve({ delivery_id: "del_test", status: 200, latency_ms: 42 });
}
function renderSettings(overrides = {}) {
    const props = {
        config: makeConfig(),
        failures: [],
        onSave: vi.fn().mockResolvedValue(undefined),
        onDelete: vi.fn().mockResolvedValue(undefined),
        onTest: vi.fn().mockResolvedValue({ delivery_id: "del_test", status: 200, latency_ms: 42 }),
        onRetry: vi.fn().mockResolvedValue({ delivery_id: "del_retry", status: 200, latency_ms: 50 }),
        ...overrides,
    };
    return { ...render(<WebhookSettings {...props}/>), props };
}
// ── Tests ──
describe("P12-A: Dashboard Webhook Settings", () => {
    it("MUST PASS: configure → save fires onSave with endpoint_url and auth_header", async () => {
        const onSave = vi.fn().mockResolvedValue(undefined);
        const onTest = vi.fn().mockResolvedValue({ delivery_id: "del_t", status: 200, latency_ms: 30 });
        renderSettings({
            config: { configured: false },
            onSave,
            onTest,
        });
        // Should start in form mode (unconfigured)
        expect(screen.getByTestId("webhook-form")).toBeInTheDocument();
        const endpointInput = screen.getByTestId("webhook-endpoint-input");
        const authInput = screen.getByTestId("webhook-auth-input");
        fireEvent.change(endpointInput, {
            target: { value: "https://siem.example.com/ingest" },
        });
        fireEvent.change(authInput, {
            target: { value: "Authorization: Bearer my-token" },
        });
        const form = screen.getByTestId("webhook-form").querySelector("form");
        fireEvent.submit(form);
        await waitFor(() => {
            expect(onSave).toHaveBeenCalledWith(expect.objectContaining({
                endpoint_url: "https://siem.example.com/ingest",
                auth_header: "Authorization: Bearer my-token",
            }));
        });
    });
    it("MUST PASS: test button fires onTest and shows result", async () => {
        const onTest = vi.fn().mockResolvedValue({
            delivery_id: "del_test",
            status: 200,
            latency_ms: 55,
        });
        renderSettings({ onTest });
        const testBtn = screen.getByTestId("webhook-test-btn");
        fireEvent.click(testBtn);
        await waitFor(() => {
            const result = screen.getByTestId("webhook-test-result");
            expect(result).toBeInTheDocument();
            expect(result.textContent).toContain("200");
        });
        expect(onTest).toHaveBeenCalled();
    });
    it("MUST PASS: auth_header always displays as masked (never raw value)", () => {
        renderSettings();
        const authDisplay = screen.getByTestId("webhook-auth-display");
        expect(authDisplay.textContent).toBe("••••••••");
        expect(authDisplay.textContent).not.toContain("Bearer");
        expect(authDisplay.textContent).not.toContain("Splunk");
    });
    it("MUST PASS: coverage threshold stored as 0.0–1.0 but displayed as percentage", () => {
        renderSettings({
            config: makeConfig({ coverage_threshold_floor: 0.75 }),
        });
        const display = screen.getByTestId("webhook-threshold-display");
        expect(display.textContent).toContain("75%");
    });
    it("MUST PASS: WebhookStatusBanner shows when webhook is failing", () => {
        const failingConfig = makeConfig({ last_status: 502 });
        render(<WebhookStatusBanner config={failingConfig} failureCount={3}/>);
        const banner = screen.getByTestId("webhook-status-banner");
        expect(banner).toBeInTheDocument();
        expect(banner.textContent).toContain("failing");
        expect(banner.textContent).toContain("502");
        expect(banner.textContent).toContain("3");
    });
    it("MUST PASS: WebhookStatusBanner hidden when webhook is healthy", () => {
        const healthyConfig = makeConfig({ last_status: 200 });
        const { container } = render(<WebhookStatusBanner config={healthyConfig}/>);
        expect(container.innerHTML).toBe("");
    });
    it("MUST PASS: delete requires confirmation dialog", async () => {
        const onDelete = vi.fn().mockResolvedValue(undefined);
        renderSettings({ onDelete });
        // Click delete — confirmation should appear, onDelete NOT yet called
        const deleteBtn = screen.getByTestId("webhook-delete-btn");
        fireEvent.click(deleteBtn);
        expect(screen.getByTestId("webhook-confirm-delete")).toBeInTheDocument();
        expect(onDelete).not.toHaveBeenCalled();
        // Confirm delete
        const confirmBtn = screen.getByTestId("webhook-confirm-delete-btn");
        fireEvent.click(confirmBtn);
        await waitFor(() => {
            expect(onDelete).toHaveBeenCalled();
        });
    });
    it("MUST PASS: SIEM reference table renders with auth header formats", () => {
        renderSettings({
            config: makeConfig(),
        });
        // Click edit to get to form mode which has the SIEM reference
        const editBtn = screen.getByTestId("webhook-edit-btn");
        fireEvent.click(editBtn);
        const toggle = screen.getByTestId("webhook-siem-ref-toggle");
        fireEvent.click(toggle);
        const table = screen.getByTestId("webhook-siem-ref-table");
        expect(table).toBeInTheDocument();
        const rows = screen.getAllByTestId("siem-example-row");
        expect(rows.length).toBeGreaterThanOrEqual(2);
        expect(rows[0].textContent).toContain("Splunk HEC");
    });
    it("MUST PASS: dead letter panel shows event_type and retry button", async () => {
        const failures = [
            makeFailure({ event_type: "vpec_issued" }),
            makeFailure({
                id: "fail_002",
                delivery_id: "del_002",
                event_type: "gap_created",
            }),
        ];
        const onRetry = vi.fn().mockResolvedValue({
            delivery_id: "del_001",
            status: 200,
            latency_ms: 50,
        });
        renderSettings({ failures, onRetry });
        const panel = screen.getByTestId("webhook-failures-panel");
        expect(panel).toBeInTheDocument();
        // event_type column is populated
        const eventTypeCells = screen.getAllByTestId("failure-event-type");
        expect(eventTypeCells[0].textContent).toBe("vpec_issued");
        expect(eventTypeCells[1].textContent).toBe("gap_created");
        // retry button
        const retryBtns = screen.getAllByTestId("webhook-retry-btn");
        expect(retryBtns.length).toBe(2);
        fireEvent.click(retryBtns[0]);
        await waitFor(() => {
            expect(onRetry).toHaveBeenCalledWith("del_001");
        });
    });
});
//# sourceMappingURL=p12a_webhook.test.js.map