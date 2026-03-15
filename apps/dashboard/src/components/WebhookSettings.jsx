import { useState } from "react";
// ── SIEM event types reference ──
const EVENT_TYPES = [
    { type: "vpec_issued", description: "Every completed governance run" },
    { type: "gap_created", description: "Critical or high severity gap detected (immediate)" },
    { type: "coverage_threshold_breach", description: "Coverage drops below your configured threshold" },
    { type: "manifest_drift", description: "A registered check configuration changed since the last run" },
];
// ── Sample payload for preview ──
const SAMPLE_PAYLOAD = {
    source: "primust",
    event_type: "vpec_issued",
    delivery_id: "del_00000000",
    vpec_id: "vpec_abc123",
    org_id: "org_abc123",
    workflow_id: "wf_onboard",
    run_id: "run_abc123",
    commitment_hash: "poseidon2:a1b2c3d4e5f6...",
    proof_level_floor: "execution",
    provable_surface: 0.85,
    provable_surface_breakdown: {
        mathematical: 0.50,
        verifiable_inference: 0.0,
        execution: 0.35,
        witnessed: 0.0,
        attestation: 0.0,
    },
    provable_surface_basis: "executed_records",
    provable_surface_pending: 0.0,
    provable_surface_ungoverned: 0.0,
    provable_surface_suppressed: false,
    gaps_emitted: 0,
    critical_gaps: 0,
    high_gaps: 0,
    recorded_at: "2026-03-12T00:00:00Z",
    timestamp_source: "digicert_tsa",
    test_mode: false,
};
// ── Component ──
export function WebhookSettings({ config, failures = [], onSave, onDelete, onTest, onRetry, }) {
    const [endpointUrl, setEndpointUrl] = useState(config.endpoint_url ?? "");
    const [authHeader, setAuthHeader] = useState("");
    const [threshold, setThreshold] = useState(config.coverage_threshold_floor ?? 0.80);
    const [editing, setEditing] = useState(!config.configured);
    const [testResult, setTestResult] = useState(null);
    const [saving, setSaving] = useState(false);
    const [showSiemRef, setShowSiemRef] = useState(false);
    const [showPayload, setShowPayload] = useState(false);
    const [showEventTypes, setShowEventTypes] = useState(false);
    const [confirmDelete, setConfirmDelete] = useState(false);
    const handleSaveAndTest = async (e) => {
        e.preventDefault();
        setSaving(true);
        setTestResult(null);
        try {
            await onSave({
                endpoint_url: endpointUrl,
                auth_header: authHeader,
                coverage_threshold_floor: threshold,
            });
            const result = await onTest();
            setTestResult(result);
            setEditing(false);
        }
        catch {
            // error handled by parent
        }
        finally {
            setSaving(false);
        }
    };
    const handleDelete = async () => {
        await onDelete();
        setConfirmDelete(false);
        setEditing(true);
        setEndpointUrl("");
        setAuthHeader("");
        setTestResult(null);
    };
    const handleRetry = async (deliveryId) => {
        const result = await onRetry(deliveryId);
        setTestResult(result);
    };
    // ── Empty state ──
    if (!config.configured && !editing) {
        return (<div data-testid="webhook-empty-state" className="p-6 border rounded-lg">
        <h2 className="text-lg font-semibold mb-2">
          Forward governance events to your SIEM
        </h2>
        <p className="text-sm text-gray-600 mb-4">
          Primust sends a structured event to your SIEM on every VPEC issuance,
          critical/high gap detection, coverage threshold breach, and manifest
          drift. Your SIEM receives commitment_hash — the linkage anchor between
          your application logs and the Primust cryptographic proof.
        </p>
        <button onClick={() => setEditing(true)} className="px-4 py-2 bg-blue-600 text-white rounded text-sm font-medium hover:bg-blue-700" data-testid="webhook-configure-btn">
          Configure Webhook
        </button>
      </div>);
    }
    // ── Configured state (not editing) ──
    if (config.configured && !editing) {
        const isActive = config.last_status != null && config.last_status >= 200 && config.last_status < 300;
        return (<div data-testid="webhook-configured" className="space-y-6">
        <div className="p-6 border rounded-lg">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold">SIEM Integration</h2>
            <span data-testid="webhook-status-badge" className={`px-2 py-1 rounded text-xs font-medium ${isActive
                ? "bg-green-100 text-green-800"
                : "bg-red-100 text-red-800"}`}>
              {isActive ? "Active" : "Failing"}
            </span>
          </div>

          <dl className="space-y-2 text-sm">
            <div className="flex">
              <dt className="w-40 text-gray-500">Endpoint URL</dt>
              <dd className="font-mono" data-testid="webhook-endpoint-display">
                {(config.endpoint_url ?? "").length > 60
                ? config.endpoint_url.slice(0, 60) + "…"
                : config.endpoint_url}
              </dd>
            </div>
            <div className="flex">
              <dt className="w-40 text-gray-500">Auth header</dt>
              <dd data-testid="webhook-auth-display">••••••••</dd>
            </div>
            <div className="flex">
              <dt className="w-40 text-gray-500">Coverage threshold</dt>
              <dd data-testid="webhook-threshold-display">
                Alert below {Math.round((config.coverage_threshold_floor ?? 0.80) * 100)}%
              </dd>
            </div>
            {config.last_delivery && (<div className="flex">
                <dt className="w-40 text-gray-500">Last delivery</dt>
                <dd data-testid="webhook-last-delivery">
                  {new Date(config.last_delivery).toLocaleString()} — HTTP{" "}
                  {config.last_status}
                </dd>
              </div>)}
          </dl>

          <div className="flex gap-2 mt-4">
            <button onClick={async () => {
                const result = await onTest();
                setTestResult(result);
            }} className="px-3 py-1.5 border rounded text-sm hover:bg-gray-50" data-testid="webhook-test-btn">
              Send Test Event
            </button>
            <button onClick={() => setEditing(true)} className="px-3 py-1.5 border rounded text-sm hover:bg-gray-50" data-testid="webhook-edit-btn">
              Edit
            </button>
            <button onClick={() => setConfirmDelete(true)} className="px-3 py-1.5 border border-red-300 text-red-600 rounded text-sm hover:bg-red-50" data-testid="webhook-delete-btn">
              Delete
            </button>
          </div>

          {testResult && (<div className={`mt-3 p-2 rounded text-sm ${testResult.status >= 200 && testResult.status < 300
                    ? "bg-green-50 text-green-800"
                    : "bg-red-50 text-red-800"}`} data-testid="webhook-test-result">
              {testResult.status >= 200 && testResult.status < 300
                    ? `✓ Delivered — HTTP ${testResult.status} · ${testResult.latency_ms}ms`
                    : `✗ Failed — HTTP ${testResult.status}${testResult.error ? ` — ${testResult.error}` : ""}`}
            </div>)}

          {confirmDelete && (<div className="mt-3 p-3 bg-red-50 border border-red-200 rounded" data-testid="webhook-confirm-delete">
              <p className="text-sm text-red-800 mb-2">
                Delete webhook configuration? This will stop all SIEM event
                delivery.
              </p>
              <div className="flex gap-2">
                <button onClick={handleDelete} className="px-3 py-1 bg-red-600 text-white rounded text-sm" data-testid="webhook-confirm-delete-btn">
                  Delete
                </button>
                <button onClick={() => setConfirmDelete(false)} className="px-3 py-1 border rounded text-sm">
                  Cancel
                </button>
              </div>
            </div>)}
        </div>

        {/* Dead letter panel */}
        {failures.length > 0 && (<div className="p-6 border rounded-lg" data-testid="webhook-failures-panel">
            <h3 className="text-sm font-semibold mb-3">
              Recent delivery failures
            </h3>
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b text-left text-gray-500">
                  <th className="pb-2">Time</th>
                  <th className="pb-2">Event Type</th>
                  <th className="pb-2">VPEC ID</th>
                  <th className="pb-2">HTTP Status</th>
                  <th className="pb-2">Error</th>
                  <th className="pb-2"></th>
                </tr>
              </thead>
              <tbody>
                {failures.slice(0, 10).map((f) => (<tr key={f.id} className="border-b" data-testid="webhook-failure-row">
                    <td className="py-2">{new Date(f.attempted_at).toLocaleString()}</td>
                    <td className="py-2 font-mono text-xs" data-testid="failure-event-type">{f.event_type}</td>
                    <td className="py-2 font-mono text-xs">{f.vpec_id}</td>
                    <td className="py-2">{f.http_status ?? "—"}</td>
                    <td className="py-2 text-red-600 text-xs">{f.error_msg ?? "—"}</td>
                    <td className="py-2">
                      <button onClick={() => handleRetry(f.delivery_id)} className="text-blue-600 text-xs hover:underline" data-testid="webhook-retry-btn">
                        Retry
                      </button>
                    </td>
                  </tr>))}
              </tbody>
            </table>
          </div>)}
      </div>);
    }
    // ── Configuration form (editing) ──
    return (<div data-testid="webhook-form" className="space-y-6">
      <form onSubmit={handleSaveAndTest} className="p-6 border rounded-lg space-y-4">
        <h2 className="text-lg font-semibold">SIEM Integration</h2>

        <div>
          <label className="block text-sm font-semibold mb-1">
            Endpoint URL *
          </label>
          <input type="url" value={endpointUrl} onChange={(e) => setEndpointUrl(e.target.value)} placeholder="https://http-inputs.splunk.com/services/collector" className="w-full border rounded p-2 text-sm font-mono" required data-testid="webhook-endpoint-input"/>
          <p className="text-xs text-gray-500 mt-1">
            Your SIEM's HTTP event intake endpoint
          </p>
        </div>

        <div>
          <label className="block text-sm font-semibold mb-1">
            Auth Header *
          </label>
          <input type="password" value={authHeader} onChange={(e) => setAuthHeader(e.target.value)} placeholder="Authorization: Splunk <HEC_TOKEN>" className="w-full border rounded p-2 text-sm font-mono" required data-testid="webhook-auth-input"/>
          <p className="text-xs text-gray-500 mt-1">
            Full auth header including header name
          </p>
        </div>

        <div>
          <label className="block text-sm font-semibold mb-1">
            Coverage Alert Threshold
          </label>
          <div className="flex items-center gap-2">
            <input type="number" value={Math.round(threshold * 100)} onChange={(e) => setThreshold(Number(e.target.value) / 100)} min={0} max={100} className="w-24 border rounded p-2 text-sm" data-testid="webhook-threshold-input"/>
            <span className="text-sm text-gray-500">%</span>
          </div>
          <p className="text-xs text-gray-500 mt-1">
            Send alert when provable_surface drops below this value
          </p>
        </div>

        {/* SIEM quick-reference */}
        <div>
          <button type="button" onClick={() => setShowSiemRef(!showSiemRef)} className="text-sm text-blue-600 hover:underline" data-testid="webhook-siem-ref-toggle">
            {showSiemRef ? "Hide" : "Show"} SIEM auth header reference
          </button>
          {showSiemRef && config.siem_examples && (<table className="w-full text-xs mt-2 border" data-testid="webhook-siem-ref-table">
              <thead>
                <tr className="bg-gray-50 text-left">
                  <th className="p-2">SIEM</th>
                  <th className="p-2">Auth Header Format</th>
                </tr>
              </thead>
              <tbody>
                {config.siem_examples.map((ex) => (<tr key={ex.siem} className="border-t" data-testid="siem-example-row">
                    <td className="p-2 font-medium">{ex.siem}</td>
                    <td className="p-2 font-mono">{ex.format}</td>
                  </tr>))}
              </tbody>
            </table>)}
        </div>

        {/* Payload preview */}
        <div>
          <button type="button" onClick={() => setShowPayload(!showPayload)} className="text-sm text-blue-600 hover:underline" data-testid="webhook-payload-toggle">
            {showPayload ? "Hide" : "Show"} what gets sent
          </button>
          {showPayload && (<div className="mt-2" data-testid="webhook-payload-preview">
              <pre className="bg-gray-50 border rounded p-3 text-xs overflow-auto max-h-96">
                {JSON.stringify(SAMPLE_PAYLOAD, null, 2)}
              </pre>
              <div className="mt-2 text-xs text-gray-500 space-y-1">
                <p>
                  <code>commitment_hash</code> — Linkage anchor — search for
                  this in your SIEM
                </p>
                <p>
                  <code>provable_surface</code> — Hero metric — fraction of run
                  with verified governance coverage
                </p>
                <p>
                  <code>proof_level_floor</code> — Weakest-link scalar —
                  disclosed but not the primary signal
                </p>
                <p>
                  <code>gaps_emitted</code> — Number of governance gaps detected
                </p>
              </div>
            </div>)}
        </div>

        {/* Event types reference */}
        <div>
          <button type="button" onClick={() => setShowEventTypes(!showEventTypes)} className="text-sm text-blue-600 hover:underline" data-testid="webhook-events-toggle">
            {showEventTypes ? "Hide" : "Show"} what triggers a webhook
          </button>
          {showEventTypes && (<table className="w-full text-xs mt-2 border" data-testid="webhook-events-table">
              <thead>
                <tr className="bg-gray-50 text-left">
                  <th className="p-2">Event Type</th>
                  <th className="p-2">Description</th>
                </tr>
              </thead>
              <tbody>
                {EVENT_TYPES.map((et) => (<tr key={et.type} className="border-t">
                    <td className="p-2 font-mono">{et.type}</td>
                    <td className="p-2">{et.description}</td>
                  </tr>))}
              </tbody>
            </table>)}
        </div>

        <div className="flex gap-2">
          <button type="submit" disabled={saving || !endpointUrl || !authHeader} className={`px-4 py-2 rounded text-sm font-medium ${saving || !endpointUrl || !authHeader
            ? "bg-gray-300 cursor-not-allowed"
            : "bg-blue-600 text-white hover:bg-blue-700"}`} data-testid="webhook-save-btn">
            {saving ? "Saving…" : "Save and Test"}
          </button>
          {config.configured && (<button type="button" onClick={() => setEditing(false)} className="px-4 py-2 border rounded text-sm">
              Cancel
            </button>)}
        </div>

        {testResult && (<div className={`p-2 rounded text-sm ${testResult.status >= 200 && testResult.status < 300
                ? "bg-green-50 text-green-800"
                : "bg-red-50 text-red-800"}`} data-testid="webhook-test-result">
            {testResult.status >= 200 && testResult.status < 300
                ? `✓ Delivered — HTTP ${testResult.status} · ${testResult.latency_ms}ms`
                : `✗ Failed — HTTP ${testResult.status}${testResult.error ? ` — ${testResult.error}` : ""}`}
          </div>)}
      </form>
    </div>);
}
//# sourceMappingURL=WebhookSettings.js.map