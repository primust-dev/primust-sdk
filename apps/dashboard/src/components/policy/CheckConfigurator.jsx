"use client";
import { useEffect, useState } from "react";
import { PROOF_LEVEL_COLORS, PROOF_LEVEL_LABELS } from "../../lib/constants";
import { apiFetch } from "../../lib/api";
export function CheckConfigurator({ onAddCustomClick, refreshKey }) {
    const [checks, setChecks] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [editingId, setEditingId] = useState(null);
    const [editValue, setEditValue] = useState("");
    useEffect(() => {
        let cancelled = false;
        async function load() {
            setLoading(true);
            try {
                const data = await apiFetch("/policy/checks");
                if (!cancelled) {
                    setChecks(data);
                    setError(null);
                }
            }
            catch (err) {
                if (!cancelled) {
                    setError(err instanceof Error ? err.message : "Failed to load checks");
                }
            }
            finally {
                if (!cancelled)
                    setLoading(false);
            }
        }
        load();
        return () => { cancelled = true; };
    }, [refreshKey]);
    function startEdit(check) {
        setEditingId(check.check_id);
        setEditValue(check.default_threshold?.toString() ?? "");
    }
    function commitEdit(checkId) {
        const parsed = parseFloat(editValue);
        if (!isNaN(parsed)) {
            setChecks((prev) => prev.map((c) => c.check_id === checkId ? { ...c, default_threshold: parsed } : c));
        }
        setEditingId(null);
    }
    function handleKeyDown(e, checkId) {
        if (e.key === "Enter")
            commitEdit(checkId);
        if (e.key === "Escape")
            setEditingId(null);
    }
    const builtinChecks = checks.filter((c) => c.type === "builtin");
    const customChecks = checks.filter((c) => c.type === "custom");
    if (loading) {
        return (<div className="p-4 text-sm text-gray-500" data-testid="check-configurator-loading">
        Loading checks...
      </div>);
    }
    if (error) {
        return (<div className="p-4 text-sm text-red-600" data-testid="check-configurator-error">
        {error}
      </div>);
    }
    function renderTable(items, label) {
        return (<div className="mb-6">
        <div className="flex items-center justify-between mb-2">
          <h3 className="text-sm font-semibold">{label}</h3>
          {label === "Custom Checks" && (<button type="button" onClick={onAddCustomClick} className="rounded bg-blue-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-blue-700 transition-colors" data-testid="add-custom-check-btn">
              + Add Custom Check
            </button>)}
        </div>
        {items.length === 0 ? (<p className="text-sm text-gray-400 py-2">
            {label === "Custom Checks" ? "No custom checks defined yet." : "No checks available."}
          </p>) : (<div className="overflow-x-auto">
            <table className="w-full text-sm" data-testid={`check-table-${label === "Built-in Checks" ? "builtin" : "custom"}`}>
              <thead>
                <tr className="border-b text-left">
                  <th className="py-2 px-2">Check Name</th>
                  <th className="py-2 px-2">Type</th>
                  <th className="py-2 px-2">Proof Ceiling</th>
                  <th className="py-2 px-2">Description</th>
                  <th className="py-2 px-2">Default Threshold</th>
                  <th className="py-2 px-2 text-center">ZK?</th>
                </tr>
              </thead>
              <tbody>
                {items.map((check) => (<tr key={check.check_id} className="border-b" data-testid={`check-row-${check.check_id}`}>
                    <td className="py-2 px-2 font-medium">{check.check_name}</td>
                    <td className="py-2 px-2">
                      <span className={`inline-block rounded px-2 py-0.5 text-xs font-medium ${check.type === "builtin"
                        ? "bg-blue-100 text-blue-700"
                        : "bg-purple-100 text-purple-700"}`}>
                        {check.type}
                      </span>
                    </td>
                    <td className="py-2 px-2">
                      <span className={`inline-block rounded px-2 py-0.5 text-xs font-medium ${PROOF_LEVEL_COLORS[check.proof_ceiling]}`}>
                        {PROOF_LEVEL_LABELS[check.proof_ceiling] ?? check.proof_ceiling}
                      </span>
                    </td>
                    <td className="py-2 px-2 text-gray-600 max-w-xs truncate">
                      {check.description}
                    </td>
                    <td className="py-2 px-2">
                      {check.default_threshold !== undefined ? (editingId === check.check_id ? (<input type="number" value={editValue} onChange={(e) => setEditValue(e.target.value)} onBlur={() => commitEdit(check.check_id)} onKeyDown={(e) => handleKeyDown(e, check.check_id)} className="w-20 rounded border border-blue-400 px-2 py-1 text-sm focus:outline-none focus:ring-1 focus:ring-blue-400" autoFocus data-testid={`threshold-edit-${check.check_id}`}/>) : (<button type="button" onClick={() => startEdit(check)} className="rounded px-2 py-1 text-sm font-mono hover:bg-gray-100 transition-colors" data-testid={`threshold-display-${check.check_id}`}>
                            {check.default_threshold}
                          </button>)) : (<span className="text-xs text-gray-400">n/a</span>)}
                    </td>
                    <td className="py-2 px-2 text-center">
                      {check.zk_available ? (<span className="inline-block rounded bg-green-100 px-2 py-0.5 text-xs text-green-700 font-medium">
                          ZK
                        </span>) : (<span className="text-xs text-gray-400">&mdash;</span>)}
                    </td>
                  </tr>))}
              </tbody>
            </table>
          </div>)}
      </div>);
    }
    return (<div data-testid="check-configurator">
      {renderTable(builtinChecks, "Built-in Checks")}
      {renderTable(customChecks, "Custom Checks")}
    </div>);
}
//# sourceMappingURL=CheckConfigurator.js.map