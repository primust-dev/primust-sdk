"use client";
import { useEffect, useState } from "react";
import { apiFetch } from "../../lib/api";
const STATUS_STYLES = {
    draft: "bg-gray-200 text-gray-700",
    simulation: "bg-yellow-200 text-yellow-800",
    active: "bg-green-200 text-green-800",
};
function StatusPill({ status }) {
    return (<span className={`inline-block rounded-full px-3 py-0.5 text-xs font-semibold uppercase tracking-wide ${STATUS_STYLES[status]}`} data-testid="policy-status-pill">
      {status}
    </span>);
}
export function ActivePolicySummary({ onActivate }) {
    const [policy, setPolicy] = useState(null);
    const [loading, setLoading] = useState(true);
    const [activating, setActivating] = useState(false);
    useEffect(() => {
        let cancelled = false;
        async function load() {
            try {
                const data = await apiFetch("/policy/active");
                if (!cancelled)
                    setPolicy(data);
            }
            catch {
                /* no active policy is expected for new orgs */
            }
            finally {
                if (!cancelled)
                    setLoading(false);
            }
        }
        load();
        return () => { cancelled = true; };
    }, []);
    async function handleActivate() {
        if (!policy)
            return;
        setActivating(true);
        try {
            const updated = await apiFetch("/policy/activate", {
                method: "POST",
                body: { bundle_id: policy.bundle_id },
            });
            setPolicy(updated);
            onActivate?.();
        }
        catch {
            /* activation failures stay in current state */
        }
        finally {
            setActivating(false);
        }
    }
    if (loading) {
        return (<div className="rounded border p-4 text-sm text-gray-500" data-testid="policy-summary-loading">
        Loading policy...
      </div>);
    }
    if (!policy) {
        return (<div className="rounded border border-dashed p-4" data-testid="policy-summary-empty">
        <p className="text-sm text-gray-500">No active policy configured.</p>
        <p className="text-xs text-gray-400 mt-1">Select a bundle to get started.</p>
      </div>);
    }
    const simulationComplete = policy.simulation_completed_at !== null;
    const canActivate = policy.status === "simulation" && simulationComplete;
    return (<div className="rounded border p-4" data-testid="active-policy-summary">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-semibold">Active Policy</h3>
        <StatusPill status={policy.status}/>
      </div>

      <div className="space-y-2 text-sm">
        <div>
          <span className="text-gray-500">Bundle:</span>{" "}
          <span className="font-medium">{policy.bundle_name}</span>
        </div>

        {policy.activated_at && (<div>
            <span className="text-gray-500">Activated:</span>{" "}
            <span className="font-mono text-xs">{policy.activated_at}</span>
          </div>)}

        {policy.simulation_started_at && (<div>
            <span className="text-gray-500">Simulation started:</span>{" "}
            <span className="font-mono text-xs">{policy.simulation_started_at}</span>
          </div>)}

        {policy.simulation_completed_at && (<div>
            <span className="text-gray-500">Simulation completed:</span>{" "}
            <span className="font-mono text-xs">{policy.simulation_completed_at}</span>
          </div>)}
      </div>

      <div className="mt-4">
        <button type="button" onClick={handleActivate} disabled={!canActivate || activating} className={`w-full rounded px-4 py-2 text-sm font-medium transition-colors ${canActivate
            ? "bg-green-600 text-white hover:bg-green-700"
            : "bg-gray-200 text-gray-400 cursor-not-allowed"}`} data-testid="activate-policy-btn">
          {activating ? "Activating..." : "Activate"}
        </button>
        {!canActivate && policy.status === "simulation" && (<p className="text-xs text-gray-400 mt-1 text-center">
            Waiting for simulation to complete
          </p>)}
      </div>
    </div>);
}
//# sourceMappingURL=ActivePolicySummary.js.map