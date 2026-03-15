"use client";
import { useState } from "react";
import { BundleList } from "../../components/policy/BundleList";
import { BundleDetail } from "../../components/policy/BundleDetail";
import { ActivePolicySummary } from "../../components/policy/ActivePolicySummary";
export default function PolicyPage() {
    const [selectedBundle, setSelectedBundle] = useState(null);
    function handleSelectBundle(bundle) {
        setSelectedBundle(bundle);
    }
    function handleActivateBundle(_bundleId) {
        // Selecting a bundle for the active policy would trigger a draft/simulation flow.
        // The ActivePolicySummary component handles the actual activation.
    }
    return (<div className="flex gap-6" data-testid="policy-page">
      {/* Left column: Bundle list sidebar */}
      <aside className="w-1/4 min-w-[220px] rounded border bg-white py-3" data-testid="bundle-sidebar">
        <BundleList selectedBundleId={selectedBundle?.bundle_id ?? null} onSelectBundle={handleSelectBundle}/>
      </aside>

      {/* Center column: Selected bundle detail */}
      <div className="flex-1 min-w-0">
        <div className="rounded border bg-white p-6" data-testid="bundle-detail-panel">
          {selectedBundle ? (<BundleDetail bundle={selectedBundle} onSelectBundle={handleActivateBundle}/>) : (<div className="flex flex-col items-center justify-center py-16 text-center">
              <p className="text-lg text-gray-400 mb-2">No bundle selected</p>
              <p className="text-sm text-gray-400">
                Select a bundle from the sidebar to view its checks and configuration.
              </p>
            </div>)}
        </div>
      </div>

      {/* Right column: Active policy summary */}
      <aside className="w-1/4 min-w-[220px]" data-testid="policy-summary-sidebar">
        <ActivePolicySummary />
      </aside>
    </div>);
}
//# sourceMappingURL=page.js.map