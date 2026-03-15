"use client";
import { useState, useCallback } from "react";
import { CheckConfigurator } from "../../../components/policy/CheckConfigurator";
import { CustomCheckForm } from "../../../components/policy/CustomCheckForm";
export default function ChecksPage() {
    const [customCheckModalOpen, setCustomCheckModalOpen] = useState(false);
    const [refreshKey, setRefreshKey] = useState(0);
    const handleCreated = useCallback(() => {
        setRefreshKey((k) => k + 1);
    }, []);
    return (<div data-testid="checks-page">
      <div className="rounded border bg-white p-6">
        <div className="mb-4">
          <h2 className="text-lg font-semibold">Check Configuration</h2>
          <p className="text-sm text-gray-500 mt-1">
            View built-in checks and create custom checks (BYOC) for your policy bundles.
          </p>
        </div>

        <CheckConfigurator onAddCustomClick={() => setCustomCheckModalOpen(true)} refreshKey={refreshKey}/>
      </div>

      <CustomCheckForm open={customCheckModalOpen} onClose={() => setCustomCheckModalOpen(false)} onCreated={handleCreated}/>
    </div>);
}
//# sourceMappingURL=page.js.map