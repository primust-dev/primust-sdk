"use client";
import { useEffect, useState } from "react";
import { apiFetch } from "../../lib/api";
export function BundleList({ selectedBundleId, onSelectBundle }) {
    const [bundles, setBundles] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    useEffect(() => {
        let cancelled = false;
        async function load() {
            try {
                const data = await apiFetch("/policy/bundles");
                if (!cancelled) {
                    setBundles(data);
                    setLoading(false);
                }
            }
            catch (err) {
                if (!cancelled) {
                    setError(err instanceof Error ? err.message : "Failed to load bundles");
                    setLoading(false);
                }
            }
        }
        load();
        return () => { cancelled = true; };
    }, []);
    const builtins = bundles.filter((b) => b.is_builtin);
    const custom = bundles.filter((b) => !b.is_builtin);
    if (loading) {
        return (<div className="p-4 text-sm text-gray-500" data-testid="bundle-list-loading">
        Loading bundles...
      </div>);
    }
    if (error) {
        return (<div className="p-4 text-sm text-red-600" data-testid="bundle-list-error">
        {error}
      </div>);
    }
    return (<div data-testid="bundle-list">
      <h3 className="text-xs font-semibold uppercase tracking-wider text-gray-500 px-3 py-2">
        Built-in Bundles
      </h3>
      <ul className="space-y-1 px-2">
        {builtins.map((bundle) => (<li key={bundle.bundle_id}>
            <button type="button" onClick={() => onSelectBundle(bundle)} className={`w-full text-left rounded px-3 py-2 text-sm transition-colors ${selectedBundleId === bundle.bundle_id
                ? "bg-blue-100 border border-blue-300"
                : "hover:bg-gray-100 border border-transparent"}`} data-testid={`bundle-item-${bundle.bundle_id}`}>
              <div className="font-medium">{bundle.name}</div>
              <div className="flex flex-wrap gap-1 mt-1">
                {bundle.framework_mappings.map((fw) => (<span key={fw} className="inline-block rounded bg-purple-100 px-1.5 py-0.5 text-xs text-purple-700">
                    {fw}
                  </span>))}
              </div>
            </button>
          </li>))}
      </ul>

      <h3 className="text-xs font-semibold uppercase tracking-wider text-gray-500 px-3 py-2 mt-4">
        Custom
      </h3>
      <ul className="space-y-1 px-2">
        {custom.length === 0 && (<li className="px-3 py-2 text-xs text-gray-400">No custom bundles yet</li>)}
        {custom.map((bundle) => (<li key={bundle.bundle_id}>
            <button type="button" onClick={() => onSelectBundle(bundle)} className={`w-full text-left rounded px-3 py-2 text-sm transition-colors ${selectedBundleId === bundle.bundle_id
                ? "bg-blue-100 border border-blue-300"
                : "hover:bg-gray-100 border border-transparent"}`} data-testid={`bundle-item-${bundle.bundle_id}`}>
              <div className="font-medium">{bundle.name}</div>
              <div className="text-xs text-gray-500">v{bundle.version}</div>
            </button>
          </li>))}
      </ul>

      <div className="px-2 mt-4">
        <button type="button" className="w-full rounded border border-dashed border-gray-300 px-3 py-2 text-sm text-gray-600 hover:border-blue-400 hover:text-blue-600 transition-colors" data-testid="build-from-scratch-btn">
          + Build from scratch
        </button>
      </div>
    </div>);
}
//# sourceMappingURL=BundleList.js.map