"use client";
import { useEffect, useState } from "react";
import { apiFetch } from "../../../lib/api";
import { ApiKeyTable } from "../../../components/settings/ApiKeyTable";
export default function ApiKeysPage() {
    const [keys, setKeys] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    useEffect(() => {
        let cancelled = false;
        async function fetchKeys() {
            try {
                const res = await apiFetch("/settings/api-keys");
                if (!cancelled) {
                    setKeys(res.keys);
                    setLoading(false);
                }
            }
            catch (err) {
                if (!cancelled) {
                    setError(err instanceof Error ? err.message : "Failed to load keys");
                    setLoading(false);
                }
            }
        }
        fetchKeys();
        return () => {
            cancelled = true;
        };
    }, []);
    return (<div className="mx-auto max-w-3xl py-12 px-4">
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">API Keys</h1>
          <p className="mt-1 text-sm text-gray-600">
            Manage your Primust API keys. Keys are always displayed redacted.
          </p>
        </div>
      </div>

      {error && (<div className="mb-4 rounded-lg border border-red-300 bg-red-50 p-4 text-sm text-red-800" data-testid="keys-error">
          {error}
        </div>)}

      <div className="rounded-lg border border-gray-200 bg-white">
        <ApiKeyTable keys={keys} loading={loading}/>
      </div>

      <div className="mt-4 rounded border border-gray-200 bg-gray-50 p-3 text-xs text-gray-500">
        <p>
          Sandbox keys (<code>pk_sb_</code>) are subject to a daily request cap
          and behave like test keys. Upgrade to a live key for production use.
        </p>
      </div>
    </div>);
}
//# sourceMappingURL=page.js.map