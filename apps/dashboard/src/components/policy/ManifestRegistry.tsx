"use client";

import { useEffect, useState } from "react";
import type { CheckManifest } from "../../types/policy";
import type { ProofLevel } from "../../types/vpec";
import { PROOF_LEVEL_COLORS, PROOF_LEVEL_LABELS } from "../../lib/constants";
import { apiFetch } from "../../lib/api";

interface ManifestRegistryProps {
  onRegisterClick: () => void;
  onGenerateCodeClick: () => void;
  refreshKey?: number;
}

const STATUS_STYLES: Record<string, string> = {
  active: "bg-green-100 text-green-700",
  deprecated: "bg-gray-100 text-gray-500",
  pending: "bg-yellow-100 text-yellow-700",
};

export function ManifestRegistry({
  onRegisterClick,
  onGenerateCodeClick,
  refreshKey,
}: ManifestRegistryProps) {
  const [manifests, setManifests] = useState<CheckManifest[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      setLoading(true);
      try {
        const data = await apiFetch<CheckManifest[]>("/manifests");
        if (!cancelled) {
          setManifests(data);
          setError(null);
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to load manifests");
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    load();
    return () => { cancelled = true; };
  }, [refreshKey]);

  if (loading) {
    return (
      <div className="p-4 text-sm text-gray-500" data-testid="manifest-registry-loading">
        Loading manifests...
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-4 text-sm text-red-600" data-testid="manifest-registry-error">
        {error}
      </div>
    );
  }

  return (
    <div data-testid="manifest-registry">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-lg font-semibold">Manifest Registry</h2>
        <div className="flex gap-2">
          <button
            type="button"
            onClick={onGenerateCodeClick}
            className="rounded border border-gray-300 px-3 py-1.5 text-sm font-medium text-gray-700 hover:bg-gray-50 transition-colors"
            data-testid="generate-code-btn"
          >
            Generate Code
          </button>
          <button
            type="button"
            onClick={onRegisterClick}
            className="rounded bg-blue-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-blue-700 transition-colors"
            data-testid="register-manifest-btn"
          >
            Register Manifest
          </button>
        </div>
      </div>

      {manifests.length === 0 ? (
        <div className="rounded border border-dashed p-8 text-center">
          <p className="text-sm text-gray-500">No manifests registered yet.</p>
          <p className="text-xs text-gray-400 mt-1">
            Register your first check manifest to get started.
          </p>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm" data-testid="manifest-table">
            <thead>
              <tr className="border-b text-left">
                <th className="py-2 px-2">Manifest Hash</th>
                <th className="py-2 px-2">Check Name</th>
                <th className="py-2 px-2">Version</th>
                <th className="py-2 px-2">Proof Ceiling</th>
                <th className="py-2 px-2">Registered</th>
                <th className="py-2 px-2">Status</th>
              </tr>
            </thead>
            <tbody>
              {manifests.map((m) => (
                <tr
                  key={m.manifest_id}
                  className="border-b"
                  data-testid={`manifest-row-${m.manifest_id}`}
                >
                  <td className="py-2 px-2 font-mono text-xs" title={m.manifest_hash}>
                    {m.manifest_hash.slice(0, 12)}
                  </td>
                  <td className="py-2 px-2">{m.check_name}</td>
                  <td className="py-2 px-2">{m.version}</td>
                  <td className="py-2 px-2">
                    <span
                      className={`inline-block rounded px-2 py-0.5 text-xs font-medium ${PROOF_LEVEL_COLORS[m.proof_level_ceiling as ProofLevel]}`}
                    >
                      {PROOF_LEVEL_LABELS[m.proof_level_ceiling as ProofLevel] ?? m.proof_level_ceiling}
                    </span>
                  </td>
                  <td className="py-2 px-2 text-xs">{m.registered_at}</td>
                  <td className="py-2 px-2">
                    <span
                      className={`inline-block rounded px-2 py-0.5 text-xs font-medium ${STATUS_STYLES[m.status] ?? ""}`}
                    >
                      {m.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
