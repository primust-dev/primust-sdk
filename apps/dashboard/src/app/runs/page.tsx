"use client";

import { useEffect, useState } from "react";
import { apiFetch } from "../../lib/api";
import type { ProcessRun } from "../../types/vpec";
import { RunList } from "../../components/RunList";
import { RunDetail } from "../../components/RunDetail";

interface RunsResponse {
  runs: ProcessRun[];
}

export default function RunsPage() {
  const [runs, setRuns] = useState<ProcessRun[]>([]);
  const [selectedRun, setSelectedRun] = useState<ProcessRun | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function fetchRuns() {
      try {
        const res = await apiFetch<RunsResponse>("/runs");
        if (!cancelled) {
          setRuns(res.runs);
          setLoading(false);
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to load runs");
          setLoading(false);
        }
      }
    }

    fetchRuns();
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div className="space-y-6" data-testid="runs-page">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Runs</h1>
          <p className="mt-1 text-sm text-gray-600">
            All governance runs for your organization with status, proof level,
            and coverage.
          </p>
        </div>
      </div>

      {error && (
        <div
          className="rounded-lg border border-red-300 bg-red-50 p-4 text-sm text-red-800"
          data-testid="runs-error"
        >
          {error}
        </div>
      )}

      {loading ? (
        <div className="text-sm text-gray-500 py-8 text-center">
          Loading runs...
        </div>
      ) : selectedRun?.vpec ? (
        <div className="space-y-4">
          <button
            onClick={() => setSelectedRun(null)}
            className="text-sm text-blue-600 hover:underline"
          >
            &larr; Back to all runs
          </button>
          <div className="rounded-lg border border-gray-200 bg-white p-6">
            <RunDetail vpec={selectedRun.vpec} />
          </div>
        </div>
      ) : (
        <div className="rounded-lg border border-gray-200 bg-white">
          <div className="overflow-x-auto">
            <table className="w-full text-sm" data-testid="run-list">
              <thead>
                <tr className="border-b text-left">
                  <th className="py-2 px-2">Run ID</th>
                  <th className="py-2 px-2">Workflow</th>
                  <th className="py-2 px-2">State</th>
                  <th className="py-2 px-2">Proof Level</th>
                  <th className="py-2 px-2">Policy Coverage</th>
                  <th className="py-2 px-2">Started</th>
                  <th className="py-2 px-2">Gaps</th>
                  <th className="py-2 px-2">Config</th>
                </tr>
              </thead>
              <tbody>
                {runs.map((run) => (
                  <tr
                    key={run.run_id}
                    className="border-b cursor-pointer hover:bg-gray-50"
                    onClick={() => setSelectedRun(run)}
                  >
                    <td className="py-2 px-2 font-mono text-xs text-blue-600 hover:underline">
                      {run.run_id}
                      {run.partial && (
                        <span
                          className="ml-1 inline-block rounded bg-amber-200 px-1 text-xs"
                          data-testid="partial-badge"
                        >
                          PARTIAL
                        </span>
                      )}
                    </td>
                    <td className="py-2 px-2">{run.workflow_id}</td>
                    <td className="py-2 px-2">{run.state}</td>
                    <td className="py-2 px-2">
                      {run.proof_level ?? "—"}
                    </td>
                    <td className="py-2 px-2">
                      {run.policy_coverage_pct !== undefined
                        ? `${run.policy_coverage_pct}%`
                        : "—"}
                    </td>
                    <td className="py-2 px-2">{run.started_at}</td>
                    <td className="py-2 px-2">{run.gap_count}</td>
                    <td className="py-2 px-2">
                      {run.process_context_hash ? (
                        <span
                          className="inline-block rounded bg-purple-100 px-1.5 py-0.5 text-xs font-mono"
                          title={run.process_context_hash}
                        >
                          {run.process_context_hash.slice(0, 16)}...
                        </span>
                      ) : (
                        "—"
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {runs.length === 0 && (
            <div className="py-12 text-center text-sm text-gray-400">
              No runs found. Start a workflow to see governance runs here.
            </div>
          )}
        </div>
      )}
    </div>
  );
}
