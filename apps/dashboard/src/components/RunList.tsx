import type { ProcessRun } from "../types/vpec";
import { ProofLevelBadge } from "./ProofLevelBadge";

interface RunListProps {
  runs: ProcessRun[];
}

export function RunList({ runs }: RunListProps) {
  return (
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
          <tr key={run.run_id} className="border-b">
            <td className="py-2 px-2 font-mono text-xs">
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
              {run.proof_level ? (
                <ProofLevelBadge level={run.proof_level} />
              ) : (
                "—"
              )}
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
                  data-testid="config-epoch-badge"
                  title={run.process_context_hash}
                >
                  {run.process_context_hash.slice(0, 16)}…
                </span>
              ) : (
                "—"
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
