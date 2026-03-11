import type { GapEntry } from "../types/vpec";
import { GAP_TYPE_LABELS, GAP_SEVERITY_COLORS } from "../lib/constants";

interface GapDetailProps {
  gap: GapEntry;
}

/**
 * Gap detail view — full details rendered.
 * For policy_config_drift: show prior_hash vs current_hash diff.
 * For witnessed gaps: show reviewer_credential block.
 */
export function GapDetail({ gap }: GapDetailProps) {
  const details = gap.details as Record<string, unknown>;

  return (
    <div className="space-y-4" data-testid="gap-detail">
      <div className="flex items-center gap-3">
        <h2 className="text-lg font-bold">{gap.gap_id}</h2>
        <span
          className={`inline-block rounded px-2 py-0.5 text-xs font-medium ${GAP_SEVERITY_COLORS[gap.severity]}`}
        >
          {gap.severity}
        </span>
      </div>

      <div>
        <span className="font-semibold">Type: </span>
        {GAP_TYPE_LABELS[gap.gap_type] ?? gap.gap_type}
      </div>

      <div>
        <span className="font-semibold">State: </span>
        {gap.state}
      </div>

      {/* Policy config drift — show hash diff */}
      {gap.gap_type === "policy_config_drift" && (
        <div data-testid="config-drift-diff">
          <h3 className="font-semibold mb-1">Configuration Drift</h3>
          <div className="text-sm space-y-1 bg-gray-50 p-2 rounded">
            <div>
              <span className="text-red-600">- Prior: </span>
              <code className="font-mono text-xs">
                {(details.prior_hash as string) ?? "unknown"}
              </code>
            </div>
            <div>
              <span className="text-green-600">+ Current: </span>
              <code className="font-mono text-xs">
                {(details.current_hash as string) ?? "unknown"}
              </code>
            </div>
          </div>
        </div>
      )}

      {/* Witnessed gaps — show reviewer credential */}
      {(gap.gap_type === "reviewer_credential_invalid" ||
        gap.gap_type === "witnessed_display_missing" ||
        gap.gap_type === "witnessed_rationale_missing") &&
        details.reviewer_credential && (
          <div data-testid="reviewer-credential-block">
            <h3 className="font-semibold mb-1">Reviewer Credential</h3>
            <pre className="text-xs bg-gray-50 p-2 rounded overflow-auto">
              {JSON.stringify(details.reviewer_credential, null, 2)}
            </pre>
          </div>
        )}

      {/* Full details JSON */}
      <div>
        <h3 className="font-semibold mb-1">Details</h3>
        <pre className="text-xs bg-gray-50 p-2 rounded overflow-auto" data-testid="gap-details-json">
          {JSON.stringify(details, null, 2)}
        </pre>
      </div>
    </div>
  );
}
