import { GAP_TYPE_LABELS, GAP_SEVERITY_COLORS } from "../lib/constants";
/**
 * Gap Inbox — all open gaps sorted by severity (Critical first).
 * All 15 gap types must render with display labels.
 */
export function GapInbox({ gaps }) {
    const severityOrder = ["Critical", "High", "Medium", "Low", "Informational"];
    const sorted = [...gaps].sort((a, b) => severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity));
    return (<div data-testid="gap-inbox">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b text-left">
            <th className="py-2 px-2">Gap ID</th>
            <th className="py-2 px-2">Type</th>
            <th className="py-2 px-2">Severity</th>
            <th className="py-2 px-2">Run</th>
            <th className="py-2 px-2">Detected</th>
            <th className="py-2 px-2">State</th>
          </tr>
        </thead>
        <tbody>
          {sorted.map((gap) => (<tr key={gap.gap_id} className={gap.severity === "Critical" ? "bg-red-50" : ""} data-testid={`gap-inbox-row-${gap.gap_id}`}>
              <td className="py-2 px-2 font-mono text-xs">{gap.gap_id}</td>
              <td className="py-2 px-2" data-testid={`gap-type-label-${gap.gap_type}`}>
                {GAP_TYPE_LABELS[gap.gap_type] ?? gap.gap_type}
              </td>
              <td className="py-2 px-2">
                <span className={`inline-block rounded px-2 py-0.5 text-xs font-medium ${GAP_SEVERITY_COLORS[gap.severity]}`} data-testid={`gap-severity-${gap.gap_id}`}>
                  {gap.severity}
                </span>
              </td>
              <td className="py-2 px-2 font-mono text-xs">
                {gap.details.run_id ?? "—"}
              </td>
              <td className="py-2 px-2">{gap.detected_at}</td>
              <td className="py-2 px-2">{gap.state}</td>
            </tr>))}
        </tbody>
      </table>
    </div>);
}
//# sourceMappingURL=GapInbox.js.map