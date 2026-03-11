import type { GapEntry } from "../types/vpec";
import { GAP_TYPE_LABELS, GAP_SEVERITY_COLORS } from "../lib/constants";

interface GapTableProps {
  gaps: GapEntry[];
}

export function GapTable({ gaps }: GapTableProps) {
  const sorted = [...gaps].sort((a, b) => {
    const order = ["Critical", "High", "Medium", "Low", "Informational"];
    return order.indexOf(a.severity) - order.indexOf(b.severity);
  });

  return (
    <table className="w-full text-sm" data-testid="gap-table">
      <thead>
        <tr className="border-b text-left">
          <th className="py-1 px-2">Gap Type</th>
          <th className="py-1 px-2">Severity</th>
          <th className="py-1 px-2">State</th>
          <th className="py-1 px-2">Detected</th>
        </tr>
      </thead>
      <tbody>
        {sorted.map((gap) => (
          <tr
            key={gap.gap_id}
            className={gap.severity === "Critical" ? "bg-red-50" : ""}
            data-testid={`gap-row-${gap.gap_type}`}
          >
            <td className="py-1 px-2" data-testid={`gap-label-${gap.gap_type}`}>
              {GAP_TYPE_LABELS[gap.gap_type] ?? gap.gap_type}
            </td>
            <td className="py-1 px-2">
              <span
                className={`inline-block rounded px-2 py-0.5 text-xs font-medium ${GAP_SEVERITY_COLORS[gap.severity]}`}
              >
                {gap.severity}
              </span>
            </td>
            <td className="py-1 px-2">{gap.state}</td>
            <td className="py-1 px-2">{gap.detected_at}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
