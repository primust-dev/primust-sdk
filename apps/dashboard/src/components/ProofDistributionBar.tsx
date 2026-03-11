import type { ProofDistribution } from "../types/vpec";
import { PROOF_LEVELS, PROOF_LEVEL_LABELS } from "../lib/constants";

interface ProofDistributionBarProps {
  distribution: ProofDistribution;
}

const BAR_COLORS: Record<string, string> = {
  mathematical: "bg-green-700",
  execution_zkml: "bg-blue-600",
  execution: "bg-yellow-500",
  witnessed: "bg-orange-500",
  attestation: "bg-gray-500",
};

export function ProofDistributionBar({ distribution }: ProofDistributionBarProps) {
  const total = PROOF_LEVELS.reduce((s, l) => s + (distribution[l] ?? 0), 0);

  return (
    <div data-testid="proof-distribution">
      {total > 0 && (
        <div className="flex h-5 rounded overflow-hidden mb-2">
          {PROOF_LEVELS.map((level) => {
            const count = distribution[level] ?? 0;
            if (count === 0) return null;
            const pct = (count / total) * 100;
            return (
              <div
                key={level}
                className={BAR_COLORS[level]}
                style={{ width: `${pct}%` }}
                title={`${PROOF_LEVEL_LABELS[level]}: ${count}`}
                data-testid={`proof-bar-${level}`}
              />
            );
          })}
        </div>
      )}
      <div className="flex flex-wrap gap-3 text-xs">
        {PROOF_LEVELS.map((level) => (
          <span key={level} data-testid={`proof-count-${level}`}>
            {PROOF_LEVEL_LABELS[level]}: {distribution[level] ?? 0}
          </span>
        ))}
      </div>
      <div className="text-xs mt-1 text-gray-500">
        Weakest link: {PROOF_LEVEL_LABELS[distribution.weakest_link]}
      </div>
    </div>
  );
}
