import type { ProofLevel } from "../types/vpec";
import { PROOF_LEVEL_COLORS, PROOF_LEVEL_LABELS } from "../lib/constants";

interface ProofLevelBadgeProps {
  level: ProofLevel;
}

export function ProofLevelBadge({ level }: ProofLevelBadgeProps) {
  return (
    <span
      className={`inline-block rounded px-2 py-0.5 text-xs font-medium ${PROOF_LEVEL_COLORS[level]}`}
      data-testid={`proof-level-${level}`}
    >
      {PROOF_LEVEL_LABELS[level]}
    </span>
  );
}
