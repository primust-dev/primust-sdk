import { PROOF_LEVEL_COLORS, PROOF_LEVEL_LABELS } from "../lib/constants";
export function ProofLevelBadge({ level }) {
    return (<span className={`inline-block rounded px-2 py-0.5 text-xs font-medium ${PROOF_LEVEL_COLORS[level]}`} data-testid={`proof-level-${level}`}>
      {PROOF_LEVEL_LABELS[level]}
    </span>);
}
//# sourceMappingURL=ProofLevelBadge.js.map