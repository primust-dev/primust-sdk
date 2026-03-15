import type { GapEntry } from "../types/vpec";
interface GapDetailProps {
    gap: GapEntry;
}
/**
 * Gap detail view — full details rendered.
 * For policy_config_drift: show prior_hash vs current_hash diff.
 * For witnessed gaps: show reviewer_credential block.
 */
export declare function GapDetail({ gap }: GapDetailProps): import("react").JSX.Element;
export {};
//# sourceMappingURL=GapDetail.d.ts.map