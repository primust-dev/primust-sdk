import type { GapEntry } from "../types/vpec";
interface GapInboxProps {
    gaps: GapEntry[];
}
/**
 * Gap Inbox — all open gaps sorted by severity (Critical first).
 * All 15 gap types must render with display labels.
 */
export declare function GapInbox({ gaps }: GapInboxProps): import("react").JSX.Element;
export {};
//# sourceMappingURL=GapInbox.d.ts.map