import type { PolicyBundle } from "../../types/policy";
interface BundleListProps {
    selectedBundleId: string | null;
    onSelectBundle: (bundle: PolicyBundle) => void;
}
export declare function BundleList({ selectedBundleId, onSelectBundle }: BundleListProps): import("react").JSX.Element;
export {};
//# sourceMappingURL=BundleList.d.ts.map