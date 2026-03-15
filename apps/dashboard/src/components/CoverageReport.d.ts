import type { ProofDistribution, GapSeverity } from "../types/vpec";
interface CoverageReportProps {
    policyCoveragePct: number;
    recordsPass: number;
    recordsTotal: number;
    instrumentationSurfacePct: number | null;
    instrumentationSurfaceBasis: string | null;
    scopeType?: string;
    coverageVerifiedPct: number;
    coveragePendingPct: number;
    coverageUngovernedPct: number;
    proofDistribution: ProofDistribution;
    gapSummary: Record<GapSeverity, number>;
}
export declare function CoverageReport({ policyCoveragePct, recordsPass, recordsTotal, instrumentationSurfacePct, instrumentationSurfaceBasis, scopeType, coverageVerifiedPct, coveragePendingPct, coverageUngovernedPct, proofDistribution, gapSummary, }: CoverageReportProps): import("react").JSX.Element;
export {};
//# sourceMappingURL=CoverageReport.d.ts.map