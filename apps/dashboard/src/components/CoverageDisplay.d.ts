interface CoverageDisplayProps {
    policyCoveragePct: number;
    recordsPass: number;
    recordsTotal: number;
    instrumentationSurfacePct: number | null;
    instrumentationSurfaceBasis: string | null;
    scopeType?: string;
    coverageVerifiedPct: number;
    coveragePendingPct: number;
    coverageUngovernedPct: number;
}
/**
 * TWO DENOMINATOR DISPLAY — mandatory, never collapse.
 * 1. Policy denominator: "Policy coverage: X% (Y of Z required checks ran)"
 * 2. Surface denominator: "Instrumentation surface: X% (scope — basis)"
 *    null → "Scope partially unknown — coverage is a lower bound"
 */
export declare function CoverageDisplay({ policyCoveragePct, recordsPass, recordsTotal, instrumentationSurfacePct, instrumentationSurfaceBasis, scopeType, coverageVerifiedPct, coveragePendingPct, coverageUngovernedPct, }: CoverageDisplayProps): import("react").JSX.Element;
export {};
//# sourceMappingURL=CoverageDisplay.d.ts.map