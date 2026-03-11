import type { ProofDistribution, GapSeverity } from "../types/vpec";
import { CoverageDisplay } from "./CoverageDisplay";
import { ProofDistributionBar } from "./ProofDistributionBar";
import { GAP_SEVERITIES, GAP_SEVERITY_COLORS } from "../lib/constants";

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

export function CoverageReport({
  policyCoveragePct,
  recordsPass,
  recordsTotal,
  instrumentationSurfacePct,
  instrumentationSurfaceBasis,
  scopeType,
  coverageVerifiedPct,
  coveragePendingPct,
  coverageUngovernedPct,
  proofDistribution,
  gapSummary,
}: CoverageReportProps) {
  return (
    <div className="space-y-6" data-testid="coverage-report">
      {/* Two denominator display */}
      <CoverageDisplay
        policyCoveragePct={policyCoveragePct}
        recordsPass={recordsPass}
        recordsTotal={recordsTotal}
        instrumentationSurfacePct={instrumentationSurfacePct}
        instrumentationSurfaceBasis={instrumentationSurfaceBasis}
        scopeType={scopeType}
        coverageVerifiedPct={coverageVerifiedPct}
        coveragePendingPct={coveragePendingPct}
        coverageUngovernedPct={coverageUngovernedPct}
      />

      {/* Proof level distribution — all 5 levels */}
      <section>
        <h3 className="font-semibold mb-2">Proof Level Distribution</h3>
        <ProofDistributionBar distribution={proofDistribution} />
      </section>

      {/* Gap summary by severity — all 5 severities */}
      <section>
        <h3 className="font-semibold mb-2">Gap Summary</h3>
        <div className="flex gap-3" data-testid="gap-summary">
          {GAP_SEVERITIES.map((sev) => (
            <div
              key={sev}
              className="text-center"
              data-testid={`gap-summary-${sev.toLowerCase()}`}
            >
              <div
                className={`rounded px-3 py-1 text-sm font-bold ${GAP_SEVERITY_COLORS[sev]}`}
              >
                {gapSummary[sev] ?? 0}
              </div>
              <div className="text-xs mt-1">{sev}</div>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
